#!/usr/bin/env python3
"""Public execution-only xxHash RVV/scalar QEMU experiment."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import shutil
import statistics
import subprocess
import time
from pathlib import Path
from typing import Iterable, Sequence

REPOSITORY = "https://github.com/Cyan4973/xxHash"
REVISION = "87b712ade86cdbcb7f1d7a2bc2980955466efbda"
QEMU = "qemu-riscv64"
CPU = "rv64,v=true,vlen=128,elen=64,vext_spec=v1.0"
SYSROOT = "/usr/riscv64-linux-gnu"
CC = "riscv64-linux-gnu-gcc"
NM = "riscv64-linux-gnu-nm"
OBJDUMP = "riscv64-linux-gnu-objdump"
READELF = "riscv64-linux-gnu-readelf"
FLAGS = "-march=rv64gcv -mabi=lp64d -O3 -DXXH_FORCE_MEMORY_ACCESS=0 -fno-pie"
SCALAR_DEFINE = "-DXXH_VECTOR=XXH_SCALAR"
TARGET_PREFIX = "XXH3_hashLong_64b_default"
DIAGNOSTIC_ARGS = ("-q", "-b5", "-i1", "-B1855")
ENDPOINT_ARGS = ("-q", "-b5", "-i5", "-B1855")
SIZES = (0, 1, 7, 31, 32, 63, 64, 65, 127, 128, 129, 1024, 4097, 65537)
ROUNDS = 5
METRIC_RE = re.compile(r"5#XXH3_64b.*?\(\s*([0-9]+(?:\.[0-9]+)?)\s+MB/s\)")
TRACE_RE = re.compile(r"0x([0-9a-fA-F]+):\s+([0-9a-fA-F]{4,16})\s+(\S+)")
OBJDUMP_RE = re.compile(r"^\s*[0-9a-fA-F]+:\s+[0-9a-fA-F]{4,16}\s+(\S+)", re.M)
VECTOR_CONFIG = {"vsetvl", "vsetvli", "vsetivli"}


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(
    command: Sequence[str],
    *,
    cwd: Path | None,
    log: Path,
    env: dict[str, str] | None = None,
    timeout: int = 1200,
) -> tuple[str, float]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    log.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    completed = subprocess.run(
        list(command), cwd=cwd, env=merged, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=timeout, check=False,
    )
    elapsed = time.perf_counter() - started
    log.write_text("$ " + " ".join(command) + "\n" + completed.stdout)
    if completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}; log={log}"
        )
    return completed.stdout, elapsed


def version(command: Sequence[str]) -> str:
    completed = subprocess.run(
        list(command), text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False,
    )
    return completed.stdout.splitlines()[0].strip() if completed.stdout else "unknown"


def qemu(binary: Path, arguments: Sequence[str], trace: Path | None = None) -> list[str]:
    command = [QEMU, "-cpu", CPU, "-L", SYSROOT]
    if trace is not None:
        command += ["-d", "in_asm", "-D", str(trace)]
    return [*command, str(binary), *arguments]


def clone_pair(root: Path) -> dict[str, Path]:
    mirror = root / "source"
    run(
        ["git", "clone", "--filter=blob:none", "--no-checkout", REPOSITORY, str(mirror)],
        cwd=None, log=root / "logs/clone.log", timeout=600,
    )
    run(
        ["git", "fetch", "--depth=1", "origin", REVISION],
        cwd=mirror, log=root / "logs/fetch.log", timeout=600,
    )
    result = {}
    for variant in ("rvv", "scalar"):
        checkout = root / "work" / variant
        run(
            ["git", "worktree", "add", "--detach", str(checkout), REVISION],
            cwd=mirror, log=root / f"logs/worktree-{variant}.log",
        )
        result[variant] = checkout
    return result


def build(checkout: Path, variant: str, root: Path) -> Path:
    cflags = FLAGS if variant == "rvv" else f"{FLAGS} {SCALAR_DEFINE}"
    env = {
        "CC": CC,
        "CFLAGS": cflags,
        "LDFLAGS": "-no-pie",
        "RUN_ENV": f"{QEMU} -cpu {CPU} -L {SYSROOT}",
    }
    for command, name, timeout in (
        (["make", "clean"], "clean", 300),
        (["make", "-j2", "xxhsum"], "build", 900),
        (["make", "check"], "make-check", 1800),
    ):
        run(command, cwd=checkout, log=root / f"logs/{name}-{variant}.log", env=env, timeout=timeout)
    destination = root / "artifacts" / variant / "xxhsum"
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(checkout / "xxhsum", destination)
    return destination


def symbol_range(binary: Path) -> tuple[int, int, str]:
    text, _ = run([NM, "-S", "-n", "-C", str(binary)], cwd=None, log=binary.parent / "nm.txt")
    matches = []
    for line in text.splitlines():
        parts = line.split(maxsplit=3)
        if len(parts) != 4 or not parts[3].startswith(TARGET_PREFIX):
            continue
        try:
            address, size = int(parts[0], 16), int(parts[1], 16)
        except ValueError:
            continue
        if size:
            matches.append((address, address + size, parts[3]))
    exact = [item for item in matches if item[2] == TARGET_PREFIX + ".constprop.0"]
    chosen = exact if exact else matches
    if len(chosen) != 1:
        raise RuntimeError(f"target symbol is not unique in {binary}: {matches}")
    return chosen[0]


def is_vector(mnemonic: str) -> bool:
    value = mnemonic.lower()
    return value in VECTOR_CONFIG or (value.startswith("v") and "." in value)


def target_code(binary: Path) -> dict[str, object]:
    start, end, symbol = symbol_range(binary)
    text, _ = run(
        [OBJDUMP, "-d", "-C", f"--start-address=0x{start:x}", f"--stop-address=0x{end:x}", str(binary)],
        cwd=None, log=binary.parent / "target.objdump.txt",
    )
    mnemonics = [item.lower() for item in OBJDUMP_RE.findall(text)]
    vectors = [item for item in mnemonics if is_vector(item)]
    operations = [item for item in vectors if item not in VECTOR_CONFIG]
    return {
        "symbol": symbol,
        "start": hex(start),
        "end": hex(end),
        "instruction_count": len(mnemonics),
        "rvv_instruction_count": len(vectors),
        "rvv_operation_count": len(operations),
        "rvv_mnemonics": sorted(set(vectors)),
    }


def build_id(binary: Path) -> str:
    text, _ = run([READELF, "-n", str(binary)], cwd=None, log=binary.parent / "readelf-notes.txt")
    match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", text)
    if match is None:
        raise RuntimeError(f"missing GNU Build ID in {binary}")
    return match.group(1).lower()


def elf(binary: Path, root: Path) -> dict[str, object]:
    return {
        "path": binary.relative_to(root).as_posix(),
        "size_bytes": binary.stat().st_size,
        "sha256": sha256(binary),
        "gnu_build_id": build_id(binary),
        "machine": "RISC-V",
    }


def payload(size: int, mode: int) -> bytes:
    if mode == 0:
        return bytes(size)
    if mode == 1:
        return bytes(index % 251 for index in range(size))
    seed = hashlib.sha256(f"rax-xxhash-{size}".encode()).digest()
    return (seed * ((size + len(seed) - 1) // len(seed)))[:size]


def digest(binary: Path, path: Path, root: Path, label: str) -> str:
    text, _ = run(
        qemu(binary, ["-H3", str(path)]), cwd=binary.parent,
        log=root / f"correctness/{label}-{path.name}.log",
    )
    token = text.strip().split()[0].removeprefix("XXH3_")
    if len(token) != 16 or any(char not in "0123456789abcdefABCDEF" for char in token):
        raise RuntimeError(f"unexpected digest output for {path.name}: {text!r}")
    return token.lower()


def differential(binaries: dict[str, Path], root: Path) -> int:
    inputs = root / "correctness/inputs"
    inputs.mkdir(parents=True)
    checked = 0
    for size in SIZES:
        for mode in range(3):
            path = inputs / f"input-{size}-{mode}.bin"
            path.write_bytes(payload(size, mode))
            left = digest(binaries["scalar"], path, root, "scalar")
            right = digest(binaries["rvv"], path, root, "rvv")
            if left != right:
                raise RuntimeError(f"XXH3 mismatch size={size} mode={mode}: {left} != {right}")
            checked += 1
    shutil.rmtree(inputs)
    return checked


def activation(binary: Path, code: dict[str, object], root: Path, variant: str) -> dict[str, object]:
    trace = root / f"activation/{variant}/trace.log"
    trace.parent.mkdir(parents=True)
    output, _ = run(
        qemu(binary, DIAGNOSTIC_ARGS, trace), cwd=binary.parent,
        log=trace.parent / "console.log", timeout=600,
    )
    metric = parse_metric(output)
    start, end = int(str(code["start"]), 16), int(str(code["end"]), 16)
    pcs, vector_pcs, operation_pcs = set(), set(), set()
    for line in trace.read_text(errors="replace").splitlines():
        match = TRACE_RE.search(line)
        if match is None:
            continue
        pc, mnemonic = int(match.group(1), 16), match.group(3).lower()
        if not start <= pc < end:
            continue
        pcs.add(pc)
        if is_vector(mnemonic):
            vector_pcs.add(pc)
            if mnemonic not in VECTOR_CONFIG:
                operation_pcs.add(pc)
    if not pcs:
        raise RuntimeError(f"QEMU did not observe target symbol for {variant}")
    return {
        "command": ["xxhsum", *DIAGNOSTIC_ARGS],
        "endpoint_mb_s": metric,
        "target_instruction_pcs": [hex(value) for value in sorted(pcs)],
        "target_instruction_hits": len(pcs),
        "target_vector_pcs": [hex(value) for value in sorted(vector_pcs)],
        "target_vector_instructions": len(vector_pcs),
        "target_vector_operation_pcs": [hex(value) for value in sorted(operation_pcs)],
        "target_vector_operations": len(operation_pcs),
        "trace_semantics": "unique target PCs present in QEMU in_asm translated blocks",
    }


def parse_metric(text: str) -> float:
    match = METRIC_RE.search(text.replace("\r", "\n"))
    if match is None:
        raise RuntimeError("missing frozen XXH3_64b metric")
    value = float(match.group(1))
    if not math.isfinite(value) or value <= 0:
        raise RuntimeError("invalid endpoint metric")
    return value


def measure(binaries: dict[str, Path], root: Path) -> dict[str, object]:
    for variant in ("scalar", "rvv"):
        run(qemu(binaries[variant], DIAGNOSTIC_ARGS), cwd=binaries[variant].parent, log=root / f"measurement/warmup-{variant}.log")
    samples = {"scalar": [], "rvv": []}
    order = []
    for round_index in range(ROUNDS):
        variants = ("scalar", "rvv") if round_index % 2 == 0 else ("rvv", "scalar")
        for variant in variants:
            text, elapsed = run(
                qemu(binaries[variant], ENDPOINT_ARGS), cwd=binaries[variant].parent,
                log=root / f"measurement/round-{round_index + 1}-{variant}.log", timeout=600,
            )
            metric = parse_metric(text)
            samples[variant].append(metric)
            order.append({"round": round_index + 1, "variant": variant, "metric_mb_s": metric, "host_seconds": elapsed})
    paired = [
        {"round": index + 1, "rvv_over_scalar": samples["rvv"][index] / samples["scalar"][index]}
        for index in range(ROUNDS)
    ]
    ratio = float(statistics.median(item["rvv_over_scalar"] for item in paired))
    (root / "runs.jsonl").write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in order))
    return {
        "command": ["xxhsum", *ENDPOINT_ARGS],
        "rounds": ROUNDS,
        "order": order,
        "samples_mb_s": samples,
        "median_mb_s": {key: float(statistics.median(value)) for key, value in samples.items()},
        "paired_ratios": paired,
        "median_paired_rvv_over_scalar": ratio,
        "observed_direction": "rvv-higher" if ratio > 1 else "scalar-higher" if ratio < 1 else "equal",
        "statistical_claim": "descriptive-fixed-QEMU-only",
    }


def environment() -> dict[str, object]:
    os_release = Path("/etc/os-release").read_text() if Path("/etc/os-release").is_file() else ""
    value = {
        "execution_kind": "qemu-user",
        "qemu": version([QEMU, "--version"]),
        "compiler": version([CC, "--version"]),
        "binutils": version([OBJDUMP, "--version"]),
        "cpu": CPU,
        "sysroot": SYSROOT,
        "host": dict(platform.uname()._asdict()),
        "os_release": os_release,
        "runner_image": os.environ.get("ImageOS"),
        "runner_arch": os.environ.get("RUNNER_ARCH"),
    }
    value["fingerprint"] = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    output = parser.parse_args().output.resolve()
    if output.exists():
        raise SystemExit(f"output exists: {output}")
    output.mkdir(parents=True)
    result = {
        "schema": "rax.xxhash-qemu-intervention.v1",
        "status": "running",
        "project": {"repository": REPOSITORY, "revision": REVISION},
    }
    try:
        checkouts = clone_pair(output)
        binaries = {variant: build(path, variant, output) for variant, path in checkouts.items()}
        code = {variant: target_code(binary) for variant, binary in binaries.items()}
        if int(code["rvv"]["rvv_operation_count"]) <= 0:
            raise RuntimeError("RVV build has no target-range RVV operations")
        if int(code["scalar"]["rvv_operation_count"]) != 0:
            raise RuntimeError("scalar control contains target-range RVV operations")
        checked = differential(binaries, output)
        active = {variant: activation(binaries[variant], code[variant], output, variant) for variant in ("rvv", "scalar")}
        if int(active["rvv"]["target_vector_operations"]) <= 0:
            raise RuntimeError("RVV route did not execute a target-range RVV operation")
        if int(active["scalar"]["target_vector_operations"]) != 0:
            raise RuntimeError("scalar control executed a target-range RVV operation")
        endpoint = measure(binaries, output)
        result = {
            "schema": "rax.xxhash-qemu-intervention.v1",
            "status": "complete",
            "run_id": f"gha:{os.environ.get('GITHUB_RUN_ID')}:{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}",
            "project": {
                "repository": REPOSITORY,
                "revision": REVISION,
                "route_id": "xxh3-64b-compile-time",
                "work_set_id": "xxh3-64b-block-1855",
                "work_units": 1,
                "diagnostic_entry": "xxhsum " + " ".join(DIAGNOSTIC_ARGS),
                "endpoint_entry": "xxhsum " + " ".join(ENDPOINT_ARGS),
            },
            "intervention": {
                "factor": "compile-time XXH3 implementation route",
                "rvv_cflags": FLAGS,
                "scalar_cflags": FLAGS + " " + SCALAR_DEFINE,
                "only_intended_difference": SCALAR_DEFINE,
            },
            "environment": environment(),
            "correctness": {"make_check": {"rvv": "pass", "scalar": "pass"}, "differential_inputs": checked, "status": "pass"},
            "artifacts": {variant: {"elf": elf(binary, output), "target_code": code[variant]} for variant, binary in binaries.items()},
            "activation": active,
            "endpoint": endpoint,
            "claim_scope": {
                "qemu_functional": "measured",
                "qemu_relative_timing": "measured",
                "physical_riscv_performance": "not-claimed",
                "retired_instruction_count": "not-measured",
                "exclusive_stage_costs": "not-collected",
            },
        }
        write_json(output / "result.json", result)
        shutil.rmtree(output / "work", ignore_errors=True)
        shutil.rmtree(output / "source", ignore_errors=True)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except Exception as error:
        result["status"] = "failed"
        result["error"] = str(error)
        write_json(output / "result.json", result)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
