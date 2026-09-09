#!/usr/bin/env python3
"""Build and measure the frozen libjpeg-turbo RVV pair on a public QEMU runner.

The public stage intentionally omits the private RAX-Bench check. It packages
the exact binaries, image and QEMU/sysroot needed to run that check off-repo.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import statistics
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from typing import Any, Iterable, Sequence

REPOSITORY = "https://github.com/libjpeg-turbo/libjpeg-turbo"
BASE = "34e04f671e9ee028a8c14449da80474ff259803f"
REFERENCE = "9817c408542c72c0e505360580ae7ebcfa487baf"
CPU = "rv64,v=true,vlen=128,elen=64,vext_spec=v1.0"
SYSROOT = "/usr/riscv64-linux-gnu"
QEMU = "qemu-riscv64"
C_FLAGS = "-march=rv64gcv -mabi=lp64d -O2 -fno-pie"
ASM_FLAGS = "-march=rv64gcv -mabi=lp64d"
BENCHMARK_ARGS = (
    "95", "-precision", "8", "-rgb", "-quiet",
    "-benchtime", "0.2", "-warmup", "0",
)
TRACE_PC_RE = re.compile(r"0x([0-9a-fA-F]+):")
TRACE_OPCODE_RE = re.compile(r"[0-9a-fA-F]{4,16}")
LOAD_RE = re.compile(
    r"^\s*LOAD\s+0x[0-9a-fA-F]+\s+0x([0-9a-fA-F]+)\s+"
    r"0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+0x([0-9a-fA-F]+)\s+"
    r"([RWE ]+)\s+0x[0-9a-fA-F]+\s*$"
)
VECTOR_CONFIG = {"vsetvl", "vsetvli", "vsetivli"}


class StageError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def required(name: str) -> str:
    value = shutil.which(name)
    if not value:
        raise StageError(f"required tool is unavailable: {name}")
    return value


class Recorder:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.rows: list[dict[str, Any]] = []

    def run(
        self,
        label: str,
        command: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: int = 1800,
        check: bool = True,
    ) -> tuple[str, float, int]:
        start = time.perf_counter()
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        elapsed = time.perf_counter() - start
        log = self.root / "logs" / f"{label}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        transcript = "$ " + " ".join(command) + "\n" + completed.stdout
        if not transcript.endswith("\n"):
            transcript += "\n"
        transcript += f"RAX_ELAPSED_SECONDS={elapsed:.17g}\n"
        log.write_text(transcript, encoding="utf-8")
        self.rows.append(
            {
                "label": label,
                "argv": list(command),
                "cwd": None if cwd is None else str(cwd),
                "returncode": completed.returncode,
                "elapsed_seconds": elapsed,
                "log": str(log.relative_to(self.root)),
            }
        )
        if check and completed.returncode:
            raise StageError(
                f"{label} returned {completed.returncode}; see {log}"
            )
        return completed.stdout, elapsed, completed.returncode

    def save(self) -> None:
        write_json(self.root / "commands.json", self.rows)


def checkout_pair(recorder: Recorder, work: Path) -> tuple[Path, Path]:
    mirror = work / "source"
    recorder.run(
        "clone",
        ["git", "clone", "--filter=blob:none", "--no-checkout", REPOSITORY, str(mirror)],
        timeout=900,
    )
    outputs: list[Path] = []
    for label, revision in (("base", BASE), ("reference", REFERENCE)):
        checkout = work / label
        recorder.run(
            f"fetch-{label}",
            ["git", "fetch", "--depth=1", "origin", revision],
            cwd=mirror,
            timeout=900,
        )
        recorder.run(
            f"worktree-{label}",
            ["git", "worktree", "add", "--detach", str(checkout), revision],
            cwd=mirror,
        )
        head, _, _ = recorder.run(
            f"head-{label}", ["git", "rev-parse", "HEAD"], cwd=checkout
        )
        if head.strip() != revision:
            raise StageError(f"{label} checkout identity mismatch")
        outputs.append(checkout)
    return outputs[0], outputs[1]


def make_wrapper(path: Path, compiler: str) -> Path:
    compiler_path = required(compiler)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "#!/bin/sh\n"
        f"exec {compiler_path} --target=riscv64-linux-gnu "
        "--gcc-toolchain=/usr --rtlib=libgcc -fuse-ld=lld "
        '-Wno-unused-command-line-argument "$@"\n',
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def configure_and_build(
    recorder: Recorder, checkout: Path, label: str, output: Path
) -> Path:
    build = checkout / "build-rvv"
    wrappers = output / "compiler-wrappers"
    cc = make_wrapper(wrappers / f"cc-{label}", "clang")
    cxx = make_wrapper(wrappers / f"cxx-{label}", "clang++")
    emulator = f"{QEMU};-cpu;{CPU};-L;{SYSROOT}"
    command = [
        "cmake", "-S", ".", "-B", str(build), "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_SYSTEM_NAME=Linux",
        "-DCMAKE_SYSTEM_PROCESSOR=riscv64",
        f"-DCMAKE_C_COMPILER={cc}",
        f"-DCMAKE_CXX_COMPILER={cxx}",
        f"-DCMAKE_ASM_COMPILER={cc}",
        f"-DCMAKE_AR={required('riscv64-linux-gnu-ar')}",
        f"-DCMAKE_RANLIB={required('riscv64-linux-gnu-ranlib')}",
        f"-DCMAKE_STRIP={required('riscv64-linux-gnu-strip')}",
        f"-DCMAKE_C_FLAGS={C_FLAGS}",
        f"-DCMAKE_ASM_FLAGS={ASM_FLAGS}",
        "-DCMAKE_EXE_LINKER_FLAGS=-no-pie -fuse-ld=lld",
        f"-DCMAKE_CROSSCOMPILING_EMULATOR={emulator}",
        "-DWITH_SIMD=1", "-DENABLE_SHARED=1", "-DENABLE_STATIC=1",
    ]
    text, _, _ = recorder.run(
        f"configure-{label}", command, cwd=checkout, timeout=1800
    )
    if label == "reference" and (
        "Performing Test HAVE_RVV - Failed" in text
        or "SIMD extensions not available for this CPU" in text
    ):
        raise StageError("reference build disabled the RVV SIMD backend")
    recorder.run(
        f"build-{label}",
        [
            "cmake", "--build", str(build), "--target",
            "tjbench-static", "tjunittest-static",
            "cjpeg-static", "djpeg-static", "-j2",
        ],
        cwd=checkout,
        timeout=3600,
    )
    return build


def qemu(binary: Path, arguments: Iterable[str] = (), *, trace: Path | None = None) -> list[str]:
    command = [QEMU, "-cpu", CPU, "-L", SYSROOT]
    if trace is not None:
        command += ["-d", "in_asm", "-D", str(trace)]
    return [*command, str(binary), *arguments]


def symbol_ranges(binary: Path, hints: Sequence[str]) -> list[tuple[int, int, str]]:
    completed = subprocess.run(
        ["riscv64-linux-gnu-nm", "-S", "-n", "-C", str(binary)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if completed.returncode:
        return []
    lowered = [hint.lower() for hint in hints]
    ranges: list[tuple[int, int, str]] = []
    for line in completed.stdout.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) < 4:
            continue
        address, size, _kind, name = fields
        if not any(hint in name.lower() for hint in lowered):
            continue
        try:
            start, length = int(address, 16), int(size, 16)
        except ValueError:
            continue
        if length:
            ranges.append((start, start + length, name))
    return ranges


def executable_ranges(binary: Path) -> list[tuple[int, int]]:
    completed = subprocess.run(
        ["riscv64-linux-gnu-readelf", "-W", "-l", str(binary)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    ranges: list[tuple[int, int]] = []
    for line in completed.stdout.splitlines():
        match = LOAD_RE.match(line)
        if not match or "E" not in match.group(3):
            continue
        start, length = int(match.group(1), 16), int(match.group(2), 16)
        if length:
            ranges.append((start, start + length))
    return ranges


def trace_activation(
    recorder: Recorder, binary: Path, arguments: Sequence[str], output: Path
) -> dict[str, Any]:
    trace = output / "activation" / "trace.log"
    trace.parent.mkdir(parents=True, exist_ok=True)
    recorder.run(
        "activation",
        qemu(binary, arguments, trace=trace),
        cwd=binary.parent,
        timeout=1800,
    )
    targets = symbol_ranges(binary, ["jsimd_", "rgb_ycc", "fdct", "downsample"])
    binaries = executable_ranges(binary)
    target_hits = target_vector = total_vector = 0
    target_pcs: set[int] = set()
    with trace.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            match = TRACE_PC_RE.search(line)
            if not match:
                continue
            fields = line[match.end():].strip().split()
            if len(fields) < 2 or not TRACE_OPCODE_RE.fullmatch(fields[0]):
                continue
            pc, mnemonic = int(match.group(1), 16), fields[1].lower()
            in_target = any(start <= pc < end for start, end, _ in targets)
            if in_target:
                target_hits += 1
            is_vector = mnemonic in VECTOR_CONFIG or (
                mnemonic.startswith("v") and "." in mnemonic
            )
            if is_vector:
                total_vector += 1
                if in_target:
                    target_vector += 1
                    target_pcs.add(pc)
    if not targets or target_hits <= 0 or target_vector <= 0:
        raise StageError("selected tjbench path did not execute target RVV code")
    return {
        "symbol_ranges": [
            {"start": hex(start), "end": hex(end), "name": name}
            for start, end, name in targets
        ],
        "binary_ranges": [
            {"start": hex(start), "end": hex(end)} for start, end in binaries
        ],
        "trace_vector_instructions": total_vector,
        "target_instruction_hits": target_hits,
        "target_vector_instructions": target_vector,
        "target_vector_pcs": [hex(value) for value in sorted(target_pcs)],
        "trace_sha256": sha256(trace),
    }


def benchmark_arguments(input_path: Path, benchtime: str = "0.2") -> list[str]:
    values = [str(input_path), *BENCHMARK_ARGS]
    values[values.index("0.2")] = benchtime
    return values


def parse_metric(text: str) -> float:
    for line in text.replace("\r", "\n").splitlines():
        if "RGB (TD)" not in line or "8 /4:4:4" not in line:
            continue
        fields = line.split()
        if len(fields) >= 8:
            try:
                value = float(fields[7])
            except ValueError:
                continue
            if math.isfinite(value) and value > 0:
                return value
    raise StageError("tjbench did not emit the frozen RGB 4:4:4 metric")


def measure(
    recorder: Recorder,
    base: Path,
    reference: Path,
    builds: dict[str, Path],
    output: Path,
) -> dict[str, Any]:
    samples: list[dict[str, Any]] = []
    checkouts = {"base": base, "reference": reference}
    for round_index in range(3):
        order = (
            ("base", "reference")
            if round_index % 2 == 0
            else ("reference", "base")
        )
        for label in order:
            text, elapsed, _ = recorder.run(
                f"measurement-round-{round_index + 1}-{label}",
                qemu(
                    builds[label] / "tjbench-static",
                    benchmark_arguments(
                        checkouts[label] / "testimages" / "testorig.ppm"
                    ),
                ),
                cwd=builds[label],
                timeout=1200,
            )
            samples.append(
                {
                    "round": round_index + 1,
                    "variant": label,
                    "metric": parse_metric(text),
                    "external_elapsed_seconds": elapsed,
                }
            )
    medians = {
        label: statistics.median(
            float(row["metric"]) for row in samples if row["variant"] == label
        )
        for label in ("base", "reference")
    }
    return {
        "metric": "tjbench_rgb_444_compression_mpix_s",
        "direction": "higher-is-better",
        "samples": samples,
        "median": medians,
        "reference_over_base": medians["reference"] / medians["base"],
    }


def package_private_check(
    recorder: Recorder,
    base: Path,
    builds: dict[str, Path],
    output: Path,
) -> dict[str, Any]:
    package = output / "private-check-package"
    package.mkdir(parents=True)
    for label, build in builds.items():
        folder = package / label
        folder.mkdir()
        for name in ("cjpeg-static", "djpeg-static"):
            shutil.copy2(build / name, folder / name)
    shutil.copy2(base / "testimages" / "testorig.ppm", package / "testorig.ppm")

    runtime = package / "runtime"
    runtime.mkdir()
    qemu_path = Path(required(QEMU))
    shutil.copy2(qemu_path, runtime / "qemu-riscv64")
    with tarfile.open(runtime / "riscv64-linux-gnu.tar.gz", "w:gz") as archive:
        archive.add(SYSROOT, arcname="riscv64-linux-gnu")

    files = [
        {
            "path": str(path.relative_to(package)),
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        for path in sorted(package.rglob("*"))
        if path.is_file()
    ]
    write_json(
        package / "contract.json",
        {
            "schema": "rax.libjpeg-private-check-package.v1",
            "task_id": "libjpeg-turbo-9817c40",
            "source": {"base": BASE, "reference": REFERENCE},
            "qemu_cpu": CPU,
            "sysroot_archive_root": "riscv64-linux-gnu",
            "expected_private_check": [
                "q75-420", "q95-444", "q90-gray"
            ],
            "files": files,
        },
    )
    recorder.run(
        "runtime-qemu-version",
        [str(runtime / "qemu-riscv64"), "--version"],
        check=True,
    )
    return {
        "package": str(package.relative_to(output)),
        "contract": str((package / "contract.json").relative_to(output)),
        "qemu_sha256": sha256(runtime / "qemu-riscv64"),
        "sysroot_archive_sha256": sha256(
            runtime / "riscv64-linux-gnu.tar.gz"
        ),
    }


def version(command: Sequence[str]) -> str:
    completed = subprocess.run(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if completed.returncode or not completed.stdout.strip():
        raise StageError(f"cannot query version: {' '.join(command)}")
    return completed.stdout.splitlines()[0]


def run(output: Path) -> int:
    output = output.resolve()
    if output.exists() and any(output.iterdir()):
        raise StageError(f"output must be empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    recorder = Recorder(output)
    result: dict[str, Any] = {
        "schema": "rax.libjpeg-q1-public.v1",
        "task_id": "libjpeg-turbo-9817c40",
        "rax_source_sha": os.environ.get("RAX_SOURCE_SHA"),
        "claim_scope": "qemu-relative",
        "source": {
            "repository": REPOSITORY,
            "base": BASE,
            "reference": REFERENCE,
        },
        "runner": {
            "qemu": version([QEMU, "--version"]),
            "compiler": version(["clang", "--version"]),
            "cpu": CPU,
            "sysroot": SYSROOT,
        },
        "gates": {
            "build": "pending",
            "public_correctness": "pending",
            "activation": "pending",
            "measurement": "pending",
            "private_correctness": "pending-off-repo",
        },
    }
    try:
        base, reference = checkout_pair(recorder, output / "work")
        builds = {
            "base": configure_and_build(recorder, base, "base", output),
            "reference": configure_and_build(
                recorder, reference, "reference", output
            ),
        }
        result["gates"]["build"] = "pass"

        for label, build in builds.items():
            recorder.run(
                f"public-test-{label}",
                qemu(build / "tjunittest-static"),
                cwd=build,
                timeout=1800,
            )
        result["gates"]["public_correctness"] = "pass"

        result["activation"] = trace_activation(
            recorder,
            builds["reference"] / "tjbench-static",
            benchmark_arguments(
                reference / "testimages" / "testorig.ppm", "0.01"
            ),
            output,
        )
        result["gates"]["activation"] = "pass"

        result["measurement"] = measure(
            recorder, base, reference, builds, output
        )
        result["gates"]["measurement"] = "pass"
        result["private_check_package"] = package_private_check(
            recorder, base, builds, output
        )
        result["status"] = "awaiting-private-correctness"
        write_json(output / "result.json", result)
        recorder.save()
        return 0
    except Exception as error:
        result["status"] = "failed"
        result["error"] = f"{type(error).__name__}: {error}"
        write_json(output / "result.json", result)
        recorder.save()
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        return run(args.output)
    except (OSError, StageError, subprocess.SubprocessError, ValueError) as error:
        print(f"LIBJPEG PUBLIC Q1 FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
