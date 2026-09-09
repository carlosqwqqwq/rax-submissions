#!/usr/bin/env python3
"""Run the fixed Boost.UUID PR #196 public-entry replay under QEMU."""

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
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

BASE_REPO = "https://github.com/boostorg/uuid.git"
BASE_REV = "2aa25a3afe023c5324d1b13015a65f67bfaef08c"
CANDIDATE_REPO = "https://github.com/e4d08/uuid.git"
CANDIDATE_REV = "a3b8f19c17861507a13cbbfa4b9b396f82699694"
WRAPPERS = ("rax_parse_char", "rax_parse_char16", "rax_parse_char32")
CHAR_TYPES = ("char", "char16_t", "char32_t")
EXPECTED = (
    ("success-lower", 36, "none", "000102030405060708090a0b0c0d0e0f"),
    ("success-upper", 36, "none", "1234567890abcdef1234567890abcdef"),
    ("success-prefix-extra", 36, "none", "000102030405060708090a0b0c0d0e0f"),
    ("eoi-empty", 0, "unexpected_end_of_input", ""),
    ("eoi-one", 1, "unexpected_end_of_input", ""),
    ("eoi-35", 35, "unexpected_end_of_input", ""),
    ("hex-at-zero", 0, "hex_digit_expected", ""),
    ("hex-at-six", 6, "hex_digit_expected", ""),
    ("hex-at-35", 35, "hex_digit_expected", ""),
    ("dash-at-8", 8, "dash_expected", ""),
    ("dash-at-13", 13, "dash_expected", ""),
    ("dash-at-18", 18, "dash_expected", ""),
    ("dash-at-23", 23, "dash_expected", ""),
)
BENCHMARK_CASES = (
    "success-lower",
    "eoi-one",
    "hex-at-zero",
    "hex-at-six",
    "hex-at-35",
    "dash-at-8",
    "dash-at-23",
)
BENCHMARK_VARIANTS = ("candidate-generic", "candidate-rvv")
BENCHMARK_ITERATIONS = 250_000
BENCHMARK_REPETITIONS = 9
OBJDUMP_LINE = re.compile(
    r"^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2,16}\s+)+"
    r"([a-z][a-z0-9_.]*)\b"
)
TRACE_LINE = re.compile(
    r"^\s*0x([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2,16}\s+)+"
    r"([a-z][a-z0-9_.]*)\b"
)
NM_LINE = re.compile(
    r"^([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+\S\s+(\S+)$"
)


class ReplayError(RuntimeError):
    pass


class Recorder:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.rows: list[dict[str, Any]] = []

    def run(
        self,
        label: str,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        check: bool = True,
        timeout: int = 240,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            list(argv),
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        folder = self.root / "logs"
        folder.mkdir(parents=True, exist_ok=True)
        stdout = folder / f"{label}.stdout"
        stderr = folder / f"{label}.stderr"
        stdout.write_text(result.stdout, encoding="utf-8")
        stderr.write_text(result.stderr, encoding="utf-8")
        self.rows.append(
            {
                "label": label,
                "argv": list(argv),
                "cwd": None if cwd is None else str(cwd),
                "returncode": result.returncode,
                "stdout": str(stdout.relative_to(self.root)),
                "stderr": str(stderr.relative_to(self.root)),
            }
        )
        if check and result.returncode:
            raise ReplayError(
                f"{label} returned {result.returncode}; see {stderr}"
            )
        return result

    def save(self) -> None:
        write_jsonl(self.root / "commands.jsonl", self.rows)


def tool(name: str) -> str:
    value = shutil.which(name)
    if value is None:
        raise ReplayError(f"required tool is absent: {name}")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def checkout(
    recorder: Recorder,
    label: str,
    repository: str,
    revision: str,
    destination: Path,
) -> dict[str, str]:
    destination.mkdir(parents=True)
    git = tool("git")
    recorder.run(f"{label}-init", [git, "init", "-q"], cwd=destination)
    recorder.run(
        f"{label}-remote",
        [git, "remote", "add", "origin", repository],
        cwd=destination,
    )
    recorder.run(
        f"{label}-fetch",
        [git, "fetch", "--depth", "1", "origin", revision],
        cwd=destination,
        timeout=360,
    )
    recorder.run(
        f"{label}-checkout",
        [git, "checkout", "--detach", "-q", "FETCH_HEAD"],
        cwd=destination,
    )
    head = recorder.run(
        f"{label}-head", [git, "rev-parse", "HEAD"], cwd=destination
    ).stdout.strip()
    tree = recorder.run(
        f"{label}-tree",
        [git, "rev-parse", "HEAD^{tree}"],
        cwd=destination,
    ).stdout.strip()
    if head != revision:
        raise ReplayError(f"{label} revision mismatch: {head}")
    return {"repository": repository, "revision": head, "tree": tree}


def parse_records(stdout: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(stdout.splitlines(), 1):
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 6:
            raise ReplayError(f"invalid record on line {number}: {line!r}")
        case_id, char_type, verdict, offset, error, uuid_hex = fields
        rows.append(
            {
                "case_id": case_id,
                "character_type": char_type,
                "verdict": verdict,
                "offset": int(offset),
                "error": error,
                "uuid_hex": uuid_hex,
            }
        )
    return rows


def check_records(rows: list[dict[str, Any]]) -> None:
    expected = {
        (case_id, char_type): (offset, error, uuid_hex)
        for case_id, offset, error, uuid_hex in EXPECTED
        for char_type in CHAR_TYPES
    }
    if len(rows) != len(expected):
        raise ReplayError("semantic record count differs from the fixed matrix")
    for row in rows:
        key = (row["case_id"], row["character_type"])
        observed = (row["offset"], row["error"], row["uuid_hex"])
        if (
            key not in expected
            or row["verdict"] != "pass"
            or observed != expected[key]
        ):
            raise ReplayError(f"semantic oracle rejected {key}: {observed}")


def parse_benchmark(stdout: str) -> dict[str, Any]:
    lines = [line for line in stdout.splitlines() if line]
    if len(lines) != 1:
        raise ReplayError(f"benchmark produced {len(lines)} records")
    fields = lines[0].split("\t")
    if len(fields) != 6 or fields[0] != "BENCH":
        raise ReplayError(f"invalid benchmark record: {lines[0]!r}")
    _, case_id, character_type, iterations, elapsed_ns, sink = fields
    row = {
        "case_id": case_id,
        "character_type": character_type,
        "iterations": int(iterations),
        "elapsed_ns": int(elapsed_ns),
        "sink": sink,
    }
    if (
        row["character_type"] != "char"
        or row["iterations"] <= 0
        or row["elapsed_ns"] <= 0
    ):
        raise ReplayError(f"invalid benchmark values: {row!r}")
    return row


def instruction_mnemonics(text: str, pattern: re.Pattern[str]) -> list[str]:
    return sorted(
        {
            match.group(match.lastindex or 1)
            for line in text.splitlines()
            if (match := pattern.match(line))
            and match.group(match.lastindex or 1).startswith("v")
        }
    )


def build(
    recorder: Recorder,
    name: str,
    source: Path,
    march: str,
    harness: Path,
    output: Path,
    tools: dict[str, str],
) -> dict[str, Any]:
    folder = output / "build" / name
    folder.mkdir(parents=True)
    binary = folder / "boost_uuid_from_chars"
    result = recorder.run(
        f"build-{name}",
        [
            tools["cxx"],
            "-O3",
            "-g",
            "-std=gnu++17",
            f"-march={march}",
            "-mabi=lp64d",
            "-fno-omit-frame-pointer",
            "-fno-ipa-icf",
            "-Wall",
            "-Wextra",
            "-static",
            "-I",
            str(source / "include"),
            str(harness),
            "-o",
            str(binary),
        ],
        timeout=360,
    )
    marker = (
        "Using from_chars_riscv.hpp, RISC-V Vector Extension"
        if name == "candidate-rvv"
        else "Using from_chars_generic.hpp"
    )
    if marker not in result.stdout + result.stderr:
        raise ReplayError(f"{name} did not report {marker!r}")

    identity: dict[str, str] = {}
    for label, command in {
        "readelf-header": [tools["readelf"], "-h", str(binary)],
        "readelf-notes": [tools["readelf"], "-n", str(binary)],
        "nm": [tools["nm"], "-S", "-n", "--defined-only", str(binary)],
    }.items():
        text = recorder.run(f"{name}-{label}", command).stdout
        path = folder / f"{label}.txt"
        path.write_text(text, encoding="utf-8")
        identity[label] = str(path.relative_to(output))

    wrappers: dict[str, Any] = {}
    for symbol in WRAPPERS:
        text = recorder.run(
            f"{name}-objdump-{symbol}",
            [
                tools["objdump"],
                "-d",
                "-C",
                f"--disassemble={symbol}",
                str(binary),
            ],
        ).stdout
        path = folder / f"objdump-{symbol}.txt"
        path.write_text(text, encoding="utf-8")
        wrappers[symbol] = {
            "objdump": str(path.relative_to(output)),
            "vector_mnemonics": instruction_mnemonics(text, OBJDUMP_LINE),
        }

    with_vector = [
        wrapper for wrapper, value in wrappers.items() if value["vector_mnemonics"]
    ]
    if name == "candidate-rvv" and set(with_vector) != set(WRAPPERS):
        raise ReplayError("not every RVV public wrapper contains vector code")
    if name != "candidate-rvv" and with_vector:
        raise ReplayError(f"{name} public wrapper contains vector code")

    return {
        "name": name,
        "source_revision": BASE_REV if name == "baseline-generic" else CANDIDATE_REV,
        "march": march,
        "binary": str(binary.relative_to(output)),
        "binary_sha256": sha256(binary),
        "implementation_marker": marker,
        "identity": identity,
        "wrappers": wrappers,
    }


def select_profile(
    recorder: Recorder,
    vlen: int,
    binary: Path,
) -> list[str]:
    values = (
        f"rv64,v=true,vlen={vlen},elen=64,vext_spec=v1.0",
        f"max,v=true,vlen={vlen},elen=64,vext_spec=v1.0",
        f"rv64,v=true,vlen={vlen},elen=64",
        f"max,v=true,vlen={vlen},elen=64",
    )
    attempts: list[dict[str, Any]] = []
    for index, cpu in enumerate(values):
        prefix = [tool("qemu-riscv64"), "-cpu", cpu]
        result = recorder.run(
            f"profile-{vlen}-{index}",
            [*prefix, str(binary), "--probe"],
            check=False,
            timeout=120,
        )
        attempts.append({"cpu": cpu, "returncode": result.returncode})
        if result.returncode == 0:
            rows = parse_records(result.stdout)
            if rows and all(row["verdict"] == "pass" for row in rows):
                return prefix
    raise ReplayError(
        f"no working QEMU profile for VLEN={vlen}: {attempts!r}"
    )


def ranges(nm_text: str) -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    for line in nm_text.splitlines():
        match = NM_LINE.match(line.strip())
        if match and match.group(3) in WRAPPERS:
            start = int(match.group(1), 16)
            result[match.group(3)] = (
                start,
                start + int(match.group(2), 16),
            )
    if set(result) != set(WRAPPERS):
        raise ReplayError("nm does not contain all public wrapper ranges")
    return result


def trace(
    recorder: Recorder,
    prefix: Sequence[str],
    binary: Path,
    folder: Path,
) -> dict[str, Any]:
    trace_file = folder / "qemu-in-asm.log"
    process = recorder.run(
        f"trace-{folder.name}",
        [
            *prefix,
            "-d",
            "in_asm",
            "-D",
            str(trace_file),
            str(binary),
            "--probe",
        ],
        timeout=180,
    )
    if any(row["verdict"] != "pass" for row in parse_records(process.stdout)):
        raise ReplayError("trace probe failed semantics")

    symbol_ranges = ranges(
        (binary.parent / "nm.txt").read_text(encoding="utf-8")
    )
    executed: set[str] = set()
    vector_lines: list[str] = []
    wrapper_lines: list[str] = []
    for line in trace_file.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        match = TRACE_LINE.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        mnemonic = match.group(2)
        for symbol, (start, end) in symbol_ranges.items():
            if start <= address < end:
                executed.add(symbol)
                wrapper_lines.append(line)
        if mnemonic.startswith("v"):
            vector_lines.append(line)

    if "rax_parse_char" not in executed or not vector_lines:
        raise ReplayError("trace lacks public-wrapper or executed RVV evidence")
    excerpt = folder / "qemu-in-asm-excerpt.txt"
    excerpt.write_text(
        "\n".join(
            [
                "[public wrapper]",
                *wrapper_lines[:160],
                "",
                "[executed vector instructions]",
                *vector_lines[:160],
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        "trace": str(trace_file.relative_to(recorder.root)),
        "trace_sha256": sha256(trace_file),
        "excerpt": str(excerpt.relative_to(recorder.root)),
        "executed_wrappers": sorted(executed),
        "executed_vector_instruction_count": len(vector_lines),
        "executed_vector_mnemonics": sorted(
            {
                TRACE_LINE.match(line).group(2)
                for line in vector_lines
                if TRACE_LINE.match(line)
            }
        ),
    }


def sign_test_two_sided(ratios: Sequence[float]) -> float:
    positive = sum(value > 1.0 for value in ratios)
    negative = sum(value < 1.0 for value in ratios)
    count = positive + negative
    if count == 0:
        return 1.0
    tail = min(positive, negative)
    probability = 2.0 * sum(
        math.comb(count, index) for index in range(tail + 1)
    ) / (2**count)
    return min(1.0, probability)


def benchmark_profile(
    recorder: Recorder,
    prefix: Sequence[str],
    builds: dict[str, dict[str, Any]],
    output: Path,
    vlen: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}
    binaries = {
        name: output / builds[name]["binary"] for name in BENCHMARK_VARIANTS
    }

    for case_id in BENCHMARK_CASES:
        case_rows: list[dict[str, Any]] = []
        for repetition in range(BENCHMARK_REPETITIONS):
            order = (
                BENCHMARK_VARIANTS
                if repetition % 2 == 0
                else tuple(reversed(BENCHMARK_VARIANTS))
            )
            for order_index, name in enumerate(order):
                process = recorder.run(
                    f"bench-{vlen}-{case_id}-{repetition}-{name}",
                    [
                        *prefix,
                        str(binaries[name]),
                        "--benchmark",
                        case_id,
                        str(BENCHMARK_ITERATIONS),
                    ],
                    timeout=300,
                )
                row = parse_benchmark(process.stdout)
                if (
                    row["case_id"] != case_id
                    or row["iterations"] != BENCHMARK_ITERATIONS
                ):
                    raise ReplayError("benchmark identity differs from protocol")
                row.update(
                    {
                        "vlen": vlen,
                        "variant": name,
                        "repetition": repetition,
                        "order_index": order_index,
                    }
                )
                case_rows.append(row)
                rows.append(row)

        if len({row["sink"] for row in case_rows}) != 1:
            raise ReplayError(f"benchmark semantic sink differs for {case_id}")
        by_pair: dict[int, dict[str, int]] = {}
        for row in case_rows:
            by_pair.setdefault(row["repetition"], {})[row["variant"]] = row[
                "elapsed_ns"
            ]
        if any(set(pair) != set(BENCHMARK_VARIANTS) for pair in by_pair.values()):
            raise ReplayError(f"benchmark pair incomplete for {case_id}")

        ratios = [
            pair["candidate-generic"] / pair["candidate-rvv"]
            for _, pair in sorted(by_pair.items())
        ]
        p_value = sign_test_two_sided(ratios)
        median_ratio = statistics.median(ratios)
        if p_value <= 0.05 and median_ratio > 1.0:
            direction = "rvv-benefit"
        elif p_value <= 0.05 and median_ratio < 1.0:
            direction = "rvv-regression"
        else:
            direction = "no-clear-direction"

        medians: dict[str, float] = {}
        for name in BENCHMARK_VARIANTS:
            values = [
                row["elapsed_ns"]
                for row in case_rows
                if row["variant"] == name
            ]
            medians[name] = statistics.median(values) / BENCHMARK_ITERATIONS
        summary[case_id] = {
            "character_type": "char",
            "iterations_per_sample": BENCHMARK_ITERATIONS,
            "paired_repetitions": BENCHMARK_REPETITIONS,
            "candidate_generic_median_ns_per_call": medians[
                "candidate-generic"
            ],
            "candidate_rvv_median_ns_per_call": medians["candidate-rvv"],
            "paired_speedup_generic_over_rvv": ratios,
            "median_paired_speedup_generic_over_rvv": median_ratio,
            "two_sided_exact_sign_p": p_value,
            "direction": direction,
        }
    return rows, summary


def version(recorder: Recorder, label: str, argv: Sequence[str]) -> str:
    result = recorder.run(label, argv, check=False)
    text = (result.stdout + result.stderr).strip()
    if result.returncode or not text:
        raise ReplayError(f"cannot obtain {label}")
    return text.splitlines()[0]


def host_identity() -> dict[str, Any]:
    cpu_model = None
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            if line.lower().startswith(("model name", "hardware")):
                cpu_model = line.split(":", 1)[-1].strip()
                break
    affinity = None
    if hasattr(os, "sched_getaffinity"):
        affinity = sorted(os.sched_getaffinity(0))
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_model": cpu_model,
        "logical_cpu_count": os.cpu_count(),
        "process_affinity": affinity,
    }


def manifest(root: Path) -> list[dict[str, Any]]:
    ignored = {root / "manifest.json"}
    return [
        {
            "path": str(path.relative_to(root)),
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        for path in sorted(root.rglob("*"))
        if path.is_file() and path not in ignored
    ]


def run(output: Path) -> dict[str, Any]:
    output = output.resolve()
    if output.exists() and any(output.iterdir()):
        raise ReplayError(f"output is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    recorder = Recorder(output)
    package = Path(__file__).resolve().parent
    harness = package / "harness.cpp"

    tools = {
        name: tool(executable)
        for name, executable in {
            "cxx": "riscv64-linux-gnu-g++",
            "objdump": "riscv64-linux-gnu-objdump",
            "readelf": "riscv64-linux-gnu-readelf",
            "nm": "riscv64-linux-gnu-nm",
            "qemu": "qemu-riscv64",
        }.items()
    }
    versions = {
        "compiler": version(
            recorder, "version-cxx", [tools["cxx"], "--version"]
        ),
        "objdump": version(
            recorder, "version-objdump", [tools["objdump"], "--version"]
        ),
        "qemu": version(
            recorder, "version-qemu", [tools["qemu"], "--version"]
        ),
        "python": sys.version.splitlines()[0],
    }
    recorder.run(
        "qemu-cpu-help", [tools["qemu"], "-cpu", "help"], check=False
    )

    sources = output / "sources"
    source_identity = {
        "base": checkout(
            recorder, "base", BASE_REPO, BASE_REV, sources / "base"
        ),
        "candidate": checkout(
            recorder,
            "candidate",
            CANDIDATE_REPO,
            CANDIDATE_REV,
            sources / "candidate",
        ),
    }
    builds = {
        "baseline-generic": build(
            recorder,
            "baseline-generic",
            sources / "base",
            "rv64gc",
            harness,
            output,
            tools,
        ),
        "candidate-generic": build(
            recorder,
            "candidate-generic",
            sources / "candidate",
            "rv64gc",
            harness,
            output,
            tools,
        ),
        "candidate-rvv": build(
            recorder,
            "candidate-rvv",
            sources / "candidate",
            "rv64gcv",
            harness,
            output,
            tools,
        ),
    }
    shutil.rmtree(sources)

    all_rows: list[dict[str, Any]] = []
    benchmark_rows: list[dict[str, Any]] = []
    profiles: dict[str, Any] = {}
    rvv_binary = output / builds["candidate-rvv"]["binary"]
    for vlen in (128, 256):
        folder = output / "runs" / f"vlen-{vlen}"
        folder.mkdir(parents=True)
        prefix = select_profile(recorder, vlen, rvv_binary)
        observed: dict[str, list[dict[str, Any]]] = {}
        for name, build_info in builds.items():
            binary = output / build_info["binary"]
            result = recorder.run(
                f"run-{vlen}-{name}", [*prefix, str(binary)], timeout=180
            )
            rows = parse_records(result.stdout)
            check_records(rows)
            observed[name] = rows
            all_rows.extend(
                {**row, "variant": name, "vlen": vlen} for row in rows
            )
        baseline = observed["baseline-generic"]
        if any(rows != baseline for rows in observed.values()):
            raise ReplayError(f"semantic divergence at VLEN={vlen}")
        measured_rows, measured_summary = benchmark_profile(
            recorder,
            prefix,
            builds,
            output,
            vlen,
        )
        benchmark_rows.extend(measured_rows)
        profiles[str(vlen)] = {
            "qemu_prefix": prefix,
            "semantic_equivalence": True,
            "records_per_variant": len(baseline),
            "trace": trace(recorder, prefix, rvv_binary, folder),
            "qemu_conditioned_cost": measured_summary,
        }

    write_jsonl(output / "semantic-records.jsonl", all_rows)
    write_jsonl(output / "qemu-cost-samples.jsonl", benchmark_rows)
    host = host_identity()
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "source": source_identity,
                "versions": versions,
                "host": host,
                "profiles": {
                    key: value["qemu_prefix"]
                    for key, value in profiles.items()
                },
                "benchmark_protocol": {
                    "cases": BENCHMARK_CASES,
                    "iterations": BENCHMARK_ITERATIONS,
                    "repetitions": BENCHMARK_REPETITIONS,
                },
                "build_sha256": {
                    name: value["binary_sha256"]
                    for name, value in builds.items()
                },
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    result = {
        "schema": "rax.boost-uuid-qemu.v2",
        "case_id": "boost-uuid-196-error-position-profitability",
        "source": {
            "pull_request": "https://github.com/boostorg/uuid/pull/196",
            **source_identity,
            "changed_paths": [
                "include/boost/uuid/detail/config.hpp",
                "include/boost/uuid/detail/from_chars.hpp",
                "include/boost/uuid/detail/from_chars_riscv.hpp",
            ],
        },
        "package": {
            "harness": "harness.cpp",
            "harness_sha256": sha256(harness),
            "runner": "run.py",
            "runner_sha256": sha256(Path(__file__).resolve()),
        },
        "environment": {
            "execution_kind": "qemu-user",
            "correctness_passed": True,
            "environment_fingerprint": fingerprint,
            "versions": versions,
            "host": host,
        },
        "public_entry": {
            "header": "boost/uuid/uuid_io.hpp",
            "function": "boost::uuids::from_chars",
            "wrappers": list(WRAPPERS),
            "character_types": list(CHAR_TYPES),
        },
        "dispatch": {
            "baseline": builds["baseline-generic"]["implementation_marker"],
            "candidate_generic": builds["candidate-generic"][
                "implementation_marker"
            ],
            "candidate_rvv": builds["candidate-rvv"][
                "implementation_marker"
            ],
            "natural_chain": (
                "__riscv_v -> BOOST_UUID_USE_RISCV_V -> "
                "boost::uuids::from_chars -> detail::from_chars_simd"
            ),
        },
        "builds": builds,
        "semantic_oracle": {
            "source": "upstream tests plus a fixed byte oracle",
            "cases": len(EXPECTED),
            "character_types": len(CHAR_TYPES),
            "records_per_variant": len(EXPECTED) * len(CHAR_TYPES),
            "checks": ["ptr offset", "from_chars_error", "UUID bytes"],
        },
        "qemu_profiles": profiles,
        "correctness_passed": True,
        "natural_dispatch_passed": True,
        "actual_elf_identity_passed": True,
        "executed_rvv_target_code_passed": True,
        "qemu_conditioned_performance": {
            "status": "measured",
            "claim_scope": "fixed-qemu-user-environment-only",
            "metric": "in-guest steady_clock nanoseconds for repeated public char entry",
            "comparison": "candidate-generic versus candidate-rvv from the same source revision",
            "cases": list(BENCHMARK_CASES),
            "iterations_per_sample": BENCHMARK_ITERATIONS,
            "paired_repetitions": BENCHMARK_REPETITIONS,
            "pairing": "alternating generic/RVV order within every repetition",
            "direction_rule": (
                "two-sided exact sign test p<=0.05 and median paired ratio direction"
            ),
            "raw_samples": "qemu-cost-samples.jsonl",
            "not_valid_for": [
                "physical RISC-V processor speed",
                "hardware cycles",
                "cache or bandwidth",
                "pipeline, frequency or power",
            ],
        },
        "physical_processor_performance": {
            "status": "out-of-scope",
            "reason": "the project has no RISC-V development board",
        },
        "semantic_records": "semantic-records.jsonl",
    }
    write_json(output / "result.json", result)
    recorder.save()
    write_json(
        output / "manifest.json",
        {
            "schema": "rax.replay-artifact-manifest.v1",
            "case_id": result["case_id"],
            "files": manifest(output),
        },
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = run(args.output)
    except (
        OSError,
        ReplayError,
        subprocess.SubprocessError,
        ValueError,
    ) as error:
        print(f"BOOST UUID QEMU REPLAY FAILED: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
