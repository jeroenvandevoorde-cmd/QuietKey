#!/usr/bin/env python3
"""Separately invoked QuietKey M16 / Bitcoin Core v28.0 differential runner.

This runner consumes only committed public fixture bytes. It contains no
signer, private-key operation, wallet RPC, transaction submission, or product
dependency on Bitcoin Core.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import platform
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any


CORE_RELEASE = "28.0"
CORE_ARCHIVE = "bitcoin-28.0-x86_64-apple-darwin.tar.gz"
CORE_ARCHIVE_BYTES = 37_680_963
CORE_ARCHIVE_SHA256 = "77e931bbaaf47771a10c376230bf53223f5380864bad3568efc7f4d02e40a0f7"
SUMS_BYTES = 2_620
SUMS_LINES = 25
SUMS_SHA256 = "d1384c7cbb9027bc5642943d675d25f2edd88e34207e0aaa307babf097d6d023"
SUMS_LINE = f"{CORE_ARCHIVE_SHA256}  {CORE_ARCHIVE}"
BITCOIND_SHA256 = "55afd04193715ef76bb445a8aec7c18f1af780b9df8b8e5028c1b78baa15b4ee"
BITCOIN_CLI_SHA256 = "2b53751345cdc0f326fa82e721c1f33b29db75d39f9125cb212d2e38524e4c1c"
BITCOIND_VERSION = "Bitcoin Core version v28.0.0"
BITCOIN_CLI_VERSION = "Bitcoin Core RPC client version v28.0.0"
REGTEST_GENESIS = "0f9188f13cb7b2c71f2a335e3a4f57466c36f5ccfdade5404115b441e1e0a6b7"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as src:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                return h.hexdigest()
            h.update(chunk)


def sha256d_display(data: bytes) -> str:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()[::-1].hex()


def compact_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def parse_hex(value: str, label: str) -> bytes:
    if len(value) % 2:
        raise ValueError(f"{label}: odd hex length")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{label}: invalid hex") from exc


def parse_fixture(path: Path) -> tuple[dict[str, str], list[dict[str, str]]]:
    header: dict[str, str] = {}
    cases: list[dict[str, str]] = []
    current = header
    for number, raw in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        if not raw or raw.startswith("#"):
            continue
        if ": " not in raw and not raw.endswith(":"):
            raise ValueError(f"fixture line {number}: missing ': ' separator")
        key, value = raw.split(":", 1)
        if value.startswith(" "):
            value = value[1:]
        if key == "case":
            current = {"case": value}
            cases.append(current)
        elif key in current:
            raise ValueError(f"fixture line {number}: duplicate field {key}")
        else:
            current[key] = value
    return header, cases


def required(fields: dict[str, str], name: str) -> str:
    try:
        return fields[name]
    except KeyError as exc:
        raise ValueError(f"missing fixture field {name}") from exc


def read_cs(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise ValueError("truncated CompactSize")
    first = data[pos]
    pos += 1
    if first < 0xFD:
        return first, pos
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    end = pos + width
    if end > len(data):
        raise ValueError("truncated CompactSize payload")
    value = int.from_bytes(data[pos:end], "little")
    minimum = {2: 0xFD, 4: 0x10000, 8: 0x100000000}[width]
    if value < minimum:
        raise ValueError("nonminimal CompactSize")
    return value, end


def tx_counts(unsigned: bytes) -> tuple[int, int]:
    pos = 4
    vin, pos = read_cs(unsigned, pos)
    for _ in range(vin):
        pos += 36
        script_len, pos = read_cs(unsigned, pos)
        pos += script_len + 4
        if pos > len(unsigned):
            raise ValueError("truncated unsigned transaction input")
    vout, pos = read_cs(unsigned, pos)
    for _ in range(vout):
        pos += 8
        script_len, pos = read_cs(unsigned, pos)
        pos += script_len
        if pos > len(unsigned):
            raise ValueError("truncated unsigned transaction output")
    if pos + 4 != len(unsigned):
        raise ValueError("unsigned transaction trailing or truncated locktime")
    return vin, vout


Record = tuple[int, bytes, bytes]


def parse_psbt(data: bytes) -> list[list[Record]]:
    if not data.startswith(b"psbt\xff"):
        raise ValueError("bad PSBT magic")
    pos = 5

    def one_map() -> list[Record]:
        nonlocal pos
        records: list[Record] = []
        while True:
            key_len, pos = read_cs(data, pos)
            if key_len == 0:
                return records
            key_end = pos + key_len
            if key_end > len(data):
                raise ValueError("truncated PSBT key")
            key = data[pos:key_end]
            pos = key_end
            value_len, pos = read_cs(data, pos)
            value_end = pos + value_len
            if value_end > len(data):
                raise ValueError("truncated PSBT value")
            value = data[pos:value_end]
            pos = value_end
            key_type, type_end = read_cs(key, 0)
            if type_end > len(key):
                raise ValueError("bad PSBT key type")
            records.append((key_type, key, value))

    maps = [one_map()]
    unsigned_values = [value for typ, key, value in maps[0] if typ == 0 and len(key) == 1]
    if len(unsigned_values) != 1:
        raise ValueError("PSBT must contain one unsigned transaction")
    vin, vout = tx_counts(unsigned_values[0])
    maps.extend(one_map() for _ in range(vin + vout))
    if pos != len(data):
        raise ValueError("PSBT trailing bytes")
    return maps


def map_multisets(maps: list[list[Record]]) -> list[list[Record]]:
    return [sorted(records, key=lambda item: (item[0], item[1], item[2])) for records in maps]


def locate_255_256_order(maps: list[list[Record]]) -> tuple[int, list[int], list[str]]:
    found: list[tuple[int, list[int], list[str]]] = []
    for index, records in enumerate(maps):
        selected = [(typ, key.hex()) for typ, key, _ in records if typ in (255, 256)]
        if selected:
            found.append((index, [typ for typ, _ in selected], [key for _, key in selected]))
    if len(found) != 1:
        raise ValueError("expected exactly one map carrying unknown types 255 and 256")
    return found[0]


class Checks:
    def __init__(self) -> None:
        self.total = 0

    def that(self, condition: bool, message: str) -> None:
        self.total += 1
        if not condition:
            raise AssertionError(message)

    def equal(self, actual: Any, expected: Any, message: str) -> None:
        self.that(actual == expected, f"{message}: actual={actual!r}, expected={expected!r}")


class Core:
    def __init__(self, bitcoind: Path, cli: Path, root: Path, port: int, transcript: list[str]):
        self.bitcoind = bitcoind
        self.cli = cli
        self.root = root
        self.port = port
        self.transcript = transcript
        self.process: subprocess.Popen[bytes] | None = None
        self.log_handle: Any = None
        self.rpc_index = 0

    def start(self) -> None:
        log_path = self.root / "bitcoind.log"
        self.log_handle = log_path.open("wb")
        args = [
            str(self.bitcoind),
            f"-datadir={self.root}",
            "-regtest=1",
            "-server=1",
            "-disablewallet=1",
            "-listen=0",
            "-connect=0",
            "-dnsseed=0",
            "-fixedseeds=0",
            "-discover=0",
            "-upnp=0",
            "-natpmp=0",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            f"-rpcport={self.port}",
            "-printtoconsole=1",
        ]
        self.process = subprocess.Popen(args, stdout=self.log_handle, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 30
        last_error = ""
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"bitcoind exited during startup with {self.process.returncode}")
            try:
                self.rpc("getblockchaininfo")
                return
            except RuntimeError as exc:
                last_error = str(exc)
                time.sleep(0.1)
        raise RuntimeError(f"bitcoind RPC startup timeout: {last_error}")

    def rpc(self, method: str, *params: str) -> Any:
        args = [
            str(self.cli),
            "-regtest",
            f"-datadir={self.root}",
            f"-rpcport={self.port}",
            "-rpcclienttimeout=30",
            method,
            *params,
        ]
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"RPC {method} failed ({proc.returncode}): {proc.stderr.strip()}")
        raw = proc.stdout.strip()
        result = None if raw in ("", "null") else json.loads(raw)
        prefix = f"rpc_{self.rpc_index:03d}"
        self.transcript.append(f"{prefix}_method={method}")
        self.transcript.append(f"{prefix}_params={compact_json(list(params))}")
        self.transcript.append(f"{prefix}_result={compact_json(result)}")
        self.rpc_index += 1
        return result

    def stop(self) -> int:
        if self.process is None:
            return 0
        if self.process.poll() is None:
            try:
                self.rpc("stop")
            except Exception as exc:  # preserve failure in transcript; still terminate below
                self.transcript.append(f"daemon_stop_rpc_error={compact_json(str(exc))}")
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=10)
        if self.log_handle is not None:
            self.log_handle.close()
        return int(self.process.returncode or 0)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def first_line(path: Path, argument: str) -> str:
    proc = subprocess.run([str(path), argument], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"{path.name} {argument} failed")
    return proc.stdout.splitlines()[0]


def choose_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def safe_extract(archive: Path, destination: Path) -> None:
    root = destination.resolve()
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        for member in members:
            target = (destination / member.name).resolve()
            if root not in target.parents and target != root:
                raise ValueError("archive path escapes extraction root")
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError("archive contains unsupported link/device entry")
        tar.extractall(destination, members=members)


def fixture_bytes(case: dict[str, str], stem: str, checks: Checks) -> bytes:
    data = parse_hex(required(case, f"{stem}_hex"), f"{case['case']} {stem}")
    checks.equal(len(data), int(required(case, f"{stem}_len")), f"{case['case']} {stem} length")
    checks.equal(sha256_bytes(data), required(case, f"{stem}_sha256"), f"{case['case']} {stem} SHA256")
    return data


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--procedure", required=True, type=Path)
    parser.add_argument("--sha256sums", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--transcript", required=True, type=Path)
    args = parser.parse_args()

    transcript_path = args.transcript.resolve()
    if transcript_path.exists():
        raise SystemExit("refusing to overwrite transcript")
    transcript: list[str] = ["QUIETKEY_M16_CORE_DIFFERENTIAL_TRANSCRIPT_V1"]
    checks = Checks()
    core: Core | None = None
    error: str | None = None

    try:
        repo = args.repo_root.resolve()
        fixture = args.fixture.resolve()
        procedure = args.procedure.resolve()
        sums = args.sha256sums.resolve()
        archive = args.archive.resolve()
        runner = Path(__file__).resolve()

        checks.equal(git(repo, "status", "--porcelain"), "", "repository clean at entry")
        transcript.extend(
            [
                f"run_utc={dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')}",
                f"repo_commit={git(repo, 'rev-parse', 'HEAD')}",
                f"repo_tree={git(repo, 'rev-parse', 'HEAD^{tree}')}",
                "repo_clean=true",
                f"host_os={platform.system()}",
                f"host_release={platform.release()}",
                f"host_arch={platform.machine()}",
                f"python_version={platform.python_version()}",
                f"harness_sha256={sha256_file(runner)}",
                f"procedure_sha256={sha256_file(procedure)}",
                f"fixture_sha256={sha256_file(fixture)}",
                f"core_release={CORE_RELEASE}",
            ]
        )

        sums_data = sums.read_bytes()
        checks.equal(len(sums_data), SUMS_BYTES, "SHA256SUMS size")
        checks.equal(sums_data.count(b"\n"), SUMS_LINES, "SHA256SUMS LF count")
        checks.that(sums_data.endswith(b"\n"), "SHA256SUMS final LF")
        checks.equal(sha256_bytes(sums_data), SUMS_SHA256, "SHA256SUMS SHA256")
        lines = sums_data.decode("ascii").splitlines()
        checks.equal([line for line in lines if line.endswith(f"  {CORE_ARCHIVE}")], [SUMS_LINE], "selected checksum line")
        checks.equal(archive.name, CORE_ARCHIVE, "archive filename")
        checks.equal(archive.stat().st_size, CORE_ARCHIVE_BYTES, "archive size")
        checks.equal(sha256_file(archive), CORE_ARCHIVE_SHA256, "archive SHA256")
        transcript.extend(
            [
                f"sha256sums_bytes={SUMS_BYTES}",
                f"sha256sums_lines={SUMS_LINES}",
                f"sha256sums_sha256={SUMS_SHA256}",
                f"core_archive={CORE_ARCHIVE}",
                f"core_archive_bytes={CORE_ARCHIVE_BYTES}",
                f"core_archive_sha256={CORE_ARCHIVE_SHA256}",
            ]
        )

        header, cases = parse_fixture(fixture)
        checks.equal(
            required(header, "corpus_state"),
            "READY",
            "fixture corpus state (the committed placeholder must fail closed)",
        )
        checks.equal(required(header, "core_release"), CORE_RELEASE, "fixture Core release")
        checks.equal(required(header, "core_archive"), CORE_ARCHIVE, "fixture Core archive")
        checks.equal(required(header, "core_archive_sha256"), CORE_ARCHIVE_SHA256, "fixture Core archive hash")
        checks.equal(required(header, "regtest_genesis_hash"), REGTEST_GENESIS, "fixture genesis")
        positive = [case for case in cases if required(case, "class") == "differential-accept"]
        negative = [case for case in cases if required(case, "class") == "differential-reject"]
        checks.equal(len(positive), 2, "two positive differential cases")
        checks.equal(len(negative), 3, "three negative Core controls")

        seed_block = fixture_bytes(header, "seed_block", checks)
        seed_coinbase = fixture_bytes(header, "seed_coinbase", checks)
        checks.equal(seed_block[80], 1, "seed block transaction count")
        checks.equal(seed_block[81:], seed_coinbase, "seed block sole transaction bytes")
        checks.equal(sha256d_display(seed_block[:80]), required(header, "seed_block_hash"), "seed block hash")
        checks.equal(sha256d_display(seed_coinbase), required(header, "seed_coinbase_txid"), "seed coinbase txid")

        with tempfile.TemporaryDirectory(prefix="qk-m16-core-") as temp_name:
            temp = Path(temp_name)
            extracted = temp / "release"
            extracted.mkdir()
            safe_extract(archive, extracted)
            bitcoind = extracted / "bitcoin-28.0" / "bin" / "bitcoind"
            cli = extracted / "bitcoin-28.0" / "bin" / "bitcoin-cli"
            checks.equal(sha256_file(bitcoind), BITCOIND_SHA256, "bitcoind SHA256")
            checks.equal(sha256_file(cli), BITCOIN_CLI_SHA256, "bitcoin-cli SHA256")
            daemon_version = first_line(bitcoind, "-version")
            cli_version = first_line(cli, "-version")
            checks.equal(daemon_version, BITCOIND_VERSION, "bitcoind version")
            checks.equal(cli_version, BITCOIN_CLI_VERSION, "bitcoin-cli version")
            transcript.extend(
                [
                    f"bitcoind_sha256={BITCOIND_SHA256}",
                    f"bitcoin_cli_sha256={BITCOIN_CLI_SHA256}",
                    f"bitcoind_version={daemon_version}",
                    f"bitcoin_cli_version={cli_version}",
                ]
            )

            datadir = temp / "node"
            datadir.mkdir()
            core = Core(bitcoind, cli, datadir, choose_port(), transcript)
            core.start()
            chain = core.rpc("getblockchaininfo")
            checks.equal(chain["chain"], "regtest", "Core chain")
            checks.equal(chain["blocks"], 0, "initial Core height")
            genesis = core.rpc("getblockhash", "0")
            checks.equal(genesis, REGTEST_GENESIS, "Core regtest genesis")
            transcript.extend(["chain=regtest", f"genesis_hash={REGTEST_GENESIS}", "height_before_seed=0"])

            submitted = core.rpc("submitblock", seed_block.hex())
            checks.equal(submitted, None, "submitblock result")
            checks.equal(core.rpc("getblockcount"), 1, "height after seed")
            checks.equal(core.rpc("getblockhash", "1"), required(header, "seed_block_hash"), "active seed block")
            transcript.extend(
                [
                    f"seed_block_hash={required(header, 'seed_block_hash')}",
                    f"seed_coinbase_txid={required(header, 'seed_coinbase_txid')}",
                    "height_after_seed=1",
                ]
            )

            generated = core.rpc("generatetodescriptor", "100", "raw(51)")
            checks.equal(len(generated), 100, "maturity block count")
            checks.equal(core.rpc("getblockcount"), 101, "height after maturity")
            utxo = core.rpc(
                "gettxout",
                required(header, "seed_coinbase_txid"),
                required(header, "seed_vout"),
                "true",
            )
            checks.that(isinstance(utxo, dict), "seed UTXO exists")
            checks.equal(utxo["confirmations"], 101, "seed UTXO confirmations")
            checks.equal(utxo["coinbase"], True, "seed UTXO coinbase flag")
            checks.equal(utxo["scriptPubKey"]["hex"], required(header, "seed_script_pubkey_hex"), "seed UTXO script")
            checks.equal(round(float(utxo["value"]) * 100_000_000), int(required(header, "seed_amount_sats")), "seed UTXO amount")
            transcript.extend(
                [
                    "maturity_blocks_generated=100",
                    "height_after_maturity=101",
                    "seed_utxo_unspent=true",
                    "seed_utxo_coinbase=true",
                    "seed_utxo_confirmations=101",
                ]
            )

            for case_index, case in enumerate(positive):
                before = checks.total
                name = required(case, "case")
                m15 = fixture_bytes(case, "m15_psbt", checks)
                finalized = fixture_bytes(case, "finalized_psbt", checks)
                raw_tx = fixture_bytes(case, "raw_tx", checks)
                stripped = fixture_bytes(case, "stripped_tx", checks)
                checks.equal(sha256d_display(stripped), required(case, "txid"), f"{name} local txid")
                checks.equal(sha256d_display(raw_tx), required(case, "wtxid"), f"{name} local wtxid")

                core_final = core.rpc("finalizepsbt", b64(m15), "false")
                checks.equal(core_final["complete"], True, f"{name} Core final complete")
                core_psbt = base64.b64decode(core_final["psbt"], validate=True)
                rule = required(case, "core_finalized_psbt_rule")
                if rule == "byte-equal":
                    checks.equal(core_psbt, finalized, f"{name} finalized PSBT byte equality")
                elif rule == "decoded-equal-order-delta":
                    checks.that(core_psbt != finalized, f"{name} expected PSBT byte order delta")
                    qk_decode = core.rpc("decodepsbt", b64(finalized))
                    core_decode = core.rpc("decodepsbt", b64(core_psbt))
                    checks.equal(qk_decode, core_decode, f"{name} decoded PSBT equivalence")
                    qk_maps = parse_psbt(finalized)
                    core_maps = parse_psbt(core_psbt)
                    checks.equal(map_multisets(qk_maps), map_multisets(core_maps), f"{name} PSBT record multisets")
                    qk_index, qk_order, qk_keys = locate_255_256_order(qk_maps)
                    core_index, core_order, core_keys = locate_255_256_order(core_maps)
                    checks.equal(core_index, qk_index, f"{name} unknown map index")
                    checks.equal(qk_order, [255, 256], f"{name} QuietKey unknown order")
                    checks.equal(core_order, [256, 255], f"{name} Core unknown order")
                    checks.equal(qk_keys, ["fdff00", "fd0001"], f"{name} QuietKey unknown full keys")
                    checks.equal(core_keys, ["fd0001", "fdff00"], f"{name} Core unknown full keys")
                else:
                    raise ValueError(f"{name}: closed finalized PSBT rule")

                extracted_result = core.rpc("finalizepsbt", b64(m15), "true")
                checks.equal(extracted_result["complete"], True, f"{name} Core extraction complete")
                checks.equal(extracted_result["hex"], raw_tx.hex(), f"{name} raw transaction bytes")
                decoded_tx = core.rpc("decoderawtransaction", raw_tx.hex())
                checks.equal(decoded_tx["txid"], required(case, "txid"), f"{name} Core txid")
                checks.equal(decoded_tx["hash"], required(case, "wtxid"), f"{name} Core wtxid")
                checks.equal(len(decoded_tx["vin"]), 1, f"{name} one input")
                expected_witness = [required(case, f"witness_{i}_hex") for i in range(4)]
                checks.equal(decoded_tx["vin"][0]["txinwitness"], expected_witness, f"{name} exact witness")
                checks.equal(decoded_tx["vin"][0]["scriptSig"]["hex"], "", f"{name} empty scriptSig")
                acceptance = core.rpc("testmempoolaccept", compact_json([raw_tx.hex()]), "0")
                checks.equal(len(acceptance), 1, f"{name} one acceptance result")
                result = acceptance[0]
                checks.equal(result.get("allowed"), True, f"{name} allowed")
                checks.equal(result["txid"], required(case, "txid"), f"{name} accepted txid")
                checks.equal(result["wtxid"], required(case, "wtxid"), f"{name} accepted wtxid")
                checks.that(result.get("vsize", 0) > 0, f"{name} positive vsize")
                checks.that("reject-reason" not in result, f"{name} no reject reason")
                checks.that("package-error" not in result, f"{name} no package error")
                prefix = f"case_{case_index:03d}"
                transcript.extend(
                    [
                        f"{prefix}_name={name}",
                        f"{prefix}_core_complete=true",
                        f"{prefix}_core_psbt_rule={rule}",
                        f"{prefix}_raw_tx_equal=true",
                        f"{prefix}_txid={required(case, 'txid')}",
                        f"{prefix}_wtxid={required(case, 'wtxid')}",
                        f"{prefix}_testmempoolaccept_allowed=true",
                        f"{prefix}_assertions={checks.total - before}",
                        f"{prefix}_failures=0",
                    ]
                )
                if rule == "byte-equal":
                    transcript.append(f"{prefix}_core_psbt_equal=true")
                else:
                    transcript.extend(
                        [
                            f"{prefix}_core_psbt_equal=false",
                            f"{prefix}_decoded_equal=true",
                            f"{prefix}_record_multisets_equal=true",
                            f"{prefix}_quietkey_unknown_type_order=255,256",
                            f"{prefix}_core_unknown_type_order=256,255",
                            f"{prefix}_order_only_delta=true",
                        ]
                    )

            for offset, case in enumerate(negative):
                before = checks.total
                name = required(case, "case")
                raw_tx = fixture_bytes(case, "raw_tx", checks)
                checks.equal(sha256d_display(raw_tx), required(case, "wtxid"), f"{name} local wtxid")
                rejection = core.rpc("testmempoolaccept", compact_json([raw_tx.hex()]), "0")
                checks.equal(len(rejection), 1, f"{name} one rejection result")
                result = rejection[0]
                checks.equal(result.get("allowed"), False, f"{name} rejected")
                checks.equal(result["txid"], required(case, "txid"), f"{name} rejected txid")
                checks.equal(result["wtxid"], required(case, "wtxid"), f"{name} rejected wtxid")
                checks.that(bool(result.get("reject-reason")), f"{name} nonempty reject reason")
                prefix = f"case_{len(positive) + offset:03d}"
                transcript.extend(
                    [
                        f"{prefix}_name={name}",
                        f"{prefix}_mutation={required(case, 'mutation')}",
                        f"{prefix}_testmempoolaccept_allowed=false",
                        f"{prefix}_reject_reason={compact_json(result['reject-reason'])}",
                        f"{prefix}_assertions={checks.total - before}",
                        f"{prefix}_failures=0",
                    ]
                )

            stop_code = core.stop()
            transcript.extend(["daemon_stop_requested=true", f"daemon_exit_code={stop_code}"])
            checks.equal(stop_code, 0, "bitcoind clean exit")
            transcript.extend(
                [
                    f"positive_cases={len(positive)}",
                    f"negative_core_controls={len(negative)}",
                    f"rpc_calls={core.rpc_index}",
                    f"assertions_total={checks.total}",
                    "assertions_failed=0",
                    "result=PASS",
                ]
            )
            core = None
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        transcript.extend([f"failure={compact_json(error)}", f"assertions_total={checks.total}", "assertions_failed=1", "result=FAIL"])
    finally:
        if core is not None:
            try:
                code = core.stop()
                transcript.extend(["daemon_stop_requested=true", f"daemon_exit_code={code}"])
            except Exception as stop_exc:
                transcript.append(f"daemon_stop_error={compact_json(str(stop_exc))}")
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        with transcript_path.open("x", encoding="ascii", newline="\n") as out:
            out.write("\n".join(transcript) + "\n")

    if error is not None:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
