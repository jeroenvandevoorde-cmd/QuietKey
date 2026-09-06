"""QK-DEC-162 pure math vectors; no proprietary API, converter, or native card execution.

PERMANENTLY NEVER-FUND TEST MATERIAL. QK_APPLET_TEST_JAVA_HOME may select a local
JDK for ordinary JVM vectors. If none works, PureJvmVectorsPending is an explicit
skip; source/constants checks still run and no runtime success is reported.
"""

import hashlib
import hmac
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


BASE = Path(__file__).resolve().parents[1]
REPO = BASE.parents[1]
JAVA = BASE / "src" / "org" / "quietkey" / "cardb"
MODEL = REPO / "host" / "qk-card-model" / "src"
HARNESS = BASE / "tests" / "VectorHarness.java"
PURE = ("Sha512.java", "HmacSha512.java", "Scalar256.java", "Wipe.java")


def java_bytes(source, name):
    match = re.search(r"byte\[\]\s+" + name + r"\s*=\s*\{(.*?)\};", source, re.S)
    if match is None:
        raise AssertionError("MissingJavaConstant:" + name)
    return bytes(int(value, 16) for value in re.findall(r"0x([0-9a-fA-F]{2})\b", match[1]))


def rust_words(source, name):
    match = re.search(r"const\s+" + name + r":\s*\[u64;\s*\d+\]\s*=\s*\[(.*?)\];", source, re.S)
    if match is None:
        raise AssertionError("MissingRegisteredConstant:" + name)
    return b"".join(int(value.replace("_", ""), 16).to_bytes(8, "big")
                    for value in re.findall(r"0x([0-9a-f_]+)", match[1]))


def harness_hex(name):
    source = HARNESS.read_text(encoding="utf-8")
    match = re.search(r"String\s+" + name + r"\s*=\s*(.*?);", source, re.S)
    if match is None:
        raise AssertionError("MissingHarnessVector:" + name)
    return bytes.fromhex("".join(re.findall(r'"([0-9a-f]+)"', match[1])))


def registered_test_output(path):
    source = path.read_text(encoding="utf-8")
    match = re.search(r"assert_eq!\(\s*output,\s*\[(.*?)\]\s*\)", source, re.S)
    if match is None:
        raise AssertionError("MissingRegisteredKnownAnswer:" + path.name)
    return bytes(int(value, 16) for value in re.findall(r"0x([0-9a-f]{2})\b", match[1]))


class SourceVectorTests(unittest.TestCase):
    def test_sha512_round_and_initial_bytes_match_registered_model(self):
        java = (JAVA / "Sha512.java").read_text(encoding="utf-8")
        rust = (MODEL / "sha512.rs").read_text(encoding="utf-8")
        self.assertEqual(java_bytes(java, "INITIAL"), rust_words(rust, "INITIAL"))
        self.assertEqual(java_bytes(java, "K"), rust_words(rust, "K"))
        self.assertEqual(len(java_bytes(java, "INITIAL")), 64)
        self.assertEqual(len(java_bytes(java, "K")), 640)

    def test_scalar_order_matches_registered_model(self):
        java = (JAVA / "Scalar256.java").read_text(encoding="utf-8")
        rust = (MODEL / "scalar.rs").read_text(encoding="utf-8")
        match = re.search(r"const ORDER: \[u8; 32\] = \[(.*?)\];", rust, re.S)
        expected = bytes(int(value, 16) for value in re.findall(r"0x([0-9a-f]{2})\b", match[1]))
        self.assertEqual(java_bytes(java, "ORDER"), expected)
        self.assertEqual(len(expected), 32)

    def test_frozen_abc_vector_has_model_and_python_ties(self):
        expected = registered_test_output(MODEL / "sha512.rs")
        self.assertEqual(harness_hex("ABC_SHA512"), expected)
        self.assertEqual(expected, hashlib.sha512(b"abc").digest())

    def test_frozen_ckd_hmac_vector_has_model_and_python_ties(self):
        expected = registered_test_output(MODEL / "hmac_sha512.rs")
        self.assertEqual(harness_hex("BIP32_HMAC"), expected)
        self.assertEqual(expected, hmac.new(bytes(range(32)), bytes(range(37)), "sha512").digest())

    def test_pure_helpers_have_no_optional_integer_or_platform_dependency(self):
        for filename in PURE:
            source = (JAVA / filename).read_text(encoding="utf-8")
            source = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)
            with self.subTest(source=filename):
                self.assertNotRegex(source, r"\b(?:int|long|float|double)\b")
                self.assertNotRegex(source, r"\bimport\b")
                self.assertNotIn("NativeSecp256k1", source)

    def test_vector_harness_excludes_applet_and_native_curve_execution(self):
        source = HARNESS.read_text(encoding="utf-8")
        self.assertIn("PERMANENTLY NEVER-FUND TEST MATERIAL", source)
        self.assertNotRegex(source, r"\b(?:javacard|javacardx)\s*\.")
        self.assertNotIn("NativeSecp256k1", source)
        self.assertNotIn("KeyCardBApplet", source)
        self.assertIn("new Random(123456)", source)

    def test_native_boundary_declares_exact_digest_and_finally_cleanup(self):
        source = (JAVA / "NativeSecp256k1.java").read_text(encoding="utf-8")
        self.assertIn("KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY", source)
        self.assertIn("KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT", source)
        self.assertIn("signer.signPreComputedHash(digest, digestOffset, (short) 32", source)
        self.assertNotIn("signer.sign(", source)
        self.assertNotIn("signer.update(", source)
        self.assertIn("key.clearKey()", source)
        self.assertIn("Wipe.clear(point)", source)


class PureJvmVectorTests(unittest.TestCase):
    def tools(self):
        selected = os.environ.get("QK_APPLET_TEST_JAVA_HOME")
        if selected:
            home = Path(selected)
            if not home.is_absolute():
                self.fail("PureJvmToolRejected: selected JDK path is not absolute")
            java = home / "bin" / "java"
            javac = home / "bin" / "javac"
            if not all(path.is_file() and os.access(path, os.X_OK) for path in (java, javac)):
                self.fail("PureJvmToolRejected: selected JDK lacks java or javac")
        else:
            java = shutil.which("java")
            javac = shutil.which("javac")
            if not java or not javac:
                self.skipTest("PureJvmVectorsPending: working java and javac are unavailable")
        environment = dict(os.environ)
        for name in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH"):
            environment.pop(name, None)
        for executable in (java, javac):
            try:
                result = subprocess.run([str(executable), "-version"], env=environment,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            except (OSError, subprocess.TimeoutExpired):
                if selected:
                    self.fail("PureJvmToolRejected: selected JDK cannot execute")
                self.skipTest("PureJvmVectorsPending: working java and javac are unavailable")
            if result.returncode != 0:
                if selected:
                    self.fail("PureJvmToolRejected: selected JDK version check failed")
                self.skipTest("PureJvmVectorsPending: working java and javac are unavailable")
        return str(java), str(javac), environment

    def test_registered_vectors_and_reference_comparisons(self):
        java, javac, environment = self.tools()
        with tempfile.TemporaryDirectory(prefix="qk-pure-vectors-") as directory:
            command = [javac, "-source", "1.8", "-target", "1.8", "-proc:none",
                       "-implicit:none", "-encoding", "UTF-8", "-g:none", "-d", directory]
            command += [str(JAVA / name) for name in PURE] + [str(HARNESS)]
            compiled = subprocess.run(command, env=environment, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, timeout=90, text=True)
            self.assertEqual(compiled.returncode, 0, "PureJvmCompilationFailed:\n" + compiled.stderr)
            executed = subprocess.run([java, "-cp", directory, "org.quietkey.cardb.VectorHarness"],
                                      env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      timeout=90, text=True)
            self.assertEqual(executed.returncode, 0, "PureJvmVectorsFailed:\n" + executed.stderr)
            self.assertEqual(executed.stderr, "")
            self.assertEqual(executed.stdout, "QK-PURE-VECTORS PASS assertions=6266\n")


if __name__ == "__main__":
    unittest.main()
