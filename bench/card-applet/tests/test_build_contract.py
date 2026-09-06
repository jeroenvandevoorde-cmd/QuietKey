"""Pure QK-DEC-162 build checks. No compiler, converter or card is invoked."""

import binascii
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest import mock
import zipfile


BASE = Path(__file__).resolve().parents[1]
REPO = BASE.parents[1]
SPEC = importlib.util.spec_from_file_location("qk_canonical_cap", BASE / "canonical-cap.py")
CAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAP)


def minimal():
    return {name: bytes([n + 1]) for n, name in enumerate(CAP.COMPONENTS[:3])}


def raw_zip(files=None, compression=zipfile.ZIP_STORED, entries=None):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=compression) as archive:
        for name, body in entries if entries is not None else (files or minimal()).items():
            archive.writestr(name, body)
    return out.getvalue()


def patch(body, offset, fmt, value):
    result = bytearray(body)
    struct.pack_into(fmt, result, offset, value)
    return bytes(result)


class Utf8Info(zipfile.ZipInfo):
    def _encodeFilenameFlags(self):
        return self.filename.encode("utf-8"), 0x800


def second_canonical(files):
    out = io.BytesIO()
    values = dict(files)
    values[CAP.MANIFEST] = CAP.MANIFEST_BODY
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, value in sorted(values.items()):
            info = Utf8Info(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.create_version = 20
            info.extract_version = 20
            info.external_attr = 0x81a40000
            info.internal_attr = 0
            info.compress_type = 0
            archive.writestr(info, value)
    return out.getvalue()


class PackagingTests(unittest.TestCase):
    def reject(self, name, body, **kwargs):
        with self.assertRaisesRegex(CAP.Rejection, "^" + name + "$"):
            CAP.parse_raw(body, **kwargs)

    def test_reference_constructor_byte_equality(self):
        files = minimal()
        files[CAP.SIDECARS[1]] = b"<opaque timestamp='unchanged'/>"
        self.assertEqual(CAP.canonicalize(raw_zip(files))[0], second_canonical(files))

    def test_raw_timestamps_order_compression_do_not_change_canonical(self):
        one = raw_zip(minimal())
        two = raw_zip(dict(reversed(list(minimal().items()))), zipfile.ZIP_DEFLATED)
        self.assertNotEqual(one, two)
        self.assertEqual(CAP.canonicalize(one)[0], CAP.canonicalize(two)[0])

    def test_manifest_regenerated_only(self):
        files = minimal()
        files[CAP.MANIFEST] = b"nondeterministic raw manifest"
        files[CAP.SIDECARS[1]] = b"<exact/>"
        files[CAP.SIDECARS[2]] = b"<also-exact/>"
        canonical, facts = CAP.canonicalize(raw_zip(files))
        parsed = CAP.parse_raw(canonical)
        self.assertEqual(parsed[CAP.MANIFEST], CAP.MANIFEST_BODY)
        self.assertEqual(parsed[CAP.SIDECARS[1]], b"<exact/>")
        self.assertEqual(parsed[CAP.SIDECARS[2]], b"<also-exact/>")
        for entry in facts:
            value = parsed[entry["name"]]
            self.assertEqual(entry["bytes"], len(value))
            self.assertEqual(entry["crc32"], "%08x" % (binascii.crc32(value) & 0xffffffff))
            self.assertEqual(entry["sha256"], CAP.sha(value))

    def test_canonical_headers_are_fully_fixed(self):
        value, _ = CAP.canonicalize(raw_zip())
        with zipfile.ZipFile(io.BytesIO(value)) as archive:
            names = archive.namelist()
            self.assertEqual(names, sorted(names))
            for item in archive.infolist():
                self.assertEqual(item.flag_bits, 0x800)
                self.assertEqual(item.compress_type, 0)
                self.assertEqual(item.create_system, 3)
                self.assertEqual(item.create_version, 20)
                self.assertEqual(item.extract_version, 20)
                self.assertEqual(item.external_attr, 0x81a40000)
                self.assertEqual(item.internal_attr, 0)
                self.assertEqual(item.extra, b"")
                self.assertEqual(item.comment, b"")
                self.assertEqual(item.date_time, (1980, 1, 1, 0, 0, 0))
            self.assertEqual(archive.comment, b"")
        self.assertEqual(CAP.canonicalize(value)[0], value)

    def test_empty_ancestor_directories_omitted(self):
        entries = [(name, b"") for name in sorted(CAP.DIRECTORIES)] + list(minimal().items())
        self.assertEqual(CAP.canonicalize(raw_zip(entries=entries))[0], second_canonical(minimal()))

    def test_directory_must_be_empty(self):
        files = minimal()
        files["META-INF/"] = b"x"
        self.reject("ArchiveDirectoryRejected", raw_zip(files))

    def test_extra_directory_rejected(self):
        files = minimal()
        files["elsewhere/"] = b""
        self.reject("ArchivePathRejected", raw_zip(files))

    def test_all_components_preserved(self):
        files = {name: bytes([n]) * 32 for n, name in enumerate(CAP.COMPONENTS)}
        self.assertEqual({k: v for k, v in CAP.parse_raw(CAP.canonicalize(raw_zip(files))[0]).items()
                          if k in CAP.COMPONENTS}, files)

    def test_each_mandatory_component_required(self):
        for name in CAP.REQUIRED:
            with self.subTest(name=name):
                files = minimal()
                del files[name]
                self.reject("MissingCapComponent", raw_zip(files))

    def test_class_sidecars_require_exact_compiled_body(self):
        files = minimal()
        files[CAP.CLASSES[0]] = b"compiled bytes"
        raw = raw_zip(files)
        self.reject("ClassMismatch", raw)
        self.reject("ClassMismatch", raw, class_bodies={CAP.CLASSES[0]: b"other bytes"})
        canonical, _ = CAP.canonicalize(raw, {CAP.CLASSES[0]: b"compiled bytes"})
        self.assertEqual(CAP.parse_raw(canonical, {CAP.CLASSES[0]: b"compiled bytes"})[CAP.CLASSES[0]],
                         b"compiled bytes")

    def test_inner_and_unknown_class_rejected(self):
        for name in (CAP.CLASS_ROOT + "KeyCardBApplet$Inner.class", CAP.CLASS_ROOT + "Extra.class"):
            with self.subTest(name=name):
                files = minimal()
                files[name] = b"x"
                self.reject("ArchivePathRejected", raw_zip(files))

    def test_alternate_traversal_and_non_utf8_names_rejected(self):
        for name in ("../Header.cap", "/org/quietkey/cardb/javacard/Header.cap",
                     "org\\quietkey\\cardb\\javacard\\Header.cap", "META-INF/mAnIfEsT.mf", "é.cap"):
            with self.subTest(name=name):
                files = minimal()
                files[name] = b"x"
                self.reject("ArchivePathRejected", raw_zip(files))

    def test_duplicate_entry_rejected(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            raw = raw_zip(entries=list(minimal().items()) * 2)
        self.reject("DuplicateArchiveEntry", raw)

    def test_symlink_and_special_files_rejected(self):
        for kind in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK):
            with self.subTest(kind=kind):
                out = io.BytesIO()
                with zipfile.ZipFile(out, "w") as archive:
                    for name, body in minimal().items():
                        item = zipfile.ZipInfo(name)
                        item.create_system = 3
                        item.external_attr = (kind | 0o600) << 16
                        archive.writestr(item, body)
                self.reject("ArchiveSpecialFileRejected", out.getvalue())

    def test_encryption_is_distinct(self):
        value = raw_zip()
        central = value.index(b"PK\x01\x02")
        self.reject("EncryptionRejected", patch(value, central + 8, "<H", 1))

    def test_unknown_zip_flags(self):
        value = raw_zip()
        central = value.index(b"PK\x01\x02")
        self.reject("UnsupportedZipFlags", patch(value, central + 8, "<H", 16))

    def test_unknown_compression(self):
        value = raw_zip()
        central = value.index(b"PK\x01\x02")
        self.reject("CompressionRejected", patch(value, central + 10, "<H", 12))

    def test_zip64_rejected(self):
        value = raw_zip()
        self.reject("Zip64Rejected", patch(value, len(value) - 10, "<I", 0xffffffff))

    def test_zip64_extra_rejected(self):
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as archive:
            for name, body in minimal().items():
                info = zipfile.ZipInfo(name)
                info.extra = struct.pack("<HH", 1, 0)
                archive.writestr(info, body)
        self.reject("Zip64Rejected", out.getvalue())

    def test_multidisk_rejected(self):
        value = raw_zip()
        self.reject("MultiDiskRejected", patch(value, len(value) - 18, "<H", 1))

    def test_trailing_data(self):
        self.reject("TrailingData", raw_zip() + b"x")

    def test_local_central_mismatch(self):
        self.reject("ArchiveHeaderMismatch", patch(raw_zip(), 8, "<H", 8))

    def test_crc_mismatch(self):
        value = raw_zip()
        first = 30 + len(CAP.COMPONENTS[0])
        self.reject("ArchiveCrcMismatch", value[:first] + b"z" + value[first + 1:])

    def test_padding_before_local_header(self):
        value = raw_zip()
        central = value.index(b"PK\x01\x02")
        self.reject("ArchiveOverlapOrPadding", patch(value, central + 42, "<I", 1))

    def test_archive_bounds(self):
        self.reject("ArchiveOverLimit", b"x" * (CAP.MAX_RAW + 1))
        value = raw_zip()
        value = patch(value, len(value) - 14, "<H", 65)
        self.reject("ArchiveOverLimit", patch(value, len(value) - 12, "<H", 65))

    def test_per_file_bound_precedes_decompression(self):
        value = raw_zip()
        central = value.index(b"PK\x01\x02")
        self.reject("ArchiveOverLimit", patch(value, central + 24, "<I", CAP.MAX_FILE + 1))

    def test_raw_bound_does_not_impose_unratified_stored_output_bound(self):
        files = minimal()
        for name in CAP.COMPONENTS[3:6]:
            files[name] = b"x" * 900000
        raw = raw_zip(files, zipfile.ZIP_DEFLATED)
        self.assertLess(len(raw), CAP.MAX_RAW)
        canonical, _ = CAP.canonicalize(raw)
        self.assertGreater(len(canonical), CAP.MAX_RAW)
        self.assertEqual(CAP.parse_raw(canonical, canonical_input=True)[CAP.COMPONENTS[3]],
                         b"x" * 900000)

    def test_decompression_excess_bounded(self):
        packed = __import__("zlib").compress(b"x" * 1000)[2:-4]
        with self.assertRaisesRegex(CAP.Rejection, "^DecompressionExcess$"):
            CAP.decompress(packed, 8, 1)

    def test_deflate_garbage_and_trailing_stream_rejected(self):
        for value in (b"not deflate", __import__("zlib").compress(b"x")[2:-4] + b"x"):
            with self.subTest(value=value), self.assertRaises(CAP.Rejection):
                CAP.decompress(value, 8, 1)

    def test_valid_data_descriptors(self):
        class NonSeekable(io.BytesIO):
            def seekable(self):
                return False

            def seek(self, *args):
                raise io.UnsupportedOperation()
        out = NonSeekable()
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, body in minimal().items():
                archive.writestr(name, body)
        self.assertEqual(CAP.parse_raw(out.getvalue()), minimal())

    def test_truncations_reject_by_name(self):
        value = raw_zip()
        for count in range(len(value)):
            with self.subTest(count=count), self.assertRaises(CAP.Rejection):
                CAP.parse_raw(value[:count])


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="qk-cap-contract-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.base = self.root / "bench/card-applet"
        self.base.mkdir(parents=True)
        (self.root / "tools").mkdir()
        for name in ("build.xml", "build.sh", "DEPENDENCY-ALLOWLIST.tsv"):
            shutil.copyfile(BASE / name, self.base / name)
        shutil.copyfile(REPO / "tools/check-card-applet.sh", self.root / "tools/check-card-applet.sh")
        allow = self.base / "DEPENDENCY-ALLOWLIST.tsv"
        if "\napi\t" not in allow.read_text():
            with allow.open("a") as output:
                output.write("api\tJava Card Classic API\t3.0.5\t" + CAP.API_SHA
                    + "\tregistered DevKit lib/api_classic-3.0.5.jar (56791 bytes)"
                    + "\tOracle Technology Network Developer License Agreement for Oracle Java"
                    + "\tsole compile API\n")
        self.source = self.base / "src/org/quietkey/cardb"
        self.source.mkdir(parents=True)
        for name in CAP.SOURCES:
            (self.source / (name + ".java")).write_text("package org.quietkey.cardb;\n")

    def reject(self, name):
        with self.assertRaisesRegex(CAP.Rejection, "^" + name + "$"):
            CAP.check_repository(self.root, check_closures=False)

    def test_clean_clone_guard_needs_no_tools(self):
        self.assertEqual(CAP.check_repository(self.root, False),
                         {"allowlist_rows": 24, "source_files": 9, "result": "PASS"})

    def test_guard_every_cap_attribute_is_closed(self):
        path = self.base / "build.xml"
        original = path.read_text()
        for name, value in CAP.CAP_ATTRIBUTES.items():
            with self.subTest(name=name):
                path.write_text(original.replace(name + '="' + value + '"', name + '="wrong"'))
                self.reject("BuildDeclarationMismatch")
        path.write_text(original)

    def test_guard_extra_task_and_sources_rejected(self):
        path = self.base / "build.xml"
        original = path.read_text()
        for extra in ('<exec executable="unexpected"/>', '<sources path="extra"/>',
                      '<import file="other.xml"/>'):
            with self.subTest(extra=extra):
                path.write_text(original.replace("</target>", extra + "</target>"))
                self.reject("BuildDeclarationMismatch")

    def test_guard_external_xml_entity_rejected(self):
        path = self.base / "build.xml"
        path.write_text('<!DOCTYPE project SYSTEM "file:///etc/passwd">\n<project/>')
        self.reject("BuildDeclarationMismatch")

    def test_guard_only_nine_source_files(self):
        (self.source / "Extra.java").write_text("class Extra {}")
        self.reject("UnexpectedSource")

    def test_guard_missing_source(self):
        (self.source / "Wipe.java").unlink()
        self.reject("UnexpectedSource")

    def test_guard_vendored_artifact(self):
        for suffix in (".jar", ".CAP", ".class", ".exp", ".zip", ".gz", ".so"):
            with self.subTest(suffix=suffix):
                path = self.base / ("bad" + suffix)
                path.write_bytes(b"fixture")
                self.reject("VendoredToolRejected")
                path.unlink()

    def test_guard_alternate_build_system(self):
        (self.base / "pom.xml").write_text("<project/>")
        self.reject("UndeclaredBuildInput")

    def test_guard_symlink(self):
        (self.base / "alias").symlink_to(self.source, target_is_directory=True)
        self.reject("PathRejected")

    def test_guard_wrapper_cannot_smuggle_options(self):
        path = self.base / "build.sh"
        path.write_text(path.read_text() + "JAVA_TOOL_OPTIONS=-javaagent:evil.jar\n")
        self.reject("BuildWrapperMismatch")

    def test_guard_allowlist_hash_and_license(self):
        path = self.base / "DEPENDENCY-ALLOWLIST.tsv"
        original = path.read_text()
        for old, new in ((CAP.TOOLS["jdk"][2], "0" * 64), ("Apache-2.0", "Unknown"),
                         ("candidate applet build driver", "unreviewed build driver")):
            with self.subTest(old=old):
                path.write_text(original.replace(old, new, 1))
                self.reject("DependencyAllowlistMismatch")

    def test_guard_allowlist_extra_and_duplicate(self):
        path = self.base / "DEPENDENCY-ALLOWLIST.tsv"
        path.write_text(path.read_text() + "api\tother\t1\t" + "0" * 64 + "\tx\ty\tz\n")
        self.reject("DependencyAllowlistMismatch")

    def test_guard_closure_metadata_failure(self):
        with mock.patch.object(CAP.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"")):
            with self.assertRaisesRegex(CAP.Rejection, "^ClosureInspectionFailed$"):
                CAP.check_repository(self.root)

    def test_guard_closure_rejects_direct_and_transitive_paths(self):
        for field in ("manifest_path", "dependency"):
            package = {"manifest_path": str(self.root / "host/qk-core/Cargo.toml"), "dependencies": []}
            if field == "manifest_path":
                package[field] = str(self.base / "foreign/Cargo.toml")
            else:
                package["dependencies"] = [{"path": str(self.base)}]
            value = {"resolve": {}, "packages": [package]}
            result = subprocess.CompletedProcess([], 0, json.dumps(value).encode(), b"")
            with self.subTest(field=field), mock.patch.object(CAP.subprocess, "run", return_value=result):
                with self.assertRaisesRegex(CAP.Rejection, "^AppletClosureViolation$"):
                    CAP.check_repository(self.root)

    def test_guard_checks_all_three_closure_graphs(self):
        value = {"resolve": {}, "packages": []}
        result = subprocess.CompletedProcess([], 0, json.dumps(value).encode(), b"")
        with mock.patch.object(CAP.subprocess, "run", return_value=result) as run:
            CAP.check_repository(self.root)
        self.assertEqual(run.call_count, 3)
        for call in run.call_args_list:
            self.assertIn("--all-features", call.args[0])
            self.assertIn("--offline", call.args[0])
            self.assertIn("--locked", call.args[0])


class RecipeTests(unittest.TestCase):
    def test_compile_and_ant_commands_exact(self):
        jdk, ant, devkit, task, src, classes, tmp, raw = map(Path, (
            "/jdk", "/ant", "/devkit", "/task.jar", "/src", "/out/classes", "/out/tmp", "/out/raw.cap"))
        javac, convert, env = CAP.build_commands(jdk, ant, devkit, task, src, classes, tmp, raw)
        self.assertEqual(javac[:16], ["/jdk/bin/javac", "-source", "1.8", "-target", "1.8",
            "-bootclasspath", "/devkit/lib/api_classic-3.0.5.jar", "-classpath",
            "/devkit/lib/api_classic-3.0.5.jar", "-proc:none", "-implicit:none", "-encoding",
            "UTF-8", "-g:none", "-d", "/out/classes"])
        self.assertEqual(javac[16:], ["/src/bench/card-applet/src/org/quietkey/cardb/" + name + ".java"
                                     for name in CAP.SOURCES])
        self.assertEqual(convert, ["/jdk/bin/java", "-Dant.home=/ant", "-Dfile.encoding=UTF-8",
            "-Duser.language=en", "-Duser.country=US", "-Duser.timezone=UTC", "-Djava.io.tmpdir=/out/tmp",
            "-classpath", "/ant/lib/ant-launcher.jar", "org.apache.tools.ant.launch.Launcher",
            "-nouserlib", "-noclasspath", "-verbose", "-f", "/src/bench/card-applet/build.xml",
            "-Dqk.devkit=/devkit", "-Dqk.classes=/out/classes", "-Dqk.raw.cap=/out/raw.cap",
            "-Dqk.task.jar=/task.jar", "convert"])
        self.assertEqual(env, {"JAVA_HOME": "/jdk", "PATH": "/jdk/bin:/usr/bin:/bin",
            "LC_ALL": "C", "LANG": "C", "TZ": "UTC", "_ANT_JAVACARD_LOGHACK": "false"})

    def test_production_seam_rejects_before_inputs(self):
        with self.assertRaisesRegex(CAP.Rejection, "^ProductionTestIdentifiersRejected$"):
            CAP.build(["production"] + ["unopened"] * 9)

    def test_converter_log_exact_command(self):
        jdk, devkit, classes, tmp = map(Path, ("/jdk", "/kit", "/classes", "/private/tmp"))
        expected = CAP.converter_command(jdk, devkit, classes, tmp / "converter")
        log = "[convert] Executing '/jdk/bin/java' with arguments:\n" + "\n".join(
            "[convert] '" + value + "'" for value in expected[1:]) + "\n[convert] end\n"
        self.assertEqual(CAP.parse_converter_log(log, jdk, devkit, classes, tmp), expected)
        for old, new in (("3.0.5", "3.0.4"), ("-nobanner", "-noverify"),
                         ("/private/tmp/converter", "/other/converter")):
            with self.subTest(old=old), self.assertRaises(CAP.Rejection):
                CAP.parse_converter_log(log.replace(old, new), jdk, devkit, classes, tmp)

    def test_converter_verification_line_required_exactly_once(self):
        command = CAP.converter_command(Path("/jdk"), Path("/kit"), Path("/classes"), Path("/tmp/converter"))
        message = "[verify] Verification of /tmp/converter/org/quietkey/cardb/javacard/cardb.cap passed\n"
        CAP.verify_converter_log(message, command)
        for text in ("", message + message, message.replace("passed", "failed")):
            with self.subTest(text=text), self.assertRaisesRegex(CAP.Rejection, "^VerificationFailed$"):
                CAP.verify_converter_log(text, command)

    def test_tool_identity_mismatch_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp).resolve() / CAP.TOOLS["task"][0]
            file.write_bytes(b"not the registered jar")
            with self.assertRaisesRegex(CAP.Rejection, "^ToolIdentityMismatch$"):
                CAP.verify_tool("task", str(file))

    def test_class_set_and_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            sub = root / "org/quietkey/cardb"
            sub.mkdir(parents=True)
            for name in CAP.SOURCES:
                (sub / (name + ".class")).write_bytes(b"\xca\xfe\xba\xbe\0\0\0\x34")
            self.assertEqual(len(CAP.load_classes(root)), 9)
            (sub / "Wipe.class").write_bytes(b"\xca\xfe\xba\xbe\0\0\0\x35")
            with self.assertRaisesRegex(CAP.Rejection, "^UnexpectedClassVersion$"):
                CAP.load_classes(root)

    def test_existing_output_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / "existing"
            path.write_bytes(b"unchanged")
            with self.assertRaisesRegex(CAP.Rejection, "^OutputAlreadyExists$"):
                CAP.absolute_path(str(path), absent=True)
            self.assertEqual(path.read_bytes(), b"unchanged")

    def test_paths_cannot_add_classpath_entries_or_log_arguments(self):
        for value in ("/private/kit:other", "/private/kit'quote", "/private/line\nbreak"):
            with self.subTest(value=value), self.assertRaisesRegex(CAP.Rejection, "^PathRejected$"):
                CAP.absolute_path(value)

    def test_extracted_files_must_match_archive_without_extras(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            archive, home = root / "kit.zip", root / "kit"
            home.mkdir()
            (home / "lib").mkdir()
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("lib/api.jar", b"public test bytes")
            (home / "lib/api.jar").write_bytes(b"public test bytes")
            records = CAP.verify_extracted(archive, home, "devkit")
            self.assertEqual(records, [{"path": str(home / "lib/api.jar"),
                                       **CAP.identity(b"public test bytes")}])
            (home / "lib/extra.jar").write_bytes(b"unregistered")
            with self.assertRaisesRegex(CAP.Rejection, "^ToolIdentityMismatch$"):
                CAP.verify_extracted(archive, home, "devkit")
            (home / "lib/extra.jar").unlink()
            (home / "lib/api.jar").write_bytes(b"changed")
            with self.assertRaisesRegex(CAP.Rejection, "^ToolIdentityMismatch$"):
                CAP.verify_extracted(archive, home, "devkit")

    def test_jdk_archive_home_is_tied_to_member_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            archive, home = root / "jdk.tar.gz", root / "jdk/Contents/Home"
            (home / "bin").mkdir(parents=True)
            with tarfile.open(archive, "w:gz") as output:
                item = tarfile.TarInfo("jdk/Contents/Home/bin/java")
                item.size = 6
                output.addfile(item, io.BytesIO(b"public"))
            (home / "bin/java").write_bytes(b"public")
            self.assertEqual(CAP.verify_extracted(archive, home, "jdk")[0]["sha256"], CAP.sha(b"public"))

    def test_failed_build_retains_named_result_and_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source, output = root / "source", root / "new-build"
            source.mkdir()
            commit = "1" * 40
            status = subprocess.CompletedProcess([], 0, b"", b"")
            head = subprocess.CompletedProcess([], 0, (commit + "\n").encode(), b"")
            with mock.patch.object(CAP.subprocess, "run", side_effect=[status, head]), \
                    mock.patch.object(CAP, "check_repository"), \
                    mock.patch.object(CAP, "verify_tool", side_effect=CAP.Rejection("ToolIdentityMismatch")):
                with self.assertRaisesRegex(CAP.Rejection, "^ToolIdentityMismatch$"):
                    CAP.build(["test", str(source), commit] + ["/unopened"] * 6 + [str(output)])
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertTrue((output / "attempt.json").is_file())
            result = json.loads((output / "build-result.json").read_text())
            self.assertEqual(result["result"], "FAIL")
            self.assertEqual(result["rejection"], "ToolIdentityMismatch")
            self.assertFalse((output / "canonical.cap").exists())

    def test_failed_subprocess_preserves_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            output = root / "failed.log"
            command = [sys.executable, "-I", "-c", "print('public failure evidence'); raise SystemExit(3)"]
            with self.assertRaisesRegex(CAP.Rejection, "^CompilationFailed$"):
                CAP.execute_logged(command, {"LANG": "C"}, root, output, "CompilationFailed")
            self.assertEqual(output.read_bytes(), b"public failure evidence\n")

    def test_missing_python_is_named(self):
        with tempfile.TemporaryDirectory() as tmp:
            for script in (BASE / "build.sh", REPO / "tools/check-card-applet.sh"):
                result = subprocess.run(["/bin/sh", str(script)], env={"PATH": tmp}, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr, b"QK-CARD-APPLET FAIL Python3Unavailable\n")

    def test_canonical_cli_does_not_execute_java(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            classes = root / "classes"
            sub = classes / "org/quietkey/cardb"
            sub.mkdir(parents=True)
            for name in CAP.SOURCES:
                (sub / (name + ".class")).write_bytes(b"\xca\xfe\xba\xbe\0\0\0\x34")
            raw, output = root / "raw.cap", root / "canonical.cap"
            raw.write_bytes(raw_zip())
            result = CAP.main(["canonicalize", "test", str(raw), str(classes), str(output)])
            self.assertEqual(result["canonical"]["sha256"], CAP.sha(output.read_bytes()))
            self.assertEqual(CAP.main(["compare", str(output), str(output)])["result"], "PASS")

    def test_compare_rejects_different_or_noncanonical_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            one, two = Path(tmp).resolve() / "one", Path(tmp).resolve() / "two"
            one.write_bytes(raw_zip())
            two.write_bytes(raw_zip() + b"x")
            with self.assertRaisesRegex(CAP.Rejection, "^NonreproducibleCanonicalOutput$"):
                CAP.main(["compare", str(one), str(two)])
            with self.assertRaisesRegex(CAP.Rejection, "^NoncanonicalCap$"):
                CAP.main(["compare", str(one), str(one)])


if __name__ == "__main__":
    unittest.main()
