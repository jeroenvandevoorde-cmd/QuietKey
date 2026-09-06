#!/usr/bin/env python3
"""QK-DEC-162 pure guard, bounded CAP packaging, and Owner-run build recipe.

Requires Python 3.9+ and the standard library. Nothing downloads tools. `check`
requires no proprietary bytes and may run the pure JVM vector tests. Only
explicit `build test ...` executes the applet compiler/converter; the first
such run remains Owner-scheduled. All output is public test material.
"""

import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tarfile
import time
import xml.etree.ElementTree as ET
import zipfile
import zlib


class Rejection(Exception):
    """The sole public failure value is the closed category name."""


def require(condition, name):
    if not condition:
        raise Rejection(name)


SOURCES = ("CardRecord", "HmacSha512", "KeyCardBApplet", "NativeSecp256k1",
           "Protocol", "Scalar256", "Session", "Sha512", "Wipe")
COMPONENT_ROOT = "org/quietkey/cardb/javacard/"
COMPONENTS = tuple(COMPONENT_ROOT + name + ".cap" for name in (
    "Header", "Directory", "Applet", "Import", "ConstantPool", "Class",
    "Method", "StaticField", "RefLocation", "Export", "Descriptor"))
REQUIRED = set(COMPONENTS[:3])
CLASS_ROOT = "APPLET-INF/classes/org/quietkey/cardb/"
CLASSES = tuple(CLASS_ROOT + name + ".class" for name in SOURCES)
MANIFEST = "META-INF/MANIFEST.MF"
MANIFEST_BODY = (b"Manifest-Version: 1.0\r\n"
                 b"QuietKey-Material: PERMANENTLY NEVER-FUND TEST MATERIAL\r\n\r\n")
SIDECARS = (MANIFEST, "META-INF/javacard.xml", "APPLET-INF/applet.xml")
FILES = set(COMPONENTS + CLASSES + SIDECARS)
DIRECTORIES = {"/".join(name.split("/")[:i]) + "/"
               for name in FILES for i in range(1, len(name.split("/")))}
MAX_RAW = 2_097_152
MAX_ENTRIES = 64
MAX_NAME = 128
MAX_FILE = 1_048_576
MAX_TOTAL = 4_194_304
# The row's 2 MiB ceiling is for compressed raw input, not STORED output.
# The canonical manifest can add bytes when absent/short in raw input.
MAX_CANONICAL_TOTAL = MAX_TOTAL + len(MANIFEST_BODY)
MAX_CANONICAL = MAX_CANONICAL_TOTAL + MAX_ENTRIES * (30 + 46 + 2 * MAX_NAME) + 22
API_BYTES = 56_791
API_SHA = "b1981a2e97b77995cc79f67f04a12f5da3672a57715d5adf8eca27264b6119bd"
TOOLS = {
    "jdk": ("OpenJDK25U-jdk_x64_mac_hotspot_25.0.4.1_1.tar.gz", 120256199,
            "e6229d9504f7922053ab31821b9e6bee8761daf7b026a3476d1a027563009880"),
    "ant": ("apache-ant-1.10.17-bin.tar.xz", 5071020,
            "9553018e2cd5368261c32b2163c802e00de0a1c9707c3cfdd4cf7d6821674b08"),
    "task": ("ant-javacard-v26.05.15.jar", 65577,
             "14f5e25c07b184e4ec02ee148892c2ea7ad5d7e9db8b91109524df8f7d000589"),
    "devkit": ("java_card_devkit_tools-bin-v26.0-b_705-04-MAY-2026.zip", 1781450,
               "86443cb1b64c006456e524d91082ba25d5ebb0ee5506c6e4d7088350ce251d9d"),
}
CAP_ATTRIBUTES = {
    "jckit": "${qk.devkit}", "targetsdk": "3.0.5", "classes": "${qk.classes}",
    "package": "org.quietkey.cardb", "aid": "F0514B3242", "version": "1.0",
    "output": "${qk.raw.cap}", "verify": "true", "debug": "false",
    "strip": "false", "ints": "false", "exportmap": "false",
}


def sha(body):
    return hashlib.sha256(body).hexdigest()


def identity(body):
    return {"bytes": len(body), "sha256": sha(body)}


def file_identity(path):
    hasher = hashlib.sha256()
    count = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1048576), b""):
            hasher.update(block)
            count += len(block)
    return {"bytes": count, "sha256": hasher.hexdigest()}


def absolute_path(value, kind="file", absent=False):
    path = Path(value)
    require(path.is_absolute() and str(path) == value and ".." not in path.parts,
            "PathRejected")
    require(not any(char in value for char in ("'", '"', ":", "\r", "\n", "\0")),
            "PathRejected")
    for part in (path,) + tuple(path.parents):
        require(not part.is_symlink(), "PathRejected")
    if absent:
        require(not path.exists() and path.parent.is_dir(), "OutputAlreadyExists")
    elif kind == "file":
        require(path.is_file() and stat.S_ISREG(path.stat().st_mode), "PathRejected")
    else:
        require(path.is_dir(), "PathRejected")
    return path


def bounded_read(path, limit=MAX_RAW):
    require(path.stat().st_size <= limit, "ArchiveOverLimit")
    with path.open("rb") as handle:
        body = handle.read(limit + 1)
    require(len(body) <= limit, "ArchiveOverLimit")
    return body


def fields(body, offset, fmt):
    size = struct.calcsize(fmt)
    require(0 <= offset <= len(body) - size, "MalformedArchive")
    return struct.unpack_from(fmt, body, offset)


def extra_fields(extra):
    offset = 0
    while offset < len(extra):
        tag, size = fields(extra, offset, "<HH")
        require(tag != 1, "Zip64Rejected")
        offset += 4 + size
        require(offset <= len(extra), "MalformedArchive")


def decompress(body, method, size):
    if method == 0:
        result = body
    else:
        try:
            decoder = zlib.decompressobj(-15)
            result = decoder.decompress(body, size + 1)
            require(len(result) <= size, "DecompressionExcess")
            require(decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,
                    "MalformedArchive")
        except zlib.error:
            raise Rejection("MalformedArchive") from None
    require(len(result) == size, "ArchiveLengthMismatch")
    return result


def parse_raw(body, class_bodies=None, check_classes=True, canonical_input=False):
    """Validate both header sets, ranges, descriptors and bodies without ZIP heuristics."""
    require(22 <= len(body) <= (MAX_CANONICAL if canonical_input else MAX_RAW), "ArchiveOverLimit")
    eocd = body.rfind(b"PK\x05\x06", max(0, len(body) - 65557))
    require(eocd >= 0, "MalformedArchive")
    sig, disk, c_disk, disk_count, count, c_size, c_start, comment = fields(
        body, eocd, "<4s4H2IH")
    require(eocd + 22 + comment == len(body), "TrailingData")
    require(disk == c_disk == 0 and disk_count == count, "MultiDiskRejected")
    require(count != 65535 and c_size != 0xffffffff and c_start != 0xffffffff,
            "Zip64Rejected")
    require(0 < count <= MAX_ENTRIES, "ArchiveOverLimit")
    require(c_start + c_size == eocd, "MalformedArchive")
    offset = c_start
    entries = []
    names = set()
    total = 0
    for _ in range(count):
        (sig, made, needed, flags, method, clock, date, crc, packed, size,
         name_len, extra_len, comment_len, start_disk, internal, external,
         local) = fields(body, offset, "<4s6H3I5H2I")
        require(sig == b"PK\x01\x02", "MalformedArchive")
        require(needed <= 20 and packed != 0xffffffff and size != 0xffffffff
                and local != 0xffffffff, "Zip64Rejected")
        require(start_disk == 0, "MultiDiskRejected")
        require(not flags & (1 | 64 | 8192), "EncryptionRejected")
        require(not flags & ~0x080e, "UnsupportedZipFlags")
        require(method in (0, 8), "CompressionRejected")
        require(method == 8 or not flags & 6, "UnsupportedZipFlags")
        require(0 < name_len <= MAX_NAME and size <= MAX_FILE, "ArchiveOverLimit")
        end = offset + 46 + name_len + extra_len + comment_len
        require(end <= eocd, "MalformedArchive")
        encoded = body[offset + 46:offset + 46 + name_len]
        try:
            name = encoded.decode("utf-8")
        except UnicodeDecodeError:
            raise Rejection("ArchivePathRejected") from None
        require(name in FILES or name in DIRECTORIES, "ArchivePathRejected")
        require(name not in names, "DuplicateArchiveEntry")
        names.add(name)
        mode = (external >> 16) & 0xffff
        file_type = stat.S_IFMT(mode)
        directory = name.endswith("/")
        require(file_type in (0, stat.S_IFDIR if directory else stat.S_IFREG),
                "ArchiveSpecialFileRejected")
        require(directory or not external & 0x10, "ArchiveSpecialFileRejected")
        require(not directory or size == 0, "ArchiveDirectoryRejected")
        extra_fields(body[offset + 46 + name_len:offset + 46 + name_len + extra_len])
        total += size
        require(total <= (MAX_CANONICAL_TOTAL if canonical_input else MAX_TOTAL), "ArchiveOverLimit")
        entries.append((local, name, encoded, flags, method, crc, packed, size))
        offset = end
    require(offset == eocd, "MalformedArchive")
    out = {}
    next_local = 0
    for local, name, encoded, flags, method, crc, packed, size in sorted(entries):
        require(local == next_local, "ArchiveOverlapOrPadding")
        (sig, needed, l_flags, l_method, clock, date, l_crc, l_packed, l_size,
         n_len, e_len) = fields(body, local, "<4s5H3I2H")
        require(sig == b"PK\x03\x04" and needed <= 20 and flags == l_flags
                and method == l_method, "ArchiveHeaderMismatch")
        require(n_len == len(encoded) and body[local + 30:local + 30 + n_len] == encoded,
                "ArchiveHeaderMismatch")
        start = local + 30 + n_len + e_len
        end = start + packed
        require(end <= c_start, "MalformedArchive")
        extra_fields(body[local + 30 + n_len:start])
        if flags & 8:
            require(l_crc in (0, crc) and l_packed in (0, packed) and l_size in (0, size),
                    "ArchiveHeaderMismatch")
            if body[end:end + 4] == b"PK\x07\x08":
                end += 4
            require(fields(body, end, "<3I") == (crc, packed, size),
                    "ArchiveHeaderMismatch")
            end += 12
        else:
            require((l_crc, l_packed, l_size) == (crc, packed, size), "ArchiveHeaderMismatch")
        require(end <= c_start, "MalformedArchive")
        value = decompress(body[start:start + packed], method, size)
        require(binascii.crc32(value) & 0xffffffff == crc, "ArchiveCrcMismatch")
        if not name.endswith("/"):
            if name in CLASSES and check_classes:
                require(class_bodies is not None and class_bodies.get(name) == value,
                        "ClassMismatch")
            out[name] = value
        next_local = end
    require(next_local == c_start, "ArchiveOverlapOrPadding")
    require(REQUIRED <= set(out), "MissingCapComponent")
    return out


def canonical_bytes(files):
    """Fully specified ZIP writer; no dependency on zipfile output defaults."""
    data = dict(files)
    data[MANIFEST] = MANIFEST_BODY
    local = bytearray()
    central = bytearray()
    for name in sorted(data, key=lambda item: item.encode("utf-8")):
        require(name in FILES, "ArchivePathRejected")
        encoded = name.encode("utf-8")
        value = data[name]
        size = len(value)
        crc = binascii.crc32(value) & 0xffffffff
        start = len(local)
        local.extend(struct.pack("<4s5H3I2H", b"PK\x03\x04", 20, 0x800, 0, 0, 0x21,
                                 crc, size, size, len(encoded), 0))
        local.extend(encoded)
        local.extend(value)
        central.extend(struct.pack("<4s6H3I5H2I", b"PK\x01\x02", 0x314, 20, 0x800,
                                   0, 0, 0x21, crc, size, size, len(encoded),
                                   0, 0, 0, 0, 0x81a40000, start))
        central.extend(encoded)
    end = struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, len(data), len(data),
                      len(central), len(local), 0)
    result = bytes(local + central + end)
    require(len(result) <= MAX_CANONICAL, "ArchiveOverLimit")
    return result


def canonicalize(raw, class_bodies=None):
    files = parse_raw(raw, class_bodies)
    canonical = canonical_bytes(files)
    reopened = parse_raw(canonical, class_bodies, canonical_input=True)
    expected = dict(files)
    expected[MANIFEST] = MANIFEST_BODY
    require(set(reopened) == set(expected), "ComponentMismatch")
    for name in expected:
        require(reopened[name] == expected[name], "ComponentMismatch")
    return canonical, [{"name": name, "bytes": len(expected[name]),
                        "crc32": "%08x" % (binascii.crc32(expected[name]) & 0xffffffff),
                        "sha256": sha(expected[name])}
                       for name in sorted(expected)]


def load_classes(path):
    required = {"org/quietkey/cardb/" + name + ".class" for name in SOURCES}
    files = {item.relative_to(path).as_posix() for item in path.rglob("*") if item.is_file()}
    require(files == required, "UnexpectedClass")
    result = {}
    for name in sorted(required):
        item = absolute_path(str(path / name))
        value = bounded_read(item, MAX_FILE)
        require(len(value) >= 8 and value[:4] == b"\xca\xfe\xba\xbe"
                and value[4:8] == b"\0\0\0\x34", "UnexpectedClassVersion")
        result["APPLET-INF/classes/" + name] = value
    return result


def ensure_test(mode):
    require(mode == "test", "ProductionTestIdentifiersRejected")


def xml_shape(element):
    require(not (element.text or "").strip() and not (element.tail or "").strip(),
            "BuildDeclarationMismatch")
    return (element.tag, element.attrib, [xml_shape(child) for child in element])


def check_xml(path):
    raw = bounded_read(path, 16384)
    require(b"<!" not in re.sub(rb"<!--.*?-->", b"", raw, flags=re.S),
            "BuildDeclarationMismatch")
    try:
        found = xml_shape(ET.fromstring(raw))
    except ET.ParseError:
        raise Rejection("BuildDeclarationMismatch") from None
    expected = ("project", {"name": "quietkey-cardb-test-cap", "default": "convert"}, [
        ("taskdef", {"name": "javacard", "classname": "pro.javacard.ant.JavaCard",
                     "classpath": "${qk.task.jar}"}, []),
        ("target", {"name": "convert"}, [("javacard", {}, [
            ("cap", CAP_ATTRIBUTES, [("applet", {
                "class": "org.quietkey.cardb.KeyCardBApplet", "aid": "F0514B324201"}, [])])])])])
    require(found == expected, "BuildDeclarationMismatch")


def build_commands(jdk, ant, devkit, task, source, classes, tmp, raw):
    api = str(devkit / "lib/api_classic-3.0.5.jar")
    javac = [str(jdk / "bin/javac"), "-source", "1.8", "-target", "1.8",
             "-bootclasspath", api, "-classpath", api, "-proc:none", "-implicit:none",
             "-encoding", "UTF-8", "-g:none", "-d", str(classes)]
    javac += [str(source / "bench/card-applet/src/org/quietkey/cardb" / (name + ".java"))
              for name in SOURCES]
    convert = [str(jdk / "bin/java"), "-Dant.home=" + str(ant), "-Dfile.encoding=UTF-8",
               "-Duser.language=en", "-Duser.country=US", "-Duser.timezone=UTC",
               "-Djava.io.tmpdir=" + str(tmp), "-classpath", str(ant / "lib/ant-launcher.jar"),
               "org.apache.tools.ant.launch.Launcher", "-nouserlib", "-noclasspath",
               "-verbose", "-f", str(source / "bench/card-applet/build.xml"),
               "-Dqk.devkit=" + str(devkit), "-Dqk.classes=" + str(classes),
               "-Dqk.raw.cap=" + str(raw), "-Dqk.task.jar=" + str(task), "convert"]
    env = {"JAVA_HOME": str(jdk), "PATH": str(jdk / "bin") + ":/usr/bin:/bin",
           "LC_ALL": "C", "LANG": "C", "TZ": "UTC", "_ANT_JAVACARD_LOGHACK": "false"}
    return javac, convert, env


def converter_command(jdk, devkit, classes, converter_tmp):
    return [str(jdk / "bin/java"), "-classpath", str(devkit / "lib/tools.jar"),
            "com.sun.javacard.converter.Main", "-d", str(converter_tmp),
            "-classdir", str(classes), "-target", "3.0.5", "-verbose", "-nobanner",
            "-useproxyclass", "-out", "CAP", "EXP", "-applet",
            "0xF0:0x51:0x4B:0x32:0x42:0x01", "org.quietkey.cardb.KeyCardBApplet",
            "org.quietkey.cardb", "0xF0:0x51:0x4B:0x32:0x42", "1.0"]


def check_wrapper(path, check=False):
    lines = [line for line in path.read_text(encoding="utf-8").splitlines()
             if not line.startswith("#") and line]
    common = ["set -eu", "if ! command -v python3 >/dev/null 2>&1; then",
              "    echo 'QK-CARD-APPLET FAIL Python3Unavailable' >&2", "    exit 1", "fi"]
    if check:
        tail = ['repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)',
                'exec python3 -I "$repo_root/bench/card-applet/canonical-cap.py" check "$repo_root"']
    else:
        tail = ['script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)',
                'exec python3 -I "$script_dir/canonical-cap.py" "$@"']
    require(lines == common + tail, "BuildWrapperMismatch")


def check_allowlist(path):
    rows = [line.split("\t") for line in path.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")]
    require(all(len(row) == 7 and all(row) for row in rows), "DependencyAllowlistMismatch")
    prior = ("\n".join("\t".join(row) for row in rows if row[0] != "api") + "\n").encode()
    require(sha(prior) == "f7dacd38fc5f9f928c2b5ce69ea388eeda063bec9b84b00211d98f9ed95c3dbc",
            "DependencyAllowlistMismatch")
    api_rows = [row for row in rows if row[0] == "api"]
    require(len(api_rows) == 1 and "lib/api_classic-3.0.5.jar" in api_rows[0][4]
            and "56791" in api_rows[0][4]
            and api_rows[0][5] == "Oracle Technology Network Developer License Agreement for Oracle Java",
            "DependencyAllowlistMismatch")
    # Pin every existing QK-DEC-155 row without making the loader a build input.
    expected = {
        ("tool", "Temurin JDK", "25.0.4.1+1"): TOOLS["jdk"][2],
        ("tool", "Apache Ant", "1.10.17"): TOOLS["ant"][2],
        ("tool", "ant-javacard", "26.05.15"): TOOLS["task"][2],
        ("tool", "Oracle Java Card Development Kit Tools", "26.0 build 705"): TOOLS["devkit"][2],
        ("tool", "GlobalPlatformPro gp.jar", "25.10.20"):
            "c88e0c5093032ec4571571f5397b6174e56bf632667950fa5bb716338534b122",
        ("api", "Java Card Classic API", "3.0.5"): API_SHA,
    }
    shaded = (
        ("com.github.martinpaljak:apdu4j-core", "25.03.11", "7ac0a75967a01cd437aed37aff7255a8c33d5773b19404cd665e65ff26c044e3"),
        ("com.github.martinpaljak:apdu4j-pcsc", "25.03.11", "acaf86b31f811949fee80680189ea99058477dfe683cf3593086ea2e0fc7120b"),
        ("com.github.martinpaljak:apdu4j-jnasmartcardio", "25.03.11", "36eddc172de555e4b748bcca630bca197f32d19fa2528a894d3d5850a21a7401"),
        ("com.github.martinpaljak:capfile", "25.09.20", "08ed32ca2a894a164c2aaec067ffdde1351644e0f2f664344da7daecca989db3"),
        ("org.slf4j:slf4j-api", "2.0.17", "7b751d952061954d5abfed7181c1f645d336091b679891591d63329c622eb832"),
        ("org.slf4j:slf4j-simple", "2.0.17", "ddfea59ac074c6d3e24ac2c38622d2d963895e17f70b38ed4bdae4d780be6964"),
        ("org.bouncycastle:bcpkix-jdk18on", "1.82", "bdc723e20834832ac6af136cb5b5ff05e43b71d4fa151cc6510d9212ee086e63"),
        ("org.bouncycastle:bcprov-jdk18on", "1.82", "14cde2fdfaa8890480a8e5b67aceef0c90f96682c1e23c133bafdc9e0b3255ce"),
        ("org.bouncycastle:bcutil-jdk18on", "1.82", "4420691958ad1c0ba275a6d6d8a6317adbdbdc9277055b6a72aa89c88cda8c7d"),
        ("com.payneteasy:ber-tlv", "1.0-11", "a435eabb526c7d06caad20dddf16771368ba6640e5518ffac8614fdcac3d8a80"),
        ("net.sf.jopt-simple:jopt-simple", "5.0.4", "df26cc58f235f477db07f753ba5a3ab243ebe5789d9f89ecf68dd62ea9a66c28"),
        ("com.google.auto.service:auto-service-annotations", "1.1.1", "16a76dd00a2650568447f5d6e3a9e2c809d9a42367d56b45215cfb89731f4d24"),
        ("com.fasterxml.jackson.dataformat:jackson-dataformat-cbor", "2.20.0", "ab075616cbd67f5676f89825ec9c8bc7b54c84dbe934b162145b34172370b5d6"),
        ("com.fasterxml.jackson.core:jackson-databind", "2.20.0", "a70e146a6bf2cba4f9cd367169787f50adcfbb57122bc2e9c8390cd0b397ac30"),
        ("com.fasterxml.jackson.core:jackson-core", "2.20.0", "bc0cf46075877201f8406ee7de2741ae7df6c066f5f0457bd80632a718c06e72"),
        ("com.fasterxml.jackson.core:jackson-annotations", "2.20", "959a2ffb2d591436f51f183c6a521fc89347912f711bf0cae008cdf045d95319"),
        ("org.yaml:snakeyaml", "2.4", "ef779af5d29a9dde8cc70ce0341f5c6f7735e23edff9685ceaa9d35359b7bb7f"),
        ("net.java.dev.jna:jna-jpms", "5.16.0", "f4b68ffc6958c3ce3463fb908621595623db85c494bc44c7fb6f5e77f9a41804"),
    )
    expected.update({("shaded", name, version): digest for name, version, digest in shaded})
    actual = {tuple(row[:3]): row[3] for row in rows}
    require(len(actual) == len(rows) and actual == expected, "DependencyAllowlistMismatch")
    return len(rows)


def check_repository(root, check_closures=True):
    base = root / "bench/card-applet"
    check_xml(base / "build.xml")
    check_wrapper(base / "build.sh")
    check_wrapper(root / "tools/check-card-applet.sh", True)
    count = check_allowlist(base / "DEPENDENCY-ALLOWLIST.tsv")
    expected = {name + ".java" for name in SOURCES}
    source = base / "src/org/quietkey/cardb"
    require({p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()}
            == expected, "UnexpectedSource")
    for item in base.rglob("*"):
        require(not item.is_symlink(), "PathRejected")
        require(item.suffix.lower() not in (".jar", ".cap", ".class", ".exp", ".zip",
                                           ".gz", ".xz", ".tar", ".so", ".dylib"),
                "VendoredToolRejected")
        require(item.name not in ("Cargo.toml", "pom.xml", "build.gradle", "gradlew",
                                  "settings.gradle", "package.json"), "UndeclaredBuildInput")
    if check_closures:
        # A cargo metadata graph enumerates paths even when an optional dependency
        # is feature-disabled; --all-features includes every registered closure.
        for manifest in (root / "host/Cargo.toml", root / "fuzz/Cargo.toml",
                         root / "bench/card-enrollment/Cargo.toml"):
            try:
                result = subprocess.run(["cargo", "metadata", "--offline", "--locked",
                    "--format-version", "1", "--all-features", "--manifest-path", str(manifest)],
                    cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            except OSError:
                raise Rejection("ClosureInspectionFailed") from None
            require(result.returncode == 0, "ClosureInspectionFailed")
            try:
                metadata = json.loads(result.stdout)
                require(metadata["resolve"] is not None, "ClosureInspectionFailed")
                for package in metadata["packages"]:
                    path = Path(package["manifest_path"]).resolve()
                    require(base.resolve() not in path.parents, "AppletClosureViolation")
                    for dep in package["dependencies"]:
                        if dep.get("path"):
                            dpath = Path(dep["path"]).resolve()
                            require(dpath != base.resolve() and base.resolve() not in dpath.parents,
                                    "AppletClosureViolation")
            except (KeyError, ValueError, TypeError):
                raise Rejection("ClosureInspectionFailed") from None
    return {"allowlist_rows": count, "source_files": len(SOURCES), "result": "PASS"}


def verify_tool(kind, value):
    path = absolute_path(value)
    expected_name, size, digest = TOOLS[kind]
    require(path.name == expected_name and file_identity(path) == {"bytes": size, "sha256": digest},
            "ToolIdentityMismatch")
    return path


def relative_member(name):
    require(name and not name.startswith("/") and "\\" not in name
            and all(part not in ("", ".", "..") for part in name.rstrip("/").split("/")),
            "ToolArchiveMismatch")
    return name.rstrip("/")


def verify_extracted(archive, home, kind):
    """Tie every extracted input to its hash-pinned archive; forbid added files.

    JDK mac archives have one top root plus Contents/Home; Ant has one top root;
    the DevKit ZIP has bin/lib at its root. No extraction is performed here.
    """
    expected = {}
    symlinks = {}
    prefix = None
    if kind == "devkit":
        with zipfile.ZipFile(archive) as source:
            for info in source.infolist():
                name = relative_member(info.filename)
                if not info.is_dir():
                    require(name not in expected and info.file_size <= 67108864, "ToolArchiveMismatch")
                    expected[name] = identity(source.read(info))
    else:
        with tarfile.open(archive, "r:*") as source:
            for member in source:
                name = relative_member(member.name)
                parts = name.split("/")
                if prefix is None:
                    prefix = parts[0]
                require(parts[0] == prefix, "ToolArchiveMismatch")
                sub = "/".join(parts[1:])
                if kind == "jdk":
                    if not sub.startswith("Contents/Home/"):
                        continue
                    sub = sub[len("Contents/Home/"):]
                if not sub or member.isdir():
                    continue
                require(sub not in expected and sub not in symlinks, "ToolArchiveMismatch")
                if member.issym():
                    symlinks[sub] = member.linkname
                else:
                    require(member.isfile() and member.size <= 536870912, "ToolArchiveMismatch")
                    handle = source.extractfile(member)
                    require(handle is not None, "ToolArchiveMismatch")
                    hasher = hashlib.sha256()
                    count = 0
                    for chunk in iter(lambda: handle.read(1048576), b""):
                        hasher.update(chunk)
                        count += len(chunk)
                    require(count == member.size, "ToolArchiveMismatch")
                    expected[sub] = {"bytes": count, "sha256": hasher.hexdigest()}
    actual = set()
    for path in home.rglob("*"):
        relative = path.relative_to(home).as_posix()
        if path.is_symlink():
            require(relative in symlinks and os.readlink(path) == symlinks[relative], "ToolIdentityMismatch")
            resolved = path.resolve()
            require(home == resolved or home in resolved.parents, "ToolIdentityMismatch")
            actual.add(relative)
        elif path.is_file():
            require(relative in expected and file_identity(path) == expected[relative], "ToolIdentityMismatch")
            actual.add(relative)
        else:
            require(path.is_dir(), "ToolIdentityMismatch")
    require(actual == set(expected) | set(symlinks), "ToolIdentityMismatch")
    return ([{"path": str(home / name), **expected[name]} for name in sorted(expected)]
            + [{"path": str(home / name), "symlink": symlinks[name]}
               for name in sorted(symlinks)])


def atomic_new(path, body):
    with path.open("xb") as output:
        os.chmod(path, 0o600)
        output.write(body)
        output.flush()
        os.fsync(output.fileno())


def write_json(path, value):
    atomic_new(path, (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())


def execute_logged(command, environment, cwd, path, failure):
    with path.open("xb") as output:
        os.chmod(path, 0o600)
        try:
            outcome = subprocess.run(command, cwd=cwd, env=environment,
                                     stdin=subprocess.DEVNULL, stdout=output,
                                     stderr=subprocess.STDOUT, check=False)
        except OSError:
            raise Rejection(failure) from None
        require(outcome.returncode == 0, failure)


def parse_converter_log(text, jdk, devkit, classes, tmp):
    # Ant verbose Java.executeJava emits one quoted argument on each log line.
    lines = text.splitlines()
    marker = "[convert] Executing '" + str(jdk / "bin/java") + "' with arguments:"
    positions = [i for i, line in enumerate(lines) if line.strip() == marker]
    require(len(positions) == 1, "UnexpectedConverterCommand")
    args = []
    for line in lines[positions[0] + 1:]:
        value = line.strip()
        if not value.startswith("[convert]"):
            continue
        value = value[len("[convert]"):].strip()
        if value.startswith("'") and value.endswith("'"):
            args.append(value[1:-1])
        elif args:
            break
    require(len(args) >= 5 and args[3] == "-d", "UnexpectedConverterCommand")
    converter_tmp = Path(args[4])
    require(converter_tmp.is_absolute() and tmp in converter_tmp.parents, "UnexpectedConverterCommand")
    expected = converter_command(jdk, devkit, classes, converter_tmp)
    require([str(jdk / "bin/java")] + args == expected, "UnexpectedConverterCommand")
    return expected


def verify_converter_log(text, command):
    converter_tmp = Path(command[5])
    message = "[verify] Verification of " + str(converter_tmp / COMPONENT_ROOT / "cardb.cap") + " passed"
    require(sum(line.strip() == message for line in text.splitlines()) == 1,
            "VerificationFailed")


def build(args):
    require(len(args) == 10, "InvocationRejected")
    mode, root_s, commit, jdk_archive_s, jdk_s, ant_archive_s, ant_s, devkit_archive_s, task_s, output_s = args
    ensure_test(mode)
    root = absolute_path(root_s, "directory")
    output = absolute_path(output_s, absent=True)
    require(root not in output.parents and re.fullmatch(r"[0-9a-f]{40}", commit), "BuildSourceMismatch")
    output.mkdir(mode=0o700)
    registration = {"contract": "QK-CARD-APPLET-BUILD-V1", "material": "PERMANENTLY NEVER-FUND TEST MATERIAL",
                    "source_commit": commit, "result": "FAIL", "output": str(output),
                    "started_unix_ns": time.time_ns()}
    write_json(output / "attempt.json", {**registration, "arguments": args})
    try:
        status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"],
                                cwd=root, capture_output=True, check=False)
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, check=False)
        require(status.returncode == 0 and status.stdout == b"" and head.returncode == 0
                and head.stdout.decode().strip() == commit, "BuildSourceMismatch")
        check_repository(root)
        jdk_archive = verify_tool("jdk", jdk_archive_s)
        ant_archive = verify_tool("ant", ant_archive_s)
        devkit_archive = verify_tool("devkit", devkit_archive_s)
        task = verify_tool("task", task_s)
        jdk = absolute_path(jdk_s, "directory")
        ant = absolute_path(ant_s, "directory")
        devkit = absolute_path(str(devkit_archive.with_suffix("")), "directory")
        registration["tools"] = [{"path": str(path), **file_identity(path)}
                                  for path in (jdk_archive, ant_archive, devkit_archive, task)]
        registration["extracted_inputs"] = (verify_extracted(jdk_archive, jdk, "jdk")
            + verify_extracted(ant_archive, ant, "ant")
            + verify_extracted(devkit_archive, devkit, "devkit"))
        api = absolute_path(str(devkit / "lib/api_classic-3.0.5.jar"))
        require(file_identity(api) == {"bytes": API_BYTES, "sha256": API_SHA}, "ApiIdentityMismatch")
        for executable in (jdk / "bin/javac", jdk / "bin/java"):
            require(executable.is_file() and os.access(executable, os.X_OK), "ToolIdentityMismatch")
        classes, tmp, raw = output / "classes", output / "tmp", output / "raw.cap"
        classes.mkdir(mode=0o700)
        tmp.mkdir(mode=0o700)
        javac, convert, env = build_commands(jdk, ant, devkit, task, root, classes, tmp, raw)
        registration["commands"] = [javac, convert]
        registration["environment"] = env
        write_json(output / "invocation.json", registration)
        execute_logged(javac, env, output, output / "javac.log", "CompilationFailed")
        class_bodies = load_classes(classes)
        execute_logged(convert, env, output, output / "converter.log", "ConversionOrVerificationFailed")
        log = (output / "converter.log").read_text(encoding="utf-8")
        registration["converter_command"] = parse_converter_log(log, jdk, devkit, classes, tmp)
        verify_converter_log(log, registration["converter_command"])
        raw_body = bounded_read(absolute_path(str(raw)))
        canonical, entries = canonicalize(raw_body, class_bodies)
        canonical_path = output / "canonical.cap"
        atomic_new(canonical_path, canonical)
        reopened = bounded_read(canonical_path, MAX_CANONICAL)
        require(reopened == canonical, "ComponentMismatch")
        require(canonical_bytes(parse_raw(reopened, class_bodies, canonical_input=True)) == reopened,
                "ComponentMismatch")
        registration.update({"raw": identity(raw_body), "canonical": identity(reopened),
                             "entries": entries, "result": "PASS"})
    except Rejection as failure:
        registration["rejection"] = str(failure)
        raise
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError, UnicodeError):
        registration["rejection"] = "InputOrIoRejected"
        raise Rejection("InputOrIoRejected") from None
    finally:
        registration["retained_outputs"] = [{"name": item.name, **file_identity(item)}
            for item in sorted(output.iterdir())
            if item.is_file() and not item.is_symlink()]
        registration["finished_unix_ns"] = time.time_ns()
        write_json(output / "build-result.json", registration)
    return registration


def main(argv):
    require(sys.version_info >= (3, 9), "PythonVersionRejected")
    require(bool(argv), "InvocationRejected")
    if argv[0] == "check" and len(argv) == 2:
        root = absolute_path(argv[1], "directory")
        result = check_repository(root)
        tests = subprocess.run([sys.executable, "-I", "-B", "-m", "unittest", "discover",
            "-s", str(root / "bench/card-applet/tests"), "-p", "test_*.py"],
            cwd=root, stdin=subprocess.DEVNULL, check=False)
        require(tests.returncode == 0, "BuildContractTestsFailed")
        return result
    if argv[0] == "canonicalize" and len(argv) == 5:
        ensure_test(argv[1])
        raw = absolute_path(argv[2])
        classes = load_classes(absolute_path(argv[3], "directory"))
        out = absolute_path(argv[4], absent=True)
        original = bounded_read(raw)
        canonical, entries = canonicalize(original, classes)
        atomic_new(out, canonical)
        require(bounded_read(out, MAX_CANONICAL) == canonical, "ComponentMismatch")
        return {"raw": identity(original), "canonical": identity(canonical), "entries": entries}
    if argv[0] == "compare" and len(argv) == 3:
        left, right = (bounded_read(absolute_path(value), MAX_CANONICAL) for value in argv[1:])
        require(left == right, "NonreproducibleCanonicalOutput")
        # Build artifacts have a component manifest in their private run records;
        # here the byte-level writer is checked without accepting class sidecars
        # blindly: their bytes come from the equal artifacts and are compared.
        entries = parse_raw(left, check_classes=False, canonical_input=True)
        require(canonical_bytes(entries) == left, "NoncanonicalCap")
        return {"canonical": identity(left), "result": "PASS"}
    if argv[0] == "build":
        return build(argv[1:])
    raise Rejection("InvocationRejected")


if __name__ == "__main__":
    try:
        result = main(sys.argv[1:])
        print("QK-CARD-APPLET PASS " + json.dumps(result, sort_keys=True, separators=(",", ":")))
    except Rejection as error:
        print("QK-CARD-APPLET FAIL " + str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, struct.error, zipfile.BadZipFile,
            tarfile.TarError, UnicodeError):
        print("QK-CARD-APPLET FAIL InputOrIoRejected", file=sys.stderr)
        sys.exit(1)
