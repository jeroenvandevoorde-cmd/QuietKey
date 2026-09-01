# Java Card Applet Candidate Toolchain Register

PLAN-ONLY REGISTRATION - APPLET LANE CLOSED - NO CARD ACTION AUTHORIZED

## Boundary

QK-DEC-155 registers the candidate HOST apparatus toolchain planned by
QK-DEC-152. No artifact in this register is committed, vendored, redistributed,
or reachable from a QuietKey product or fuzz dependency closure. This register
authorizes no installation, build, converter run, CAP, APDU, GlobalPlatform
operation, card contact, specimen mutation, production use, or Gate claim.

The future applet build must add its own fail-closed allowlist guard. No guard,
build manifest, or `tools/check.sh` wiring is created by this registration.

## Registered top-level artifacts

| Tool | Exact artifact | Bytes | SHA-256 | Source pin | License | Status |
|---|---|---:|---|---|---|---|
| Temurin JDK 25.0.4.1+1 | `OpenJDK25U-jdk_x64_mac_hotspot_25.0.4.1_1.tar.gz` | 120,256,199 | `e6229d9504f7922053ab31821b9e6bee8761daf7b026a3476d1a027563009880` | Adoptium `temurin25-binaries` release-tag target commit `790405b2b35f68f615679082036cbeb1ae58144a` | GPL-2.0-only with Classpath Exception 2.0 | Registered working hypothesis; first successful converter run closes the JDK pin. |
| Apache Ant 1.10.17 | `apache-ant-1.10.17-bin.tar.xz` | 5,071,020 | `9553018e2cd5368261c32b2163c802e00de0a1c9707c3cfdd4cf7d6821674b08` | Apache release archive; published SHA-512 `cac0bb907c671fdf48b8fe09ae0a37e34b7fd6c7c6f85fb3b8c218f100c2e7eb65df40c1c08e6ba2f89d7cde7e68482e731c4f5458c3539b25f8ddf2c6aebcdc` | Apache-2.0 | Registered candidate build driver. |
| ant-javacard v26.05.15 | Apparatus name `ant-javacard-v26.05.15.jar`; upstream release asset `ant-javacard.jar` | 65,577 | `14f5e25c07b184e4ec02ee148892c2ea7ad5d7e9db8b91109524df8f7d000589` | Commit `52a5d97ce8530e59dddeb09713409dd4a91daa85` | MIT | Registered candidate Ant task. The apparatus rename changes no byte; a separate LOA download of the same release asset reproduced the digest. |
| Oracle Java Card Development Kit Tools 26.0 build 705 | `java_card_devkit_tools-bin-v26.0-b_705-04-MAY-2026.zip` | 1,781,450 | `86443cb1b64c006456e524d91082ba25d5ebb0ee5506c6e4d7088350ce251d9d` | Oracle Java Card download table plus Owner-held exact archive matched on the apparatus | Oracle Technology Network Developer License Agreement for Oracle Java | Registered license-gated converter/verifier archive; nonredistributable and never vendored. |
| GlobalPlatformPro v25.10.20 | `gp.jar` | 14,840,623 | `c88e0c5093032ec4571571f5397b6174e56bf632667950fa5bb716338534b122` | Commit `72f85b982c8eb2f0de34691a8c7e1771412a5349` and matching release asset | LGPL-3.0-or-later for LGPL-covered/derived code; some original files additionally MIT per the pinned README and POM; shaded components retain their individual terms | Registered apparatus-only candidate loader; never enters a product or fuzz closure. |

The exact shaded-component artifact rows and individual license lines are in
`DEPENDENCY-ALLOWLIST.tsv` beside this file.

## Oracle gated-license record

The Owner reports that the exact DevKit ZIP has 32 entries comprising only the
seven named tools `capdump`, `capgen`, `converter`, `exp2text`, `verifycap`,
`verifyexp`, and `verifyrev` as `.sh` and `.bat` scripts plus `lib` contents. It
contains no file whose name is a license, notice, or third-party record.

The Oracle Java Card downloads gateway requires an Oracle-account login and
acceptance of the agreement titled **Oracle Technology Network Developer
License Agreement for Oracle Java**. The gateway states `You must accept the
Oracle License Agreement to download this software`; its checkbox states `I
reviewed and accept the Oracle License Agreement`; and its table identifies
`Java Card Development Kit Tools 26.0 (04-May-2026)`, 1.69 MB.

The Owner directs this exact agreement-scope excerpt into the register:

> Oracle grants You a nonexclusive, nontransferable, limited license to internally use the Programs, subject to the restrictions stated in this Agreement and Program Documentation, only for the purpose of developing, testing, prototyping and demonstrating Your Application and not for any other purpose

Under `Further, You may not`, the Owner supplies this exact partial sentence;
the sentence continues in the agreement and this register does not invent or
summarize the omitted words:

> use the Programs for any data processing or any commercial, production, or internal business purposes other than developing, testing

The DevKit is not redistributable and never enters Git. Every party rebuilding
the CAP must obtain the DevKit under Oracle's terms. Whether producing a
shipped commercial CAP falls within `developing Your Application` is an Owner
legal decision required before commercial release. It is not a blocker to the
present development, testing, and prototyping registration.

## Oracle JDK-version discrepancy and evidence-close rule

Oracle's Java Card Development Kit Tools Release Notes 26.0 contain both of
these statements; neither is discarded or relabeled. `System Requirements`
states:

> This release has been verified and tested with Oracle JDK 25 (64 bit version) and OpenJDK 25 (64 bit version)

`Installation` states:

> The tools in this development kit were tested with Oracle JDK 17 (64 bit version) and OpenJDK 17 (64 bit version)

Temurin 25.0.4.1+1 is the working hypothesis. The first successful converter
run on the registered apparatus closes the JDK pin. The named, not-yet-used
fallback is Temurin 17.0.20.1+1,
`OpenJDK17U-jdk_x64_mac_hotspot_17.0.20.1_1.tar.gz`, 180,578,248 bytes,
Adoptium API candidate SHA-256
`c01975da12ed4235250ff891fe8bba73a9e73037d444b269c9d0922b5dbc8e0a`,
binary-release tag target commit `43ddbe38be15fb92c9844af8b3db02baab2046e2`.
That fallback archive is neither downloaded nor registered for use. Its digest
must be checked from the obtained bytes before it is invoked. There is no
silent JDK or Ant substitution.

## GlobalPlatformPro shaded-closure derivation

The derivation starts only after this exact check:

```sh
test "$(shasum -a 256 gp.jar | awk '{print $1}')" = \
  c88e0c5093032ec4571571f5397b6174e56bf632667950fa5bb716338534b122
```

The canonical ZIP inventory is generated directly from the registered JAR,
without using an upstream dependency POM as closure authority:

```sh
python3 - gp.jar >gp.entries.tsv <<'PY'
import hashlib, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as archive:
    for item in sorted(archive.infolist(), key=lambda value: value.filename):
        body = archive.read(item.filename)
        print(f"{item.filename}\t{item.file_size}\t{item.CRC:08x}\t{hashlib.sha256(body).hexdigest()}")
PY
```

The result has exactly 9,725 ZIP entries: 592 directories and 9,133 files. Its
1,364,749-byte LF-terminated canonical inventory has SHA-256
`7ed68c27a2b8ee1bd91ecdea0d056288da118900bfa5280ebea021c605078763`.
The JAR contains zero `META-INF/maven/` entries and zero `pom.properties`
entries. Its 245-byte manifest has SHA-256
`706649efcd875095e57c7f5589485e8577c6a12ace9601e295b8b5c59c91961a`
and names source commit `72f85b982c8eb2f0de34691a8c7e1771412a5349`.

Each of the 18 candidate archives in `DEPENDENCY-ALLOWLIST.tsv` was fetched
from its exact registered URL and checked against its registered SHA-256. The
canonical 19-line input identity is
`basename<TAB>byte-count<TAB>sha256<LF>` under `LC_ALL=C` sort and has SHA-256
`f704f5618415e2a6e5a07bbce490da3c99eec7af78722567d563708747650390`.
It includes the exact registered `gp.jar` and all 18 candidates.

The byte-attribution computation was this exact inline command; no durable
script file existed:

```sh
/usr/bin/python3 - <<'PY'
import zipfile,hashlib,glob,os,collections
base='/tmp/qk-gpp.YRfS9r'; gp=base+'/gp.jar'; cands=glob.glob(base+'/deps/*.jar')
def E(p):
 with zipfile.ZipFile(p) as z:return {i.filename:(hashlib.sha256(z.read(i)).hexdigest(),len(z.read(i))) for i in z.infolist() if not i.is_dir()}
G=E(gp);C={os.path.basename(p):E(p) for p in cands}; counts=collections.Counter(); sizes=collections.Counter();un=[]
for n,(h,s) in G.items():
 ms=[c for c,e in C.items() if e.get(n,(None,None))[0]==h]
 if len(ms)==1:counts[ms[0]]+=1;sizes[ms[0]]+=s
 elif not ms:un.append(n)
print('artifact\tmatched_files\tmatched_uncompressed_bytes')
for c in sorted(C):print(f'{c}\t{counts[c]}\t{sizes[c]}')
print('unmatched',len(un))
from collections import Counter
for p,c in Counter('/'.join(n.split('/')[:3]) for n in un).most_common():print(c,p)
PY
```

The Python body from its first import through its final LF has SHA-256
`005ebac9ff084c3f7c5c5dc04afc090aa4fc6b32a6dad5f57142f66624ca60a0`.
It ran under `/usr/bin/python3` 3.9.6, executable SHA-256
`7f30f076d0e9c38f772a76449fca9da8cf97f6a3d43b94c90a00e4f9ce7ad39e`,
on Darwin 24.6.0 x86_64. Matching exact ZIP paths and SHA-256 of the
uncompressed entry bytes attributed 9,063 files uniquely and left 70
unmatched; those totals cover all 9,133 non-directory entries, proving zero
ambiguous multi-artifact matches. The unmatched set is 48
`pro/javacard/gp` entries (47 classes plus root `git.properties`), 11
`pro/javacard/gptool` classes, six `pro/javacard/pace` classes, the root
manifest, and four root-generated or shade-merged service files:
`CardKeysProvider`, combined Jackson `JsonFactory`, the SLF4J provider, and
`SmartCardApp`. The combined `JsonFactory` body was separately decomposed into
the exact CBOR and jackson-core provider lines.

Within the code/native subset, exactly 9,045 entries match the 18 registered
artifacts and the only remaining 64 entries are the 47, 11 and six classes in
the pinned GlobalPlatformPro-owned roots. Candidate module descriptors are
excluded by the shade configuration. The JNA match includes all 28 bundled
native `jnidispatch` binaries. The three Bouncy Castle 1.82 artifacts supply
the bundled cryptographic implementation. JNA native code and Bouncy Castle
run only on the registered apparatus through `gp.jar`; neither enters any
QuietKey product or fuzz closure.

## Apparatus-copy ledger

Every row below uses apparatus alias `iMac` and private path alias
`qk-bench-evidence`. The Owner reports that `shasum -a 256` was run on the
apparatus and each result was compared with the registered value.

| Tool | Apparatus filename | Bytes | SHA-256 | Verification UTC | File mtime UTC | Result |
|---|---|---:|---|---|---|---|
| Temurin 25.0.4.1+1 | `OpenJDK25U-jdk_x64_mac_hotspot_25.0.4.1_1.tar.gz` | 120,256,199 | `e6229d9504f7922053ab31821b9e6bee8761daf7b026a3476d1a027563009880` | immediately after 2026-09-01T22:05:12Z, clock reading not captured | `2026-09-01T22:05:12Z` | MATCH |
| ant-javacard v26.05.15 | `ant-javacard-v26.05.15.jar` | 65,577 | `14f5e25c07b184e4ec02ee148892c2ea7ad5d7e9db8b91109524df8f7d000589` | immediately after 2026-09-01T22:05:12Z, clock reading not captured | `2026-09-01T22:05:12Z` | MATCH |
| Apache Ant 1.10.17 | `apache-ant-1.10.17-bin.tar.xz` | 5,071,020 | `9553018e2cd5368261c32b2163c802e00de0a1c9707c3cfdd4cf7d6821674b08` | `2026-09-01T22:00:03Z` | `2026-09-01T15:25:51Z` | MATCH |
| Oracle DevKit 26.0 build 705 | `java_card_devkit_tools-bin-v26.0-b_705-04-MAY-2026.zip` | 1,781,450 | `86443cb1b64c006456e524d91082ba25d5ebb0ee5506c6e4d7088350ce251d9d` | `2026-09-01T22:00:03Z` | `2026-09-01T14:54:13Z` | MATCH |
| GlobalPlatformPro v25.10.20 | `gp.jar` | 14,840,623 | `c88e0c5093032ec4571571f5397b6174e56bf632667950fa5bb716338534b122` | `2026-09-01T22:00:03Z` | `2026-09-01T15:28:09Z` | MATCH |

Before any future use, the build procedure must recheck the selected files in
this private bundle against this register. A mismatch stops rather than
substituting another artifact.

## Custody note and remaining gates

The already-registered private V1 transcript `identity-J3R180-02.txt`, 919
bytes, SHA-256
`5b5b08b339fc813462dde6a0080de60d98e9e07d4333cfd5d1fe3b4e3a3cf599`,
was moved into `qk-bench-evidence`; its bytes and hash did not change.

No development card has been procured or authorized. No applet source, build,
CAP comparison, loader experiment, key operation, APDU, or specimen session is
authorized by this register. The first converter run, reproducible-build
procedure, applet dependency guard, development-card procurement, key custody,
protocol row, and every later physical session retain their existing gates.
