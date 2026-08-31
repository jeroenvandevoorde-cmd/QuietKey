# F8 Enrollment Evidence Manifest

EXPERIMENTAL - ALL THREE ZERO-APDU ENROLLMENT RECORDS REGISTERED

## Current state

One saved reader-enumeration transcript and three complete zero-APDU enrollment
transcripts are registered below. Each specimen has exactly one tool-driven
contact session, in the required order `J3R180-02`, `J3R180-03`, then
`J3R180-01`; specimen 03 followed the committed registration and review of
specimen 02, and protected specimen 01 followed two successful procedures. The
enrollment phase is complete and no further card contact is authorized. The
photograph set exists in Owner custody but remains unhashed and optional under
QK-DEC-148.

## Evidence boundary

Verbatim labeling/package photographs, reader and hub serials, raw enrollment
transcripts, CPLC bytes and future APDU bytes remain in the durable private
Owner bundle. The repository records privacy-safe aliases, deterministic
artifact names, exact byte counts, SHA-256 values, UTC timestamps, tool and
source commits and privacy-safe custody paths. Each specimen ATR is published
verbatim here after its authorized enrollment. Raw byte fields are never
redacted, normalized or reconstructed before hashing.

## Canonical transcript contract

Each private enrollment transcript is LF-terminated ASCII identified as
`QK-CARD-ENROLLMENT-V1`. In fixed schema order it binds:

1. format identifier, allowlist identifier `QK-F8-ENROLL-EMPTY-V1`, and exact
   tool version;
2. the supplied source commit as exactly 40 lowercase hexadecimal characters;
3. UTC timestamp and host, reader and specimen aliases;
4. every enumerated reader-name byte and the selected reader name as lowercase
   hex, one complete octet per pair;
5. each permitted operation in exact execution order with its named outcome;
6. negotiated protocol and ATR bytes as complete lowercase hex;
7. APDU request count `0` and APDU response count `0`;
8. disconnect outcome; and
9. one named final result.

The tool writes only to its caller-supplied output stream and never persists a
file itself. The Owner redirects the exact stream into the private bundle.

## Optional intake-photo bundle

Every photo file receives its own row; aggregate set rows are forbidden because
they would not bind each exact original byte string. The recorded set may remain
unhashed indefinitely; no enrollment or later step waits on this table.

| Artifact alias | Exact private filename | Private location | UTC timestamp | Exact byte count | SHA-256 | Status |
|---|---|---|---|---:|---|---|
| `OPTIONAL - ONE ROW PER PHOTO IF REGISTERED` | `UNHASHED` | Owner iPhone and Owner iCloud | `UNREGISTERED` | `UNREGISTERED` | `UNREGISTERED` | RECORDED PRIVATE-CUSTODY FACT; NOT A CONTACT PRECONDITION |

## Apparatus evidence ledger

| Host alias | Reader alias | Hub/path alias | Private serial-map manifest | USB/enumeration artifact count and hash | Tool version/source commit/hash | UTC timestamp | Status |
|---|---|---|---|---|---|---|---|
| `iMac` | `SCR3310-01` | `OWC-HUB-01` / reader through hub to host | Reader/hub serial map remains private and unregistered | `enumerate-scr3310-01.txt`; 487 bytes; SHA-256 `ccbc9bd1073c7348161a624ca86c9c01ac008f7971383a479e9f5b27ff2616fe`; one reader; name hex `4964656e7469766520534352333378782076322e302055534220534320526561646572` (`Identive SCR33xx v2.0 USB SC Reader`) | `qk-card-enrollment 0.0.1`; source `4304f379e3ac7ccb0e9299cd0c87bc6c2cd8cf5c`; executable hash not registered | `2026-08-31T18:08:17Z` | ENUMERATE PASS; PRIVATE ARTIFACT HASH-BOUND |

Empty-reader USB identification is permitted while evidence fields are
completed. A later direct-port path is a distinct apparatus registration and
must not reuse this row.

## Specimen enrollment ledger

| Required order | Specimen alias | Public ATR bytes | Negotiated protocol | Private transcript artifact | Exact transcript bytes | Transcript SHA-256 | Tool/source commit | UTC timestamp | Private custody path | Result |
|---:|---|---|---|---|---:|---|---|---|---|---|
| 1 | `J3R180-02` | `3bd518ff8191fe1fc38073c821100a` | `T1` | `enroll-J3R180-02.txt` | 705 | `b775efa248b010f8862cc24670319fe6f76373c2c6032a804bda01e3e54d468d` | `qk-card-enrollment 0.0.1`; source `4304f379e3ac7ccb0e9299cd0c87bc6c2cd8cf5c` | `2026-08-31T18:08:17Z` | Private F8 bundle in locked storage at Owner premises | PASS; operations `EnumerateReaders`, `ExclusiveConnect`, `Reset`, `CaptureAtr`, `CaptureProtocol`, `Disconnect` all PASS; APDU tx/rx `0/0` |
| 2 | `J3R180-03` | `3bd518ff8191fe1fc38073c821100a` | `T1` | `enroll-J3R180-03.txt` | 705 | `b442a760c93e81e75f2703ec3a79c7bb179cba62deea02645f024af307872d4e` | `qk-card-enrollment 0.0.1`; source `4304f379e3ac7ccb0e9299cd0c87bc6c2cd8cf5c` | `2026-08-31T19:04:40Z` | Private F8 bundle in locked storage at Owner premises | PASS; operations `EnumerateReaders`, `ExclusiveConnect`, `Reset`, `CaptureAtr`, `CaptureProtocol`, `Disconnect` all PASS; APDU tx/rx `0/0` |
| 3 | `J3R180-01` | `3bd518ff8191fe1fc38073c821100a` | `T1` | `enroll-J3R180-01.txt` | 705 | `cd9fc46a7d1bc9356d6d422d1a9afba4ee3bd88a7b37cfb400e4551330e7cebe` | `qk-card-enrollment 0.0.1`; source `4304f379e3ac7ccb0e9299cd0c87bc6c2cd8cf5c` | `2026-08-31T19:06:43Z` | Private F8 bundle in locked storage at Owner premises | PASS; operations `EnumerateReaders`, `ExclusiveConnect`, `Reset`, `CaptureAtr`, `CaptureProtocol`, `Disconnect` all PASS; APDU tx/rx `0/0` |

## Invocation accounting

- At `2026-08-31T17:34:15Z`, one earlier ENUMERATE invocation printed to the
  terminal but was not saved because its output directory did not exist. It is
  not registered evidence and contacted no card.
- One earlier ENROLL invocation was refused during argument parsing, printed
  the usage message, and never reached the PC/SC layer.
- The three registered ENROLL invocations above are the only tool-driven card
  contacts: exactly one per specimen, ordered 02, 03, then 01. Enrollment is
  complete and no further card contact is authorized.

Any unexpected identity, state, response, result or evidence mismatch stops the
procedure for Owner disposition. It is never explored ad hoc. APDU request and
response counts must remain zero for every record under the active registration.
