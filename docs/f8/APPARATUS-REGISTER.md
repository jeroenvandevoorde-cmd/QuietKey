# F8 Card-Bench Apparatus Register

EXPERIMENTAL - SUPPLIED FACTS AND FIRST ENROLLMENT EVIDENCE REGISTERED

## Current apparatus

The first registered apparatus is the Owner's current macOS bench. One saved
empty-reader enumeration and one zero-APDU enrollment of `J3R180-02` are
registered in `ENROLLMENT-MANIFEST.md`. The operating-system PC/SC layer is an
OS-provided component outside the pinned Rust dependency closure.

- Host alias `iMac`: 3.7 GHz 6-core Intel Core i5, Radeon Pro 580X 8 GB,
  40 GB DDR4, macOS 15.7.7 build 24G720, built-in PC/SC framework.
- Reader alias `SCR3310-01`: Identiv SCR3310 v2.0 contact CCID reader with
  USB-C connector, USB vendor `0x04E6`, USB product `0x5116`, firmware `6.02`,
  bus-powered at 76 mA.
- Hub alias `OWC-HUB-01`: OWC Thunderbolt hub, USB vendor `0x1E91`, USB
  product `0xDE41`, firmware `17.46`.
- Topology: `SCR3310-01` connects through `OWC-HUB-01` to `iMac`.

Reader and hub serial numbers are retained in the private custody bundle and
are not published. Their later private-bundle byte counts and SHA-256 values
bind those raw identifiers to the public aliases. A direct-port connection is
planned for later timing-sensitive work and, if used, is a distinct apparatus
change requiring its own registration.

## Required apparatus fields

| Class | Required record before use |
|---|---|
| CCID reader | Public alias; manufacturer/model; hardware and firmware facts where observable; private serial-map reference; contact path; identification evidence byte count and SHA-256; custody. |
| Host | Public alias; supplied hardware facts; operating-system build; architecture; time source; custody. |
| PC/SC stack | OS-provided implementation/build, reader path, configuration, and bounded enumeration-output hash. |
| Capture tool | Exact locked tool version, source commit, invocation, dependency closure, configuration and executable/script hash. |
| Timing path | Clock API, resolution observation, capture point and overhead-calibration procedure for a later timing run. |
| Power-cut apparatus | Exact aliases and supply, switch, trigger, measurement and restart paths; calibration; residual-power treatment; sacrificial-only assignment for a later run. |
| Raw custody | Private Owner storage alias, custodian, write policy, backup, deterministic naming and manifest procedure. |
| Publication treatment | Raw serials and bundles private; public aliases, counts, hashes, timestamps, tool/source commits, custody paths and ATRs as ratified. |

Every run binds exact apparatus aliases and versions. Swapping a reader, host,
PC/SC layer, tool, cable path or power apparatus creates a distinct environment;
results are not silently pooled.

## Ledger

| Alias | Class | Exact identity | Version/revision | Photo/config manifest | Custody | Approved use | Source commit | Status |
|---|---|---|---|---|---|---|---|---|
| `iMac` | Host and OS PC/SC layer | 3.7 GHz 6-core Intel Core i5; Radeon Pro 580X 8 GB; 40 GB DDR4; built-in PC/SC framework | macOS 15.7.7 (`24G720`) | Saved enumeration and enrollment transcripts registered in `ENROLLMENT-MANIFEST.md` | Owner premises | Empty-reader USB identification and registered zero-APDU enrollment | tool source `4304f379e3ac7ccb0e9299cd0c87bc6c2cd8cf5c` | FACTS AND FIRST ENROLLMENT EVIDENCE REGISTERED |
| `SCR3310-01` | Contact CCID reader | Identiv SCR3310 v2.0; USB-C connector; VID `0x04E6`; PID `0x5116`; bus-powered 76 mA | firmware `6.02` | Enumeration 487 bytes, SHA-256 `ccbc9bd1073c7348161a624ca86c9c01ac008f7971383a479e9f5b27ff2616fe`; private serial bundle remains unregistered | Owner premises | Empty-reader USB identification and exact-reader exclusive zero-APDU enrollment | tool source `4304f379e3ac7ccb0e9299cd0c87bc6c2cd8cf5c` | ENUMERATION AND FIRST CONTACT EVIDENCE REGISTERED; PRIVATE SERIAL HASH PENDING |
| `OWC-HUB-01` | USB topology | OWC Thunderbolt hub; VID `0x1E91`; PID `0xDE41` | firmware `17.46` | Private serial/topology bundle: `PENDING` | Owner premises | Current reader-to-host path only | `PENDING - this register's commit` | FACTS REGISTERED; PRIVATE SERIAL HASH PENDING |

The registered tool source is commit
`4304f379e3ac7ccb0e9299cd0c87bc6c2cd8cf5c`; its executable hash is not
registered. Exact invocation timestamps, enumeration and enrollment transcript
byte counts and SHA-256 values are recorded in `ENROLLMENT-MANIFEST.md`.
