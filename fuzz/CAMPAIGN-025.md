# Process slice 6 campaign 025

Status: EXECUTED — QUALIFYING RUN COMPLETE.

The common product-and-fuzz source commit was
`946791b431f36e58e8d8ae52f2395ffa237de22a`. The fixed tool identities were
cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; and offline dependency
resolution. Every run used corpus reload disabled, a two-second input timeout,
a 2,048 MiB RSS ceiling, final-stat reporting and an empty artifact directory.
The exact commands were:

```text
fuzz/run-bounded.sh qk_core_io_peer 100000
fuzz/run-bounded.sh qk_core_session 100000
fuzz/run-bounded.sh qk_core_provisioning_entry 100000
fuzz/run-bounded.sh qk_core_provisioning_run 100000
fuzz/run-bounded.sh qk_core_normal_entry 100000
fuzz/run-bounded.sh qk_core_normal_run 100000
```

Target seeds and maximum inputs were respectively 144001/16,384,
144002/4,096, 145001/1,024, 145002/512, 149001/4,096 and 149002/4,096.

## Pre-qualification target corrections

At source `046b63e6d31fdaed3cdcfece2c8db26d47919c50`,
`qk_core_provisioning_entry` stopped on its first execution because the empty
0-byte unit (SHA-1 artifact id
`da39a3ee5e6b4b0d3255bfef95601890afd80709`, SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`)
observed 828 wiped bytes where the target expected 812. The first correction
replay stopped after 26 executions on the 25-byte unit
`4500004e545222303030303030303030323039222441410ad2` (SHA-1 artifact id
`9aea2bb936fd296fd4500e40f3617565a2ab4885`, SHA-256
`ee490d4c5c23378fc7fd1ca9f378711ed256704b347f0a17650f8a6d6fd7e852`)
after observing 860 wiped bytes where the target expected 844. Four target-only
expectations lagged the session owner's added 16 bytes: active-entry drop
812→828, active-commitment drop 844→860, termination cleanup 412→428 and
transcript-reuse cleanup plus 16. Commit
`86a96fbdb13715fd1c7e8e5b7b65bb169f60b42b` changed exactly those target
expectations; no product source changed.

At source `86a96fbdb13715fd1c7e8e5b7b65bb169f60b42b`,
`qk_core_normal_entry` stopped after 1,057 executions on the 17-byte unit
`0affffffffffffffffffffffffffffffa9` (SHA-1 artifact id
`56c23725804c38e4bb18e6679ea991b3ab4808b6`, SHA-256
`b155da8837cb5246c47ab28867588fe2523f60ec7409c42ae3c710aa28e2b480`)
because hostile input supplied `u32::MAX` as the prior session counter and the
target expected session creation to succeed. Target-only commit
`f152ef127c7c07170dab0a9755b3151e0d6ef4f6` bounded that drop-path counter to
`u32::MAX - 1`; no product source changed.

At source `f152ef127c7c07170dab0a9755b3151e0d6ef4f6`,
`qk_core_normal_run` stopped after 3,453 executions on the 16-byte unit
`24fefffffcff24fefffffcffffffffff` (SHA-1 artifact id
`b1c69946479f13726abdf404197f8e686fa35345`, SHA-256
`3a4127f3ee59c3729b7c9b8de6ab98d163fe47f9d4bb1b8d542ab971d78ab5c9`)
for the same unbounded-counter expectation in its valid and factor-B paths.
Target-only commit `89f8753c2283ed936363757ddafd1856becdd61b` bounded both counters; no
product source changed. Its subsequent run ended at 5,477 executions with no
artifact and was invalidated by the next target change.

Commit `6cf5b8075e4529c842a3d3d814858b44243c9d24` added fold-gated admission,
50 structured seeds and the planned-count guard. No campaign started there:
source review found that the selected media/camera source did not reach every
failure scenario. Commit `946791b431f36e58e8d8ae52f2395ffa237de22a`
threaded that source through all scenarios. Qualifying work began only at that
final source.

## Final-source runs

| Target | Start files/bytes | Seconds; rate/s | Coverage/features | Live files/bytes | New units | Peak RSS MiB | Post-run files/bytes | Artifacts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `qk_core_io_peer` | 35/228 | 8; 12,500 | 757/903 | 35/227 | 1 | 440 | 36/232 | 0 |
| `qk_core_session` | 114/9,217 | 11; 9,090 | 900/2,483 | 113/9,069 | 20 | 492 | 134/12,255 | 0 |
| `qk_core_provisioning_entry` | 247/11,155 | 1,933; 51 | 2,298/3,569 | 249/11,162 | 22 | 474 | 268/12,990 | 0 |
| `qk_core_provisioning_run` | 190/9,520 | 637; 156 | 2,934/4,934 | 194/9,743 | 11 | 342 | 201/10,244 | 0 |
| `qk_core_normal_entry` | 23/67 | 3; 33,333 | 935/1,365 | 58/863 | 53 | 81 | 62/875 | 0 |
| `qk_core_normal_run` | 96/411 | 273; 366 | 4,894/15,074 | 159/2,791 | 127 | 463 | 205/2,931 | 0 |

Each target executed exactly 100,000 inputs and reported a zero-second slowest
unit. The `qk_core_normal_run` total is target inputs, not 100,000 complete
cryptographic flows: inputs outside the deterministic admission fold take the
bounded named pre-ready path. The post-run sorted `SHA-256<TAB>bytes` listing
facts were respectively 2,416 bytes/
`5a6b22681a307e8e7a0478d111e314e92800dbfbc009c04b2d3403a509a3c1db`,
9,111 bytes/`9bf816146d7faeaa7ef02cc0009fe184d13b0afb353f1fcfcfa68293d4098304`,
18,243 bytes/`0b8aebb01b4f1d4d7cbe955ddabec93554d7c4a859e8539f3ff4a462c5c53319`,
13,675 bytes/`4448ae1910719d81c009780161b419a1c64a4fa422ebd322a1a26ae917e3ca31`,
4,189 bytes/`759248bdd79e4c71ff2f228dc7e5c2b6b0e1fe3a5d91d959caefe387becab1ec`
and 13,821 bytes/
`c620bb6a257b04185cf9769173344a51bfbf42f6232bb11f117bab0105d7e453`.

## Two-copy minimization and registration

Two copies of every post-run corpus were minimized separately. Both copies
followed the same progression, reached an unchanged confirmation pass and
agreed byte for byte:

- `qk_core_io_peer`: 36 files/232 bytes remained unchanged; final listing
  2,416 bytes, SHA-256
  `5a6b22681a307e8e7a0478d111e314e92800dbfbc009c04b2d3403a509a3c1db`.
- `qk_core_session`: 134/12,255 → 114/9,072 → unchanged; final listing 7,739
  bytes, SHA-256
  `cd38dd82aaedc960aa3f411b2ba8b6ff10e30c545a7c73504bb699f070199f8c`.
- `qk_core_provisioning_entry`: 268/12,990 → 248/11,023 → 247/10,994 →
  unchanged; final listing 16,806 bytes, SHA-256
  `cc0ac1a1210e958865e027c5496b1649020b30918ffe16a9622a6dc73ff12a3a`.
- `qk_core_provisioning_run`: 201/10,244 → 194/9,616 → 192/9,556 →
  191/9,526 → unchanged; final listing 12,993 bytes, SHA-256
  `4e6854479bfe1b0e2c345996fa0c930366e33c3d60a19ccdea6aa958976a70b9`.
- `qk_core_normal_entry`: 62/875 → 55/800 → 54/781 → unchanged; final
  listing 3,649 bytes, SHA-256
  `6483d31a77155217b2e07f23015ca2b3a80886df687f93a3a3375625921233f0`.
- `qk_core_normal_run`: 205/2,931 → 144/2,306 → 143/2,300 → 142/2,295
  → unchanged; final listing 9,589 bytes, SHA-256
  `d458222814b9676d5b805b35a9978124f0b6d4765fe6e342d9c39df61d9e5b3e`.

The predecessor PROCESS-S4 target entry hashes were
`322481cfab35c36da25d81bbf0a98272bf51bf8735c786aec6d8eb006eba9434`
and `706bab5fbe927cdf66f5439ab27ff701578d5369f5d7c53cb1ad99cf7c49166f`;
its aggregate was 149 files/9,445 bytes with entry SHA-256
`8cc5887300434b9f42250bfbe7b32d4f8caf9e3dbcb6a6b9e00ad690cac4b6e0`.
The predecessor manifest was 24,333 bytes/157 LF with SHA-256
`e24047c32e582c3631e4ff3e249787096b5b8ac266ebb985185de5e36389d96f`.
The predecessor PROCESS-S5 target entry hashes were
`9182722863e5b8cd9c68cc4f5b6f24af4ff2e77708c62ec7d896726db2dd2081`
and `0e89c276922177a5ccb4c7351acd5d2779492707afa6ebfc467a5a1a22650bfc`;
its aggregate was 437 files/20,675 bytes with entry SHA-256
`5c5c2823fcca36bc7508c2183c496be0a3ee71b7b6f7d82df2fe69a6795afd94`.
The predecessor manifest was 79,374 bytes/445 LF with SHA-256
`36953ec4112ae9bf01f8aba6b47d389757de9ef1d37443ed327b3c4ffc8fe6c8`.
The preregistered PROCESS-S6 start was 119 files/478 bytes with entry SHA-256
`e191a95ad273833b2aeb2375f42db8aae70c6b6f2eac0edfa3c9bc926936157f`.

The rendered manifests all bind campaign source
`946791b431f36e58e8d8ae52f2395ffa237de22a`:

| Partition | Target facts | Aggregate facts | Manifest bytes/LF/SHA-256 |
|---|---|---|---|
| PROCESS-S4 | `qk_core_io_peer` 36/232/`a9ce239a7d67870d797d69b92ebcba48b03d26899457e9f607f6e5af5e422d73`; `qk_core_session` 114/9,072/`2d9c2a58dbc9293869b7210dec21b88d18bb2d8bf73b44d747bb458d644716e7` | 150/9,304/`6a0787415520338b4b52d731c99d8baecfedaf545fba0d44d58a5d70daea0d6e` | 24,492/158/`5a867a5c37f5258e8414e1f81458c867480c2433afa3e1f1953296627497bb3b` |
| PROCESS-S5 | `qk_core_provisioning_entry` 247/10,994/`5a4023dbb5f10afa70d7ee8572d0a2fdb1d4e9ba351aa16fdd9dd5551b5cfe41`; `qk_core_provisioning_run` 191/9,526/`d02641974628c2841ca01be55d513b954c9c3e4a79f932bc8e8b9aabf7f5e775` | 438/20,520/`956643b36d9a0a58c3fe5afcc094d206927dc5b5d8679caf4d28ec40b5c8146a` | 79,548/446/`851ee04574cfcfd9f2e7d65a52b0567cedb917ebcb55d75b8571ab5b0c1ec8a7` |
| PROCESS-S6 | `qk_core_normal_entry` 54/781/`d10873dedc420d2f80922e614c771b45d5493c94f253f5ccbf77a5b553916237`; `qk_core_normal_run` 142/2,295/`9be81e64366d44f6ba00b6679c34b88d93835d2b81c1e6e0711c7b271c160a93` | 196/3,076/`cad081d5d1d61862fce6a6811abf2c542e6e0d69dfb7c15f7df309c7a649e65e` | 33,215/204/`20d781ca74756620095a5c8ae62bdf39a24f149661b8fda9b1b3f965a0aa7059` |

## Final-tree retained-corpus replay

Replay G1 loaded 1,643 files/128,638 bytes across 11 corpora and executed
1,660 units. G2 loaded 1,795 files/97,898 bytes across 11 corpora and executed
1,807 units. G3 loaded 1,701 files/116,485 bytes across 11 corpora and executed
1,713 units. Each added zero units, created zero artifacts and exited zero.

| G4 target | Loaded files/bytes | Executed units |
|---|---:|---:|
| `qk_io_session` | 399/19,921 | 400 |
| `qk_psbt` | 164/42,417 | 165 |
| `qk_core_provisioning_entry` | 247/10,994 | 248 |
| `qk_bbqr_reassembly` | 186/12,570 | 187 |
| `qk_host_sim_m29` | 185/4,933 | 186 |
| `qk_host_sim_v2_s5_screen` | 132/6,912 | 133 |
| `qk_core_normal_run` | 142/2,295 | 143 |
| `qk_host_sim_v2_s9_kit_intake` | 132/808 | 133 |
| `qk_provisioning_v2_chain` | 110/556 | 111 |
| `qk_a1` | 38/1,438 | 39 |
| `qk_update_lifecycle` | 33/143 | 35 |

G4 loaded 1,768 files/102,987 bytes and executed 1,780 units. It added zero
units, created zero artifacts and every target exited zero. Across all 44
retained corpora, 6,907 files/446,008 bytes executed 6,960 replay units, with
zero additions, zero artifacts and zero nonzero exits.

The entry oracle covered explicit profile bytes, both hostile PSBT sources,
fragmentation and coalescing, state ordering, every terminating interruption,
repeat consistency, terminal absorption, drop and wipe accounting. The run
oracle covered the public NEVER-FUND normal flow through purpose-bound A1 and
mock-card-B facts, descriptor and wallet rebinding, schema-v3 review identity,
every review position, approval hold, reparse, terminal A signing, checked
mock-B insertion, two-key finalization, exact finalized and raw bytes, txid,
wtxid, profile-permitted SD and BBQr routes, filenames, receipts, selected
BBQr geometry and reassembly, route delivery order, partial two-artifact
completion, named terminal outcomes, deterministic repetition and cleanup
accounting. No product source or target oracle changed after qualification
began at `946791b431f36e58e8d8ae52f2395ffa237de22a`.
