# M23 campaign 003

Fuzz-target source commit: `e86e0b6db79f7e31317982c992c7de7c673e7a4d`.
Executed tree and committed-seed source:
`b540fe93e93c4cc1d3ed2151a450475068141479`.

Tool identities: cargo-fuzz 0.13.2; `nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer; release-profile
overflow checks and debug assertions enabled; dependency resolution offline.

The campaign started from 14 committed public seeds totaling 46 bytes: six
for `qk_psbt_m23` and eight for `qk_host_sim_m23`. The executed command for
each target was
`PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/run-bounded.sh TARGET 100000`.
The runner supplied the fixed seed and maximum length shown below, timeout 2 s,
RSS limit 2,048 MiB, corpus reload disabled, and an empty per-target artifact
directory.

| Target | Seed | Max bytes | Executed | Final cov/ft | Engine corpus | Post-run files/bytes | New units | Peak RSS MiB | Artifact files | Timeouts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `qk_psbt_m23` | 23001 | 4,096 | 100,000 | 1,884/2,824 | 287/4,960 B | 292/4,981 B | 494 | 459 | 0 | 0 |
| `qk_host_sim_m23` | 23002 | 4,096 | 100,000 | 2,021/3,422 | 279/5,246 B | 287/5,276 B | 543 | 470 | 0 | 0 |

Total executed inputs: 200,000. Post-run filesystem inventory: 579 files,
10,257 bytes. Finding artifacts: 0. Timeouts: 0. Product-code findings: 0.

For each target, the post-run directory was copied twice and each copy was
processed by `PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH
fuzz/minimize-corpus.sh TARGET COPY`. Both copies produced the same sorted
`SHA-256<TAB>bytes` content set. One copy became the persistent corpus.

| Target | Minimized files | Bytes | Minimized content-set SHA-256 | Manifest entry-block SHA-256 |
|---|---:|---:|---|---|
| `qk_psbt_m23` | 253 | 4,494 | `532c48fdfb50f19b2317d72e8824cf81e21cc3a74a1c8b627775a86be85838e2` | `b12ee515296eb77b2328d53f33b90519f9f33fd31f3f843a3141dbea1e8e3d94` |
| `qk_host_sim_m23` | 246 | 4,769 | `c60744d805739a1220f93a07d46281834edc43890d8634a660fcf3a70c96965b` | `e7eaa83c06addb1821a1f6a556809ef87e3a1fe8bc887848d1fd8ca313b84435` |

The retained inventory is 499 files and 9,263 bytes. Its exact entry block is
SHA-256 `0f796fd770862089585378050c2ffa3954cf4fdcd616ee2bace3182d712168fb`.
`CORPUS-MANIFEST-M23.tsv` is 78,031 bytes/507 LF, SHA-256
`094e1206fb95da54faac40b72e6259ed10d91e3381570ad5f6179b63c939eaeb`.

`PATH=/private/tmp/qk-cargo-fuzz/bin:$PATH fuzz/replay-corpus.sh TARGET`
then loaded 253 and 246 retained files for `qk_psbt_m23` and
`qk_host_sim_m23` and executed 255 and 248 units, respectively. The PSBT
replay reported engine corpus 245/4,435 B, cov/ft 1,884/2,824, and peak RSS
42 MiB. The workflow replay reported engine corpus 238/4,699 B, cov/ft
2,021/3,422, and peak RSS 44 MiB. Both replays exited zero and left zero
artifact files.

No product source file changed during campaign execution, minimization,
registration, or replay.
