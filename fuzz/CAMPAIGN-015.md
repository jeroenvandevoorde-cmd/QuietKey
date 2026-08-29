# V2 slice-9 campaign 015

Status: EXECUTED — QUALIFYING RUN COMPLETE.

Fuzz-target source commit and qualifying-run tree:
`2e0dbb2902b579eda261db8674280cdd4c1df58c`.

The fixed tool identities were cargo-fuzz 0.13.2;
`nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer;
release-profile overflow checks and debug assertions enabled; dependency
resolution offline. The qualifying run started from exactly 35 committed
`qk_host_sim_v2_s9_kit_intake` seeds totaling 105 bytes. They selected all 33
closed scenarios and supplied explicit scanner-spend and fallback-spend
starts. Their 35-entry initial entry-block SHA-256 was
`9046828aa1a1000834b7c538ac588d59c4e58dd97e33121ef93e620629fe51e3`.

The exact qualifying command was:

```text
fuzz/run-bounded.sh qk_host_sim_v2_s9_kit_intake 100000
```

The command fixed seed 129001, maximum length 512, timeout 2 seconds, RSS
limit 2,048 MiB, corpus reload off, AddressSanitizer, and final-stat reporting.
It executed exactly 100,000 inputs in 22 engine seconds at 4,545 executions
per second. It finished at coverage/features 1,058/1,846 with an engine corpus
of 152 files/924 bytes, added 205 engine units, had a zero-second slowest unit,
peaked at 57 MiB RSS, and produced zero artifact files.

Every input longer than 512 bytes was excluded by the fixed target bound.
Each selected scenario ran twice and required the same typed ready, rejection,
or bounded-drop summary. The target exercised both typed Kit doors, both
immutable intake modes, both presentation orders, both share screens, every
foreign-input category and interruption, mode and door reselection, malformed
and checksum-resealed frame precedence, fallback row/column/full/confirm and
CE behavior, same-index/duplicate/wallet-mismatch pairing, invalid starts,
partial-session drops, and a direct 142-byte hostile scanner candidate.

Every ready result required exact door, mode, wallet, presentation-order,
frame-checksum, and next-screen facts, plus a terminal-free consumed session.
Every named rejection required exact name and display text, the exact wiping
terminal reason, a cleared caller scanner buffer, a stable retained failure,
and `Finished` from every later public mutator. Fallback coordinate entry
required exact committed count, pending row, and 57-symbol line/column facts.
Local shares, frames, fallback strings, and the direct scanner candidate were
volatile-wiped and asserted zero before return. No payload, image, camera,
scanner-performance, target, restore, spend, production, or Gate claim was
created.

After the writer exited, the filesystem held 191 files/1,024 bytes and the
artifact directory was empty. Two copies of that post-run corpus were
minimized serially. Both copies progressed identically through 139 files, 134
files, and 132 files, then remained byte-unchanged on the next pass. Their
final sorted `SHA-256<TAB>bytes` inventories were byte-identical: 132 entries,
808 corpus bytes, and listing SHA-256
`f226ad096dc199381137a35a376001685093c5e6585ca2a43113b988e5d8564f`.
No concurrent process wrote either minimization or artifact directory.

That fixed-point set became the persistent corpus. Its manifest entry block
has SHA-256
`6d638f9ca9b4be7191c6aba38bdb8a5590c7276e09b043f9e20529a272aca508`.
`CORPUS-MANIFEST-V2-S9.tsv` is 24,850 bytes/139 LF with SHA-256
`348db9f52be82ab7b9fcde3c42dba2336696e03f418cc7a68c530489828be497`;
its aggregate is 132 files/808 bytes with the same entry-block SHA-256. The
retained set includes a 146-byte unit selecting scenario 27 and delivering all
142 direct caller bytes. The complete cross-partition path, byte-count, and
content-hash check passed.

Retained-corpus replay loaded all 132 files totaling 808 bytes and executed
133 units. It finished at coverage/features 1,058/1,846 with an engine corpus
of 132 files/808 bytes, added zero units, had a zero-second slowest unit,
peaked at 37 MiB RSS, created zero artifact files, and exited zero.

Across qualification, minimization, import, and retained replay, panic,
timeout, sanitizer report, wrong acceptance, wrong named rejection,
door/mode/stage disagreement, pair-identity mismatch, post-rejection work,
caller-buffer wipe assertion, input over-consumption, payload exposure, and
residual fuzz artifact counts were all zero. No product source or target
oracle changed after qualification began.
