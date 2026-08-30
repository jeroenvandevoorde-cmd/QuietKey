# V2 slice-11 campaign 017

Status: EXECUTED — QUALIFYING RUN COMPLETE.

Fuzz-target source commit and qualifying-run tree:
`404626a5caa552d32090120f331cb3686cd99510`.

The fixed tool identities were cargo-fuzz 0.13.2;
`nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer;
release-profile overflow checks and debug assertions enabled; dependency
resolution offline. The qualifying run started from exactly 110 registered
public `qk_host_sim_v2_s11_kit_spend` units totaling 7,038 bytes, with unit
lengths from 1 through 266 bytes. Their registered entry-block SHA-256 was
`2ce187aed1644771a98a48cf26d16c1286554564c39758da2a8887a340d5004d`.
The target's closed scenario table spans all 28 scenarios, both intake modes,
both share-presentation orders, all ten assertion digits, both old-descriptor
branches, first/middle/last foreign-input positions, all eight interruption
classes at all three reachable stages, all eleven foreign operations at all
three stages, all three partial-owner drop stages, the QR input-source path,
and all four hostile-PSBT construction modes and shapes.

The exact qualifying command was:

```text
fuzz/run-bounded.sh qk_host_sim_v2_s11_kit_spend 100000
```

The command fixed seed 131001, maximum length 512, timeout 2 seconds, RSS
limit 2,048 MiB, corpus reload off, AddressSanitizer, and final-stat reporting.
It executed exactly 100,000 inputs in 244 engine seconds at 409 executions per
second. It finished at coverage/features 4,326/7,116 with an engine corpus of
120 files/7,922 bytes, added 33 engine units, had a zero-second slowest unit,
peaked at 173 MiB RSS, and produced zero artifact files. The post-run
filesystem corpus held 141 files/9,324 bytes.

Every input longer than 512 bytes was excluded by the fixed target bound. A
rolling-byte selector kept complete slice-9 readiness, recovered-wallet
rebind, schema-v3 review, A/B signing, and finalization sparse; non-selected
inputs exercised the exact `InvalidHumanAssertionDigit` rejection twice.
Every selected scenario also ran twice and required byte-equal typed result
and execution-trace summaries. Success required the exact intake mode and
share order, old and replacement wallet identities, receive index, review
hash, finalized-PSBT and raw-transaction hashes, txid and wtxid, zero callback
calls, exactly one signing call, exactly one finalization call, and the
`CompletedWiped` terminal.

Rejection paths required the exact error name and display text, the exact
wiping terminal where observable, zero signing and finalization calls, stable
post-terminal behavior, and a zeroed caller PSBT after submission. The target
exercised wrong-door and recovered-wallet mismatch; invalid, unchanged, and
wrong-route replacement descriptors; zero and two outputs; old receive and
change outputs; OP_RETURN, P2WPKH, and P2TR destinations; wrong P2WSH
commitment; invalid existing signatures; first, middle, and last foreign
inputs; missing, mismatched, cancelled, and repeated completeness actions;
every interruption and foreign operation at every stage; a second sweep;
premature and repeated completeness statements; every partial-owner drop;
the QR input-source path; and bounded hostile PSBT bytes. No callback signer,
generic Kit signing method, second finalized transaction, normal-wallet
continuation, restore, regeneration, export, approval, or post-terminal work
was accepted.

Two copies of the post-run corpus were minimized serially. Both copies
progressed through 116 files/7,718 bytes and listing SHA-256
`5313916041c3fb6748c690b095a03c5f9e72a612b0f4745c2f745f1a5c582d2e`,
then 115 files/7,640 bytes and listing SHA-256
`b81c162a3507cfd67fc187f02a6d4e1e1a1058de2c3bdc776d6a4fb6168debd2`,
then remained byte-unchanged on the next pass. Each listing is the sorted
`SHA-256<TAB>bytes` inventory; the fixed-point listing is 7,838 bytes. No
concurrent process wrote either minimization or artifact directory.

That byte-identical fixed-point set became the persistent corpus. Its manifest
entry block has SHA-256
`f59701fb0c717d618c863b4b32332c581b73661432c1de0174c233bee96e3a09`.
`CORPUS-MANIFEST-V2-S11.tsv` is 21,829 bytes/122 LF with SHA-256
`af8e7d996049bbd7e7fe6650f5c7288322deddaed04fc2ade28e6dadc602b173`;
its aggregate is 115 files/7,640 bytes with the same entry-block SHA-256. The
complete cross-partition path, byte-count, and content-hash check passed.

Retained-corpus replay loaded all 115 files totaling 7,640 bytes and executed
116 units. It finished at coverage/features 4,326/7,116 with an engine corpus
of 114 files/7,639 bytes, added zero units, had a zero-second slowest unit,
peaked at 50 MiB RSS, created zero artifact files, and exited zero.

Across qualification, minimization, registration, and retained replay, panic,
timeout, sanitizer report, wrong acceptance, wrong named rejection,
door/mode/stage/descriptor/destination/digit disagreement, callback/sign/
finalize-count mismatch, second capability, post-terminal work, caller-buffer
residue, and fuzz artifact counts were all zero. No product source or target
oracle changed after qualification began.
