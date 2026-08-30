# V2 slice-11 campaign 017

Status: EXECUTED — QUALIFYING RUN COMPLETE.

Fuzz-target source commit and qualifying-run tree:
`3befa450a936362f881ba13f64e2bf9938d8af28`.

The fixed tool identities were cargo-fuzz 0.13.2;
`nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer;
release-profile overflow checks and debug assertions enabled; dependency
resolution offline. The qualifying run started from exactly 440 deterministic
public `qk_host_sim_v2_s11_kit_spend` seed units totaling 24,432 bytes, with a
maximum unit length of 78 bytes. They selected all 28 closed scenarios, both
intake modes, both share-presentation orders, all ten assertion digits, both
old-descriptor branches, first/middle/last foreign-input positions, all eight
interruption classes at all three reachable stages, all eleven foreign
operations at all three stages, all three partial-owner drop stages, the QR
input-source path, and all four hostile-PSBT construction modes and shapes.
Their initial manifest-style entry-block SHA-256 was
`f6af30b7269c4f06356b34ab7f826ad0a93ed284df2a880c6a5d3516490b752a`.

The exact qualifying command was:

```text
fuzz/run-bounded.sh qk_host_sim_v2_s11_kit_spend 100000
```

The command fixed seed 131001, maximum length 512, timeout 2 seconds, RSS
limit 2,048 MiB, corpus reload off, AddressSanitizer, and final-stat reporting.
It executed exactly 100,000 inputs in 310 engine seconds at 322 executions per
second. It finished at coverage/features 4,317/7,092 with an engine corpus of
121 files/7,719 bytes, added 97 engine units, had a zero-second slowest unit,
peaked at 206 MiB RSS, and produced zero artifact files. The post-run
filesystem corpus held 512 files/29,862 bytes.

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
progressed through 113 files/7,225 bytes and listing SHA-256
`673a97077d5d121d72aeabfcdc8b42ebdaddd113f9883cdf1e8b81360295eaa9`,
then 110 files/7,038 bytes and listing SHA-256
`42fa6aa89206ac3ecf4e04e0f1f45144e7bfc94874dc7f0bf74e626a3fad2e3c`,
then remained byte-unchanged on the next pass. Each listing is the sorted
`SHA-256<TAB>bytes` inventory; the fixed-point listing is 7,496 bytes. No
concurrent process wrote either minimization or artifact directory.

That byte-identical fixed-point set became the persistent corpus. Its manifest
entry block has SHA-256
`2ce187aed1644771a98a48cf26d16c1286554564c39758da2a8887a340d5004d`.
`CORPUS-MANIFEST-V2-S11.tsv` is 20,897 bytes/117 LF with SHA-256
`d99435a243f9fa4dcfce45db28dd24da8eb1e28c6a3b734e98c222bf1716f3b0`;
its aggregate is 110 files/7,038 bytes with the same entry-block SHA-256. The
complete cross-partition path, byte-count, and content-hash check passed.

Retained-corpus replay loaded all 110 files totaling 7,038 bytes and executed
111 units. It finished at coverage/features 4,317/7,092 with an engine corpus
of 108 files/6,959 bytes, added zero units, had a zero-second slowest unit,
peaked at 49 MiB RSS, created zero artifact files, and exited zero.

Across qualification, minimization, registration, and retained replay, panic,
timeout, sanitizer report, wrong acceptance, wrong named rejection,
door/mode/stage/descriptor/destination/digit disagreement, callback/sign/
finalize-count mismatch, second capability, post-terminal work, caller-buffer
residue, and fuzz artifact counts were all zero. No product source or target
oracle changed after qualification began.
