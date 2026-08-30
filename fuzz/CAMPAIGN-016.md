# V2 slice-10 campaign 016

Status: EXECUTED — QUALIFYING RUN COMPLETE.

Fuzz-target source commit and qualifying-run tree:
`384bcdb0a5bf6658ee01b8d04d38886928260a6a`.

The fixed tool identities were cargo-fuzz 0.13.2;
`nightly-2026-08-25`; rustc
`1.100.0-nightly (e7769602a 2026-08-24)`; AddressSanitizer;
release-profile overflow checks and debug assertions enabled; dependency
resolution offline. The qualifying run started from exactly 74 committed
`qk_host_sim_v2_s10_kit_restore` seeds, each 20 bytes and totaling 1,480
bytes. They selected all 23 closed scenarios and supplied explicit variants
for all ten assertion digits, both actions, both input modes, both frame
orders, all six reachable interruption stages, all eight interruption events,
all ten foreign-operation classes, all four surviving-B mismatch classes,
and partial-owner drops. Their initial entry-block SHA-256 was
`00bbec54dbee0b9ce612d5fc5b89c595683524c2c9e0f4f66758ad2ee6aa61dd`.

The exact qualifying command was:

```text
fuzz/run-bounded.sh qk_host_sim_v2_s10_kit_restore 100000
```

The command fixed seed 130001, maximum length 512, timeout 2 seconds, RSS
limit 2,048 MiB, corpus reload off, AddressSanitizer, and final-stat reporting.
It executed exactly 100,000 inputs in 188 engine seconds at 531 executions per
second. It finished at coverage/features 2,136/2,604 with an engine corpus of
77 files/1,644 bytes, added 77 engine units, had a zero-second slowest unit,
peaked at 105 MiB RSS, and produced zero artifact files. The post-run
filesystem corpus held 130 files/2,686 bytes.

Every input longer than 512 bytes was excluded by the fixed target bound. A
rolling-byte selector kept the full registered-fixture intake, wallet rebind,
and restore path sparse; non-selected inputs exercised the exact
`InvalidHumanAssertionDigit` rejection twice. Every selected scenario also
ran twice and required byte-equal typed summaries. Successful replacement-B
and A1-reprint paths required the exact input mode, presentation-order frame
identities, wallet ID, one sink call, public receipt facts, and the exact
`MandatoryFreshWalletMigrationV2::Required` posture. A1 reprint additionally
required a caller nonce different from the registered old nonce, a different
authenticated capsule, an exact scan-back, and the receipt's exact capsule
SHA-256.

Rejection paths required the exact error name and display text, the exact
wiping terminal reason where the session remained observable, no sink call
before all branch preconditions and the matching screen digit, and stable
`Finished` behavior after termination. The target exercised Kit-Spend-door
rejection, exact-D mismatch, action and branch mismatch, missing old-card
routing, surviving-A1 and every surviving-B fact mismatch, all assertion
digits, wrong and cancel keys, both sink rejections, scan-back mismatch, every
interruption from all six stage/action owners, every prohibited operation,
and drops before and after branch preparation. Caller A1, A2, local capsule,
and reference-decryption scratch were volatile-wiped and asserted zero where
owned by the target. No recovered payload, signing route, normal-wallet
continuation, second sink call, post-terminal work, or non-migration success
was accepted.

Two copies of the post-run corpus were minimized serially. Both copies
progressed through 71 files/1,536 bytes and listing SHA-256
`b0828d9258892dd1048ee3d84f5e286326af97487aca34603fd106b43ce9ab36`,
then 69 files/1,507 bytes and listing SHA-256
`20bef9bdf438e2e886c472eafd6c8305e05cdd8eef70c94e170bb2a199c0a636`,
then remained byte-unchanged on the next pass. Each listing is the sorted
`SHA-256<TAB>bytes` inventory; the fixed-point listing is 4,685 bytes. No
concurrent process wrote either minimization or artifact directory.

That byte-identical fixed-point set became the persistent corpus. Its manifest
entry block has SHA-256
`4540070120f47dc8284ad0f10543c9f80d24667834651fe0cb5f96a6d9113591`.
`CORPUS-MANIFEST-V2-S10.tsv` is 13,526 bytes/76 LF with SHA-256
`30b211da3658e2ce470044a8756303bf8b025186e1d7d90cd70623643aa379a5`;
its aggregate is 69 files/1,507 bytes with the same entry-block SHA-256. The
complete cross-partition path, byte-count, and content-hash check passed.

Retained-corpus replay loaded all 69 files totaling 1,507 bytes and executed
70 units. It finished at coverage/features 2,136/2,604 with an engine corpus
of 67 files/1,479 bytes, added zero units, had a zero-second slowest unit,
peaked at 42 MiB RSS, created zero artifact files, and exited zero.

Across qualification, minimization, import, and retained replay, panic,
timeout, sanitizer report, wrong acceptance, wrong named rejection, door,
action, descriptor, digit or stage disagreement, sink-count mismatch,
post-terminal work, non-migration success, ordinary-exit caller-buffer
residue, and fuzz artifact counts were all zero. No product source or target
oracle changed after qualification began.
