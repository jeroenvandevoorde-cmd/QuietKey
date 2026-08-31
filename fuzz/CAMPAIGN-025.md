# Process slice 6 campaign 025

Status: PLANNED — NOT EXECUTED.

QK-DEC-149 reserves this campaign for the final process-slice-6 source tree. The common source commit will be recorded before execution and will contain the product code, tests, both new fuzz targets, fixed public starting seeds, runner and dependency guards, and this plan. Any later product or target change invalidates every run in the campaign.

## Targets and fixed runs

All runs use cargo-fuzz 0.13.2, `nightly-2026-08-25`, AddressSanitizer, overflow checks, debug assertions, an empty artifact directory, and exactly 100,000 executions:

| Target | Classification | Command | Seed | Maximum input |
|---|---|---|---:|---:|
| `qk_core_io_peer` | requalify: qk-core normal-flow additions compile into its closure | `fuzz/run-bounded.sh qk_core_io_peer 100000` | 144001 | 16384 |
| `qk_core_session` | requalify: the session enum and shared termination paths changed | `fuzz/run-bounded.sh qk_core_session 100000` | 144002 | 4096 |
| `qk_core_provisioning_entry` | requalify: qk-core normal-flow additions compile into its closure | `fuzz/run-bounded.sh qk_core_provisioning_entry 100000` | 145001 | 1024 |
| `qk_core_provisioning_run` | requalify: qk-core normal-flow additions compile into its closure | `fuzz/run-bounded.sh qk_core_provisioning_run 100000` | 145002 | 512 |
| `qk_core_normal_entry` | qualify: new hostile entry and state-order target | `fuzz/run-bounded.sh qk_core_normal_entry 100000` | 149001 | 4096 |
| `qk_core_normal_run` | qualify: new complete normal-wallet flow and export target | `fuzz/run-bounded.sh qk_core_normal_run 100000` | 149002 | 4096 |

The normal-run target reserves leading bytes `41..59` for its 25 complete
structured scenarios in order and admits one input only when the byte fold
starting at `6d` and updating as `state = state * 33 XOR byte` modulo 256 ends
at zero. Every other input takes a bounded named pre-ready rejection with
repeat and wipe checks. Two fold-valid public starting units per structured
scenario select media/no-repeat and camera/repeat, so every scenario and both
transport branches execute before mutation begins. The campaign count is
target inputs, not 100,000 complete cryptographic flows.

Each post-run corpus is copied twice outside Git. Both copies are minimized separately to an unchanged fixed point and must agree byte for byte. Agreement on a changed requalified fixed point promotes it under QK-DEC-146, recording the prior registered entry hash here; disagreement stops for Owner disposition. The new targets are registered only after the same two-copy agreement.

After promotion, all 44 registered corpora replay on the final tree. Any panic, timeout, sanitizer report, wrong acceptance, unnamed rejection, repeat mismatch, wipe mismatch, artifact, minimization disagreement, or second-copy mismatch stops publication. Completed run, minimization, partition, and replay facts replace this planned record.
