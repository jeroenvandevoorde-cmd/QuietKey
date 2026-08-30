#!/bin/sh
set -eu

[ "$#" = 2 ] || { printf 'usage: %s TARGET TEST_CASE\n' "$0" >&2; exit 2; }
target=$1
test_case=$2
case "$target" in
  qk_psbt) max_len=4096; seed=21001 ;;
  qk_descriptor) max_len=891; seed=21002 ;;
  qk_a1) max_len=96; seed=21003 ;;
  qk_a1_codec) max_len=512; seed=21004 ;;
  qk_card_trace) max_len=4096; seed=21005 ;;
  qk_bbqr_codec) max_len=4297; seed=22001 ;;
  qk_bbqr_reassembly) max_len=16384; seed=22002 ;;
  qk_psbt_m23) max_len=4096; seed=23001 ;;
  qk_host_sim_m23) max_len=4096; seed=23002 ;;
  qk_host_sim_m24) max_len=4096; seed=24001 ;;
  qk_host_sim_m25) max_len=4096; seed=25001 ;;
  qk_provisioning_inputs_m26) max_len=1024; seed=26001 ;;
  qk_provisioning_chain_m26) max_len=512; seed=26002 ;;
  qk_host_sim_m27) max_len=1024; seed=27001 ;;
  qk_host_sim_m28) max_len=4096; seed=28001 ;;
  qk_host_sim_m29) max_len=1024; seed=29001 ;;
  qk_bbqr_m30) max_len=4297; seed=30001 ;;
  qk_host_sim_m30) max_len=4096; seed=30002 ;;
  qk_provisioning_v2_inputs) max_len=1024; seed=124001 ;;
  qk_provisioning_v2_chain) max_len=512; seed=124002 ;;
  qk_host_sim_v2_s5_screen) max_len=2048; seed=125001 ;;
  qk_host_sim_v2_s5_manual_keypad) max_len=1024; seed=125002 ;;
  qk_host_sim_v2_s6_watch_only) max_len=4096; seed=126001 ;;
  qk_kit_v2_s7_codec) max_len=512; seed=127001 ;;
  qk_kit_v2_s7_combine) max_len=512; seed=127002 ;;
  qk_provisioning_v2_s8_kit_setup) max_len=512; seed=128001 ;;
  qk_host_sim_v2_s9_kit_intake) max_len=512; seed=129001 ;;
  qk_host_sim_v2_s10_kit_restore) max_len=512; seed=130001 ;;
  *) printf 'unknown target: %s\n' "$target" >&2; exit 2 ;;
esac
[ -f "$test_case" ] || { printf 'missing test case: %s\n' "$test_case" >&2; exit 2; }

root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 2
cd "$root"
[ "$(cargo fuzz --version)" = 'cargo-fuzz 0.13.2' ] || {
  printf 'cargo-fuzz 0.13.2 is required\n' >&2
  exit 2
}
[ "$(rustc +nightly-2026-08-25 --version)" = \
  'rustc 1.100.0-nightly (e7769602a 2026-08-24)' ] || {
  printf 'nightly-2026-08-25 toolchain identity mismatch\n' >&2
  exit 2
}

export CARGO_NET_OFFLINE=true
exec cargo +nightly-2026-08-25 fuzz tmin --runs 10000 "$target" "$test_case" \
  --fuzz-dir fuzz --sanitizer address -- \
  "-seed=$seed" "-max_len=$max_len" -timeout=2 -rss_limit_mb=2048
