#!/bin/sh
set -eu

[ "$#" = 2 ] || { printf 'usage: %s TARGET CORPUS_DIRECTORY\n' "$0" >&2; exit 2; }
target=$1
corpus=$2
case "$target" in
  qk_psbt) max_len=4096 ;;
  qk_descriptor) max_len=891 ;;
  qk_a1) max_len=96 ;;
  qk_a1_codec) max_len=512 ;;
  qk_card_trace) max_len=4096 ;;
  qk_bbqr_codec) max_len=4297 ;;
  qk_bbqr_reassembly) max_len=16384 ;;
  qk_psbt_m23) max_len=4096 ;;
  qk_host_sim_m23) max_len=4096 ;;
  qk_host_sim_m24) max_len=4096 ;;
  qk_host_sim_m25) max_len=4096 ;;
  qk_provisioning_inputs_m26) max_len=1024 ;;
  qk_provisioning_chain_m26) max_len=512 ;;
  qk_host_sim_m27) max_len=1024 ;;
  qk_host_sim_m28) max_len=4096 ;;
  qk_host_sim_m29) max_len=1024 ;;
  qk_bbqr_m30) max_len=4297 ;;
  qk_host_sim_m30) max_len=4096 ;;
  qk_provisioning_v2_inputs) max_len=1024 ;;
  qk_provisioning_v2_chain) max_len=512 ;;
  qk_host_sim_v2_s5_screen) max_len=2048 ;;
  qk_host_sim_v2_s5_manual_keypad) max_len=1024 ;;
  qk_host_sim_v2_s6_watch_only) max_len=4096 ;;
  *) printf 'unknown target: %s\n' "$target" >&2; exit 2 ;;
esac
[ -d "$corpus" ] || { printf 'missing corpus directory: %s\n' "$corpus" >&2; exit 2; }

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
exec cargo +nightly-2026-08-25 fuzz cmin "$target" "$corpus" \
  --fuzz-dir fuzz --sanitizer address -- \
  "-max_len=$max_len" -timeout=2 -reload=0
