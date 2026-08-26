#!/bin/sh
set -eu

[ "$#" = 1 ] || { printf 'usage: %s TARGET\n' "$0" >&2; exit 2; }
target=$1
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
  *) printf 'unknown target: %s\n' "$target" >&2; exit 2 ;;
esac

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
[ -d "fuzz/corpus/$target" ] || { printf 'missing corpus for %s\n' "$target" >&2; exit 2; }
mkdir -p "fuzz/artifacts/$target"
if find "fuzz/artifacts/$target" -type f -print -quit | grep -q .; then
  printf 'artifact directory is not empty: fuzz/artifacts/%s\n' "$target" >&2
  exit 2
fi

export CARGO_NET_OFFLINE=true
exec cargo +nightly-2026-08-25 fuzz run "$target" "fuzz/corpus/$target" \
  --fuzz-dir fuzz --sanitizer address -- \
  -runs=0 "-seed=$seed" "-max_len=$max_len" -reload=0 -timeout=2 \
  -rss_limit_mb=2048 -print_final_stats=1 \
  "-artifact_prefix=fuzz/artifacts/$target/"
