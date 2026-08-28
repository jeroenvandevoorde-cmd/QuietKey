#!/bin/sh
# Recompute and verify the partitioned QK-DEC-106/QK-DEC-109..113/QK-DEC-116/QK-DEC-118 corpus registries.
set -u

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    return 1
  fi
}

size_file() {
  if stat -f '%z' "$1" >/dev/null 2>&1; then
    stat -f '%z' "$1"
  elif stat -c '%s' "$1" >/dev/null 2>&1; then
    stat -c '%s' "$1"
  else
    return 1
  fi
}

validate_source_commit() {
  source_commit=$1
  case "$source_commit" in
    *[!0-9a-f]*|'') fail 'campaign_source must be lowercase hexadecimal' ;;
  esac
  [ "${#source_commit}" = 40 ] || \
    fail 'campaign_source must be a full 40-character commit id'
}

manifest_source() {
  manifest=$1
  source_count=$(awk -F '\t' \
    '$1 == "campaign_source" { count++ } END { print count + 0 }' "$manifest") || \
    fail "cannot inspect campaign_source in $manifest"
  [ "$source_count" = 1 ] || fail "$manifest must contain one campaign_source row"
  source_commit=$(awk -F '\t' '$1 == "campaign_source" { print $2 }' "$manifest") || \
    fail "cannot read campaign_source from $manifest"
  validate_source_commit "$source_commit"
  printf '%s\n' "$source_commit"
}

emit_directory() {
  class=$1
  target=$2
  directory=$3
  required=$4
  if [ ! -d "$directory" ]; then
    [ "$required" = no ] && return 0
    fail "required corpus directory is missing: $directory"
  fi
  [ ! -L "$directory" ] || fail "corpus directory must not be a symlink: $directory"
  if find "$directory" -mindepth 1 ! -type f -print -quit | grep -q .; then
    fail "corpus directory contains a non-regular or nested entry: $directory"
  fi
  files=$(find "$directory" -mindepth 1 -maxdepth 1 -type f | LC_ALL=C sort) || \
    fail "cannot list corpus directory: $directory"
  if [ -z "$files" ]; then
    [ "$required" = no ] && return 0
    fail "required corpus directory is empty: $directory"
  fi
  printf '%s\n' "$files" | while IFS= read -r path; do
    case "$path" in *[!A-Za-z0-9._/-]*) fail "unsafe corpus path: $path" ;; esac
    bytes=$(size_file "$path") || fail "cannot determine corpus byte count: $path"
    digest=$(sha256_file "$path") || fail "cannot hash corpus file: $path"
    printf '%s\t%s\t%s\t%s\t%s\n' "$class" "$target" "$bytes" "$digest" "$path"
  done
}

emit_partition_entries() {
  targets=$1
  destination=$2
  : > "$destination" || fail "cannot initialize corpus entries: $destination"
  for target in $targets; do
    emit_directory corpus "$target" "fuzz/corpus/$target" yes >> "$destination" || \
      fail "cannot register corpus directory for $target"
    emit_directory finding "$target" "fuzz/findings/$target" no >> "$destination" || \
      fail "cannot register finding directory for $target"
  done
}

render_partition() {
  version=$1
  source_commit=$2
  targets=$3
  target_order=$4
  entries=$5
  destination=$6

  validate_source_commit "$source_commit"
  total_count=$(wc -l < "$entries" | tr -d ' ')
  total_bytes=$(awk -F '\t' '{ sum += $3 } END { print sum + 0 }' "$entries")
  total_hash=$(sha256_file "$entries") || fail 'cannot hash aggregate corpus entries'

  {
    printf '%s\n' "$version"
    printf 'campaign_source\t%s\n' "$source_commit"
    printf 'target_order\t%s\n' "$target_order"
    for target in $targets; do
      awk -F '\t' -v wanted="$target" '$2 == wanted' "$entries" > "$target_tmp" || \
        fail "cannot select corpus entries for $target"
      count=$(wc -l < "$target_tmp" | tr -d ' ')
      [ "$count" -gt 0 ] || fail "no registered entries for $target"
      bytes=$(awk -F '\t' '{ sum += $3 } END { print sum + 0 }' "$target_tmp")
      digest=$(sha256_file "$target_tmp") || fail "cannot hash corpus entries for $target"
      printf 'target\t%s\tcount\t%s\tbytes\t%s\tentries_sha256\t%s\n' \
        "$target" "$count" "$bytes" "$digest"
    done
    printf 'aggregate\tcount\t%s\tbytes\t%s\tentries_sha256\t%s\n' \
      "$total_count" "$total_bytes" "$total_hash"
    printf 'entries_begin\n'
    printf 'class\ttarget\tbytes\tsha256\tpath\n'
    sed -n 'p' "$entries"
  } > "$destination" || fail "cannot render corpus manifest: $destination"
}

extract_manifest_paths() {
  manifest=$1
  allowed_targets=$2
  destination=$3
  if ! awk -F '\t' -v allowed="$allowed_targets" '
    BEGIN {
      count = split(allowed, list, ",")
      for (item = 1; item <= count; item++) permitted[list[item]] = 1
    }
    $0 == "entries_begin" { entries = 1; next }
    !entries { next }
    entries && !header {
      if ($0 != "class\ttarget\tbytes\tsha256\tpath") bad = 1
      header = 1
      next
    }
    {
      if (NF != 5 || !($2 in permitted) || ($1 != "corpus" && $1 != "finding")) {
        bad = 1
        next
      }
      root = ($1 == "corpus") ? "fuzz/corpus/" : "fuzz/findings/"
      prefix = root $2 "/"
      if (index($5, prefix) != 1 || length($5) <= length(prefix)) {
        bad = 1
        next
      }
      print $5
    }
    END { if (!entries || !header || bad) exit 1 }
  ' "$manifest" > "$destination"; then
    fail "$manifest contains malformed or cross-partition corpus entries"
  fi
}

root=$(git rev-parse --show-toplevel 2>/dev/null) || fail 'not inside a Git worktree'
cd "$root" || fail 'cannot enter worktree root'

m21_manifest='fuzz/CORPUS-MANIFEST.tsv'
m22_manifest='fuzz/CORPUS-MANIFEST-M22.tsv'
m23_manifest='fuzz/CORPUS-MANIFEST-M23.tsv'
m24_manifest='fuzz/CORPUS-MANIFEST-M24.tsv'
m25_manifest='fuzz/CORPUS-MANIFEST-M25.tsv'
m26_manifest='fuzz/CORPUS-MANIFEST-M26.tsv'
m27_manifest='fuzz/CORPUS-MANIFEST-M27.tsv'
m28_manifest='fuzz/CORPUS-MANIFEST-M28.tsv'
m21_targets='qk_psbt qk_descriptor qk_a1 qk_a1_codec qk_card_trace'
m22_targets='qk_bbqr_codec qk_bbqr_reassembly'
m23_targets='qk_psbt_m23 qk_host_sim_m23'
m24_targets='qk_host_sim_m24'
m25_targets='qk_host_sim_m25'
m26_targets='qk_provisioning_inputs_m26 qk_provisioning_chain_m26'
m27_targets='qk_host_sim_m27'
m28_targets='qk_host_sim_m28'
all_targets="$m21_targets $m22_targets $m23_targets $m24_targets $m25_targets $m26_targets $m27_targets $m28_targets"
m21_order='qk_psbt,qk_descriptor,qk_a1,qk_a1_codec,qk_card_trace'
m22_order='qk_bbqr_codec,qk_bbqr_reassembly'
m23_order='qk_psbt_m23,qk_host_sim_m23'
m24_order='qk_host_sim_m24'
m25_order='qk_host_sim_m25'
m26_order='qk_provisioning_inputs_m26,qk_provisioning_chain_m26'
m27_order='qk_host_sim_m27'
m28_order='qk_host_sim_m28'

mode=check
render_source=''
case "$#" in
  0) ;;
  2)
    case "$1" in
      --render) mode=render_m21 ;;
      --render-m22) mode=render_m22 ;;
      --render-m23) mode=render_m23 ;;
      --render-m24) mode=render_m24 ;;
      --render-m25) mode=render_m25 ;;
      --render-m26) mode=render_m26 ;;
      --render-m27) mode=render_m27 ;;
      --render-m28) mode=render_m28 ;;
      *) fail 'usage: check-fuzz-corpora.sh [--render SOURCE_COMMIT | --render-m22 SOURCE_COMMIT | --render-m23 SOURCE_COMMIT | --render-m24 SOURCE_COMMIT | --render-m25 SOURCE_COMMIT | --render-m26 SOURCE_COMMIT | --render-m27 SOURCE_COMMIT | --render-m28 SOURCE_COMMIT]' ;;
    esac
    render_source=$2
    validate_source_commit "$render_source"
    ;;
  *) fail 'usage: check-fuzz-corpora.sh [--render SOURCE_COMMIT | --render-m22 SOURCE_COMMIT | --render-m23 SOURCE_COMMIT | --render-m24 SOURCE_COMMIT | --render-m25 SOURCE_COMMIT | --render-m26 SOURCE_COMMIT | --render-m27 SOURCE_COMMIT | --render-m28 SOURCE_COMMIT]' ;;
esac

if [ "$mode" = check ]; then
  for manifest in "$m21_manifest" "$m22_manifest" "$m23_manifest" "$m24_manifest" \
    "$m25_manifest" "$m26_manifest" "$m27_manifest" "$m28_manifest"; do
    [ -f "$manifest" ] || fail "$manifest is missing"
    [ ! -L "$manifest" ] || fail "$manifest must not be a symlink"
    git ls-files --error-unmatch -- "$manifest" >/dev/null 2>&1 || \
      fail "$manifest is untracked"
  done
fi

[ -d fuzz/corpus ] || fail 'fuzz/corpus is missing or is not a directory'
[ ! -L fuzz/corpus ] || fail 'fuzz/corpus must not be a symlink'
unexpected=$(find fuzz/corpus -mindepth 1 -maxdepth 1 \
  ! -name qk_psbt ! -name qk_descriptor ! -name qk_a1 \
  ! -name qk_a1_codec ! -name qk_card_trace \
  ! -name qk_bbqr_codec ! -name qk_bbqr_reassembly \
  ! -name qk_psbt_m23 ! -name qk_host_sim_m23 \
  ! -name qk_host_sim_m24 ! -name qk_host_sim_m25 \
  ! -name qk_provisioning_inputs_m26 ! -name qk_provisioning_chain_m26 \
  ! -name qk_host_sim_m27 ! -name qk_host_sim_m28 -print -quit) || \
  fail 'cannot inspect fuzz/corpus roots'
[ -z "$unexpected" ] || fail "unexpected corpus root entry: $unexpected"
for target in $all_targets; do
  [ -d "fuzz/corpus/$target" ] || \
    fail "required corpus target directory is missing: fuzz/corpus/$target"
  [ ! -L "fuzz/corpus/$target" ] || \
    fail "corpus target directory must not be a symlink: fuzz/corpus/$target"
done

if [ -e fuzz/findings ] && [ ! -d fuzz/findings ]; then
  fail 'fuzz/findings exists but is not a directory'
fi
if [ -d fuzz/findings ]; then
  [ ! -L fuzz/findings ] || fail 'fuzz/findings must not be a symlink'
  unexpected=$(find fuzz/findings -mindepth 1 -maxdepth 1 \
    ! -name qk_psbt ! -name qk_descriptor ! -name qk_a1 \
    ! -name qk_a1_codec ! -name qk_card_trace \
    ! -name qk_bbqr_codec ! -name qk_bbqr_reassembly \
    ! -name qk_psbt_m23 ! -name qk_host_sim_m23 \
    ! -name qk_host_sim_m24 ! -name qk_host_sim_m25 \
    ! -name qk_provisioning_inputs_m26 ! -name qk_provisioning_chain_m26 \
    ! -name qk_host_sim_m27 ! -name qk_host_sim_m28 -print -quit) || \
    fail 'cannot inspect fuzz/findings roots'
  [ -z "$unexpected" ] || fail "unexpected finding root entry: $unexpected"
  for target in $all_targets; do
    if [ -e "fuzz/findings/$target" ] && [ ! -d "fuzz/findings/$target" ]; then
      fail "finding target entry is not a directory: fuzz/findings/$target"
    fi
    if [ -L "fuzz/findings/$target" ]; then
      fail "finding target directory must not be a symlink: fuzz/findings/$target"
    fi
  done
fi

m21_entries=$(mktemp) || fail 'mktemp failed for M21 corpus entries'
m22_entries=$(mktemp) || fail 'mktemp failed for M22 corpus entries'
m23_entries=$(mktemp) || fail 'mktemp failed for M23 corpus entries'
m24_entries=$(mktemp) || fail 'mktemp failed for M24 corpus entries'
m25_entries=$(mktemp) || fail 'mktemp failed for M25 corpus entries'
m26_entries=$(mktemp) || fail 'mktemp failed for M26 corpus entries'
m27_entries=$(mktemp) || fail 'mktemp failed for M27 corpus entries'
m28_entries=$(mktemp) || fail 'mktemp failed for M28 corpus entries'
m21_expected=$(mktemp) || fail 'mktemp failed for M21 corpus manifest'
m22_expected=$(mktemp) || fail 'mktemp failed for M22 corpus manifest'
m23_expected=$(mktemp) || fail 'mktemp failed for M23 corpus manifest'
m24_expected=$(mktemp) || fail 'mktemp failed for M24 corpus manifest'
m25_expected=$(mktemp) || fail 'mktemp failed for M25 corpus manifest'
m26_expected=$(mktemp) || fail 'mktemp failed for M26 corpus manifest'
m27_expected=$(mktemp) || fail 'mktemp failed for M27 corpus manifest'
m28_expected=$(mktemp) || fail 'mktemp failed for M28 corpus manifest'
m21_paths=$(mktemp) || fail 'mktemp failed for M21 corpus paths'
m22_paths=$(mktemp) || fail 'mktemp failed for M22 corpus paths'
m23_paths=$(mktemp) || fail 'mktemp failed for M23 corpus paths'
m24_paths=$(mktemp) || fail 'mktemp failed for M24 corpus paths'
m25_paths=$(mktemp) || fail 'mktemp failed for M25 corpus paths'
m26_paths=$(mktemp) || fail 'mktemp failed for M26 corpus paths'
m27_paths=$(mktemp) || fail 'mktemp failed for M27 corpus paths'
m28_paths=$(mktemp) || fail 'mktemp failed for M28 corpus paths'
all_paths=$(mktemp) || fail 'mktemp failed for combined corpus paths'
tracked_tmp=$(mktemp) || fail 'mktemp failed for tracked paths'
target_tmp=$(mktemp) || fail 'mktemp failed for target entries'
manifest_m21_paths=$(mktemp) || fail 'mktemp failed for M21 manifest paths'
manifest_m22_paths=$(mktemp) || fail 'mktemp failed for M22 manifest paths'
manifest_m23_paths=$(mktemp) || fail 'mktemp failed for M23 manifest paths'
manifest_m24_paths=$(mktemp) || fail 'mktemp failed for M24 manifest paths'
manifest_m25_paths=$(mktemp) || fail 'mktemp failed for M25 manifest paths'
manifest_m26_paths=$(mktemp) || fail 'mktemp failed for M26 manifest paths'
manifest_m27_paths=$(mktemp) || fail 'mktemp failed for M27 manifest paths'
manifest_m28_paths=$(mktemp) || fail 'mktemp failed for M28 manifest paths'
trap 'rm -f "$m21_entries" "$m22_entries" "$m21_expected" "$m22_expected" \
  "$m23_entries" "$m23_expected" "$m24_entries" "$m24_expected" \
  "$m25_entries" "$m25_expected" "$m26_entries" "$m26_expected" \
  "$m27_entries" "$m27_expected" "$m28_entries" "$m28_expected" \
  "$m21_paths" "$m22_paths" "$m23_paths" "$m24_paths" "$m25_paths" \
  "$m26_paths" "$m27_paths" "$m28_paths" \
  "$all_paths" "$tracked_tmp" "$target_tmp" "$manifest_m21_paths" \
  "$manifest_m22_paths" "$manifest_m23_paths" "$manifest_m24_paths" \
  "$manifest_m25_paths" "$manifest_m26_paths" "$manifest_m27_paths" \
  "$manifest_m28_paths"' EXIT HUP INT TERM

emit_partition_entries "$m21_targets" "$m21_entries"
emit_partition_entries "$m22_targets" "$m22_entries"
emit_partition_entries "$m23_targets" "$m23_entries"
emit_partition_entries "$m24_targets" "$m24_entries"
emit_partition_entries "$m25_targets" "$m25_entries"
emit_partition_entries "$m26_targets" "$m26_entries"
emit_partition_entries "$m27_targets" "$m27_entries"
emit_partition_entries "$m28_targets" "$m28_entries"
cut -f 5 "$m21_entries" | LC_ALL=C sort > "$m21_paths" || fail 'cannot list M21 corpus paths'
cut -f 5 "$m22_entries" | LC_ALL=C sort > "$m22_paths" || fail 'cannot list M22 corpus paths'
cut -f 5 "$m23_entries" | LC_ALL=C sort > "$m23_paths" || fail 'cannot list M23 corpus paths'
cut -f 5 "$m24_entries" | LC_ALL=C sort > "$m24_paths" || fail 'cannot list M24 corpus paths'
cut -f 5 "$m25_entries" | LC_ALL=C sort > "$m25_paths" || fail 'cannot list M25 corpus paths'
cut -f 5 "$m26_entries" | LC_ALL=C sort > "$m26_paths" || fail 'cannot list M26 corpus paths'
cut -f 5 "$m27_entries" | LC_ALL=C sort > "$m27_paths" || fail 'cannot list M27 corpus paths'
cut -f 5 "$m28_entries" | LC_ALL=C sort > "$m28_paths" || fail 'cannot list M28 corpus paths'
cat "$m21_paths" "$m22_paths" "$m23_paths" "$m24_paths" "$m25_paths" \
  "$m26_paths" "$m27_paths" "$m28_paths" | \
  LC_ALL=C sort > "$all_paths" || \
  fail 'cannot combine corpus paths'
duplicate=$(uniq -d "$all_paths" | sed -n '1p')
[ -z "$duplicate" ] || fail "corpus path is owned by both partitions: $duplicate"

git ls-files | LC_ALL=C sort > "$tracked_tmp" || fail 'cannot list tracked paths'
untracked=$(comm -23 "$all_paths" "$tracked_tmp") || fail 'cannot compare corpus paths with tracked files'
[ -z "$untracked" ] || fail "untracked corpus file: $(printf '%s\n' "$untracked" | sed -n '1p')"

case "$mode" in
  check)
    m21_source=$(manifest_source "$m21_manifest")
    m22_source=$(manifest_source "$m22_manifest")
    m23_source=$(manifest_source "$m23_manifest")
    m24_source=$(manifest_source "$m24_manifest")
    m25_source=$(manifest_source "$m25_manifest")
    m26_source=$(manifest_source "$m26_manifest")
    m27_source=$(manifest_source "$m27_manifest")
    m28_source=$(manifest_source "$m28_manifest")
    render_partition 'QK-M21-CORPUS-MANIFEST-V1' "$m21_source" "$m21_targets" \
      "$m21_order" "$m21_entries" "$m21_expected"
    render_partition 'QK-M22-CORPUS-MANIFEST-V1' "$m22_source" "$m22_targets" \
      "$m22_order" "$m22_entries" "$m22_expected"
    render_partition 'QK-M23-CORPUS-MANIFEST-V1' "$m23_source" "$m23_targets" \
      "$m23_order" "$m23_entries" "$m23_expected"
    render_partition 'QK-M24-CORPUS-MANIFEST-V1' "$m24_source" "$m24_targets" \
      "$m24_order" "$m24_entries" "$m24_expected"
    render_partition 'QK-M25-CORPUS-MANIFEST-V1' "$m25_source" "$m25_targets" \
      "$m25_order" "$m25_entries" "$m25_expected"
    render_partition 'QK-M26-CORPUS-MANIFEST-V1' "$m26_source" "$m26_targets" \
      "$m26_order" "$m26_entries" "$m26_expected"
    render_partition 'QK-M27-CORPUS-MANIFEST-V1' "$m27_source" "$m27_targets" \
      "$m27_order" "$m27_entries" "$m27_expected"
    render_partition 'QK-M28-CORPUS-MANIFEST-V1' "$m28_source" "$m28_targets" \
      "$m28_order" "$m28_entries" "$m28_expected"
    extract_manifest_paths "$m21_manifest" "$m21_order" "$manifest_m21_paths"
    extract_manifest_paths "$m22_manifest" "$m22_order" "$manifest_m22_paths"
    extract_manifest_paths "$m23_manifest" "$m23_order" "$manifest_m23_paths"
    extract_manifest_paths "$m24_manifest" "$m24_order" "$manifest_m24_paths"
    extract_manifest_paths "$m25_manifest" "$m25_order" "$manifest_m25_paths"
    extract_manifest_paths "$m26_manifest" "$m26_order" "$manifest_m26_paths"
    extract_manifest_paths "$m27_manifest" "$m27_order" "$manifest_m27_paths"
    extract_manifest_paths "$m28_manifest" "$m28_order" "$manifest_m28_paths"
    duplicate=$(cat "$manifest_m21_paths" "$manifest_m22_paths" "$manifest_m23_paths" \
      "$manifest_m24_paths" "$manifest_m25_paths" "$manifest_m26_paths" \
      "$manifest_m27_paths" "$manifest_m28_paths" | \
      LC_ALL=C sort | \
      uniq -d | sed -n '1p')
    [ -z "$duplicate" ] || fail "manifest path is owned by both partitions: $duplicate"
    cmp -s "$m21_manifest" "$m21_expected" || \
      fail "$m21_manifest does not match the tracked M21 corpus bytes"
    cmp -s "$m22_manifest" "$m22_expected" || \
      fail "$m22_manifest does not match the tracked M22 corpus bytes"
    cmp -s "$m23_manifest" "$m23_expected" || \
      fail "$m23_manifest does not match the tracked M23 corpus bytes"
    cmp -s "$m24_manifest" "$m24_expected" || \
      fail "$m24_manifest does not match the tracked M24 corpus bytes"
    cmp -s "$m25_manifest" "$m25_expected" || \
      fail "$m25_manifest does not match the tracked M25 corpus bytes"
    cmp -s "$m26_manifest" "$m26_expected" || \
      fail "$m26_manifest does not match the tracked M26 corpus bytes"
    cmp -s "$m27_manifest" "$m27_expected" || \
      fail "$m27_manifest does not match the tracked M27 corpus bytes"
    cmp -s "$m28_manifest" "$m28_expected" || \
      fail "$m28_manifest does not match the tracked M28 corpus bytes"
    ;;
  render_m21)
    render_partition 'QK-M21-CORPUS-MANIFEST-V1' "$render_source" "$m21_targets" \
      "$m21_order" "$m21_entries" "$m21_expected"
    sed -n 'p' "$m21_expected"
    ;;
  render_m22)
    render_partition 'QK-M22-CORPUS-MANIFEST-V1' "$render_source" "$m22_targets" \
      "$m22_order" "$m22_entries" "$m22_expected"
    sed -n 'p' "$m22_expected"
    ;;
  render_m23)
    render_partition 'QK-M23-CORPUS-MANIFEST-V1' "$render_source" "$m23_targets" \
      "$m23_order" "$m23_entries" "$m23_expected"
    sed -n 'p' "$m23_expected"
    ;;
  render_m24)
    render_partition 'QK-M24-CORPUS-MANIFEST-V1' "$render_source" "$m24_targets" \
      "$m24_order" "$m24_entries" "$m24_expected"
    sed -n 'p' "$m24_expected"
    ;;
  render_m25)
    render_partition 'QK-M25-CORPUS-MANIFEST-V1' "$render_source" "$m25_targets" \
      "$m25_order" "$m25_entries" "$m25_expected"
    sed -n 'p' "$m25_expected"
    ;;
  render_m26)
    render_partition 'QK-M26-CORPUS-MANIFEST-V1' "$render_source" "$m26_targets" \
      "$m26_order" "$m26_entries" "$m26_expected"
    sed -n 'p' "$m26_expected"
    ;;
  render_m27)
    render_partition 'QK-M27-CORPUS-MANIFEST-V1' "$render_source" "$m27_targets" \
      "$m27_order" "$m27_entries" "$m27_expected"
    sed -n 'p' "$m27_expected"
    ;;
  render_m28)
    render_partition 'QK-M28-CORPUS-MANIFEST-V1' "$render_source" "$m28_targets" \
      "$m28_order" "$m28_entries" "$m28_expected"
    sed -n 'p' "$m28_expected"
    ;;
esac

exit 0
