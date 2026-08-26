#!/bin/sh
# Recompute and verify QK-DEC-106's persistent corpus registry.
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

root=$(git rev-parse --show-toplevel 2>/dev/null) || fail 'not inside a Git worktree'
cd "$root" || fail 'cannot enter worktree root'

manifest='fuzz/CORPUS-MANIFEST.tsv'
targets='qk_psbt qk_descriptor qk_a1 qk_a1_codec qk_card_trace'
target_order='qk_psbt,qk_descriptor,qk_a1,qk_a1_codec,qk_card_trace'

mode=check
source_commit=''
case "$#" in
  0)
    [ -f "$manifest" ] || fail "$manifest is missing"
    git ls-files --error-unmatch -- "$manifest" >/dev/null 2>&1 || fail "$manifest is untracked"
    source_count=$(awk -F '\t' '$1 == "campaign_source" { count++ } END { print count + 0 }' "$manifest")
    [ "$source_count" = 1 ] || fail 'corpus manifest must contain one campaign_source row'
    source_commit=$(awk -F '\t' '$1 == "campaign_source" { print $2 }' "$manifest")
    ;;
  2)
    [ "$1" = '--render' ] || fail 'usage: check-fuzz-corpora.sh [--render SOURCE_COMMIT]'
    mode=render
    source_commit=$2
    ;;
  *) fail 'usage: check-fuzz-corpora.sh [--render SOURCE_COMMIT]' ;;
esac
case "$source_commit" in
  *[!0-9a-f]*|'') fail 'campaign_source must be lowercase hexadecimal' ;;
esac
[ "${#source_commit}" = 40 ] || fail 'campaign_source must be a full 40-character commit id'

entries_tmp=$(mktemp) || fail 'mktemp failed for corpus entries'
expected_tmp=$(mktemp) || fail 'mktemp failed for corpus manifest'
target_tmp=$(mktemp) || fail 'mktemp failed for target entries'
paths_tmp=$(mktemp) || fail 'mktemp failed for corpus paths'
tracked_tmp=$(mktemp) || fail 'mktemp failed for tracked paths'
trap 'rm -f "$entries_tmp" "$expected_tmp" "$target_tmp" "$paths_tmp" "$tracked_tmp"' EXIT HUP INT TERM

unexpected=$(find fuzz/corpus -mindepth 1 -maxdepth 1 \
  ! -name qk_psbt ! -name qk_descriptor ! -name qk_a1 \
  ! -name qk_a1_codec ! -name qk_card_trace -print -quit)
[ -z "$unexpected" ] || fail "unexpected corpus root entry: $unexpected"
for target in $targets; do
  [ -d "fuzz/corpus/$target" ] || fail "required corpus target directory is missing: fuzz/corpus/$target"
done

emit_directory() {
  class=$1
  target=$2
  directory=$3
  required=$4
  if [ ! -d "$directory" ]; then
    [ "$required" = no ] && return 0
    fail "required corpus directory is missing: $directory"
  fi
  if find "$directory" -mindepth 1 ! -type f -print -quit | grep -q .; then
    fail "corpus directory contains a non-regular or nested entry: $directory"
  fi
  files=$(find "$directory" -mindepth 1 -maxdepth 1 -type f | LC_ALL=C sort)
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

if [ -e fuzz/findings ] && [ ! -d fuzz/findings ]; then
  fail 'fuzz/findings exists but is not a directory'
fi
if [ -d fuzz/findings ]; then
  unexpected=$(find fuzz/findings -mindepth 1 -maxdepth 1 \
    ! -name qk_psbt ! -name qk_descriptor ! -name qk_a1 \
    ! -name qk_a1_codec ! -name qk_card_trace -print -quit)
  [ -z "$unexpected" ] || fail "unexpected finding root entry: $unexpected"
  for target in $targets; do
    if [ -e "fuzz/findings/$target" ] && [ ! -d "fuzz/findings/$target" ]; then
      fail "finding target entry is not a directory: fuzz/findings/$target"
    fi
  done
fi

: > "$entries_tmp"
for target in $targets; do
  emit_directory corpus "$target" "fuzz/corpus/$target" yes >> "$entries_tmp" || \
    fail "cannot register corpus directory for $target"
  emit_directory finding "$target" "fuzz/findings/$target" no >> "$entries_tmp" || \
    fail "cannot register finding directory for $target"
done

cut -f 5 "$entries_tmp" | LC_ALL=C sort > "$paths_tmp" || fail 'cannot list corpus paths'
git ls-files | LC_ALL=C sort > "$tracked_tmp" || fail 'cannot list tracked paths'
if [ -n "$(uniq -d "$paths_tmp")" ]; then
  fail 'duplicate corpus path in generated entries'
fi
untracked=$(comm -23 "$paths_tmp" "$tracked_tmp") || fail 'cannot compare corpus paths with tracked files'
[ -z "$untracked" ] || fail "untracked corpus file: $(printf '%s\n' "$untracked" | sed -n '1p')"

total_count=$(wc -l < "$entries_tmp" | tr -d ' ')
total_bytes=$(awk -F '\t' '{ sum += $3 } END { print sum + 0 }' "$entries_tmp")
total_hash=$(sha256_file "$entries_tmp") || fail 'cannot hash aggregate corpus entries'

{
  printf 'QK-M21-CORPUS-MANIFEST-V1\n'
  printf 'campaign_source\t%s\n' "$source_commit"
  printf 'target_order\t%s\n' "$target_order"
  for target in $targets; do
    awk -F '\t' -v wanted="$target" '$2 == wanted' "$entries_tmp" > "$target_tmp" || \
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
  sed -n 'p' "$entries_tmp"
} > "$expected_tmp"

if [ "$mode" = render ]; then
  sed -n 'p' "$expected_tmp"
elif ! cmp -s "$manifest" "$expected_tmp"; then
  fail "$manifest does not match the tracked corpus bytes"
fi

exit 0
