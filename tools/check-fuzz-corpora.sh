#!/bin/sh
# Recompute and verify the partitioned QK-DEC-106/QK-DEC-109..113/QK-DEC-116/QK-DEC-118..134/QK-DEC-136/QK-DEC-140 corpus registries.
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
  validated_source_value=$1
  source_label=${2:-campaign_source}
  case "$validated_source_value" in
    *[!0-9a-f]*|'') fail "$source_label must be lowercase hexadecimal" ;;
  esac
  [ "${#validated_source_value}" = 40 ] || \
    fail "$source_label must be a full 40-character commit id"
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

manifest_target_source() {
  manifest=$1
  expected_target=$2
  source_count=$(awk -F '\t' \
    '$1 == "target_source" { count++ } END { print count + 0 }' "$manifest") || \
    fail "cannot inspect target_source in $manifest"
  [ "$source_count" = 1 ] || fail "$manifest must contain one target_source row"
  if ! awk -F '\t' -v expected="$expected_target" '
    $1 == "target_source" {
      if (NF != 3 || $2 != expected) bad = 1
    }
    END { if (bad) exit 1 }
  ' "$manifest"; then
    fail "$manifest contains a malformed target_source row"
  fi
  source_commit=$(awk -F '\t' -v expected="$expected_target" \
    '$1 == "target_source" && $2 == expected { print $3 }' "$manifest") || \
    fail "cannot read target_source from $manifest"
  validate_source_commit "$source_commit" target_source
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
  target_source_target=${7:-}
  target_source_commit=${8:-}

  validate_source_commit "$source_commit"
  if [ -n "$target_source_target" ] || [ -n "$target_source_commit" ]; then
    [ -n "$target_source_target" ] && [ -n "$target_source_commit" ] || \
      fail 'target_source requires both target and commit'
    validate_source_commit "$target_source_commit" target_source
    case " $targets " in
      *" $target_source_target "*) ;;
      *) fail "target_source names unknown target: $target_source_target" ;;
    esac
  fi
  total_count=$(wc -l < "$entries" | tr -d ' ')
  total_bytes=$(awk -F '\t' '{ sum += $3 } END { print sum + 0 }' "$entries")
  total_hash=$(sha256_file "$entries") || fail 'cannot hash aggregate corpus entries'

  {
    printf '%s\n' "$version"
    printf 'campaign_source\t%s\n' "$source_commit"
    if [ -n "$target_source_target" ]; then
      printf 'target_source\t%s\t%s\n' "$target_source_target" "$target_source_commit"
    fi
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
m29_manifest='fuzz/CORPUS-MANIFEST-M29.tsv'
m30_manifest='fuzz/CORPUS-MANIFEST-M30.tsv'
v2s4_manifest='fuzz/CORPUS-MANIFEST-V2-S4.tsv'
v2s5_manifest='fuzz/CORPUS-MANIFEST-V2-S5.tsv'
v2s6_manifest='fuzz/CORPUS-MANIFEST-V2-S6.tsv'
v2s7_manifest='fuzz/CORPUS-MANIFEST-V2-S7.tsv'
v2s8_manifest='fuzz/CORPUS-MANIFEST-V2-S8.tsv'
v2s9_manifest='fuzz/CORPUS-MANIFEST-V2-S9.tsv'
v2s10_manifest='fuzz/CORPUS-MANIFEST-V2-S10.tsv'
v2s11_manifest='fuzz/CORPUS-MANIFEST-V2-S11.tsv'
firmware_manifest='fuzz/CORPUS-MANIFEST-FIRMWARE-V1.tsv'
process_s1_manifest='fuzz/CORPUS-MANIFEST-PROCESS-S1.tsv'
m21_targets='qk_psbt qk_descriptor qk_a1 qk_a1_codec qk_card_trace'
m22_targets='qk_bbqr_codec qk_bbqr_reassembly'
m23_targets='qk_psbt_m23 qk_host_sim_m23'
m24_targets='qk_host_sim_m24'
m25_targets='qk_host_sim_m25'
m26_targets='qk_provisioning_inputs_m26 qk_provisioning_chain_m26'
m27_targets='qk_host_sim_m27'
m28_targets='qk_host_sim_m28'
m29_targets='qk_host_sim_m29'
m30_targets='qk_bbqr_m30 qk_host_sim_m30'
v2s4_targets='qk_provisioning_v2_inputs qk_provisioning_v2_chain'
v2s5_targets='qk_host_sim_v2_s5_screen qk_host_sim_v2_s5_manual_keypad'
v2s6_targets='qk_host_sim_v2_s6_watch_only'
v2s7_targets='qk_kit_v2_s7_codec qk_kit_v2_s7_combine'
v2s8_targets='qk_provisioning_v2_s8_kit_setup'
v2s9_targets='qk_host_sim_v2_s9_kit_intake'
v2s10_targets='qk_host_sim_v2_s10_kit_restore'
v2s11_targets='qk_host_sim_v2_s11_kit_spend'
firmware_targets='qk_update_package qk_update_lifecycle'
process_s1_targets='qk_ipc_wire qk_ipc_endpoint_state'
all_targets="$m21_targets $m22_targets $m23_targets $m24_targets $m25_targets $m26_targets $m27_targets $m28_targets $m29_targets $m30_targets $v2s4_targets $v2s5_targets $v2s6_targets $v2s7_targets $v2s8_targets $v2s9_targets $v2s10_targets $v2s11_targets $firmware_targets $process_s1_targets"
m21_order='qk_psbt,qk_descriptor,qk_a1,qk_a1_codec,qk_card_trace'
m22_order='qk_bbqr_codec,qk_bbqr_reassembly'
m23_order='qk_psbt_m23,qk_host_sim_m23'
m24_order='qk_host_sim_m24'
m25_order='qk_host_sim_m25'
m26_order='qk_provisioning_inputs_m26,qk_provisioning_chain_m26'
m27_order='qk_host_sim_m27'
m28_order='qk_host_sim_m28'
m29_order='qk_host_sim_m29'
m30_order='qk_bbqr_m30,qk_host_sim_m30'
v2s4_order='qk_provisioning_v2_inputs,qk_provisioning_v2_chain'
v2s5_order='qk_host_sim_v2_s5_screen,qk_host_sim_v2_s5_manual_keypad'
v2s6_order='qk_host_sim_v2_s6_watch_only'
v2s7_order='qk_kit_v2_s7_codec,qk_kit_v2_s7_combine'
v2s8_order='qk_provisioning_v2_s8_kit_setup'
v2s9_order='qk_host_sim_v2_s9_kit_intake'
v2s10_order='qk_host_sim_v2_s10_kit_restore'
v2s11_order='qk_host_sim_v2_s11_kit_spend'
firmware_order='qk_update_package,qk_update_lifecycle'
process_s1_order='qk_ipc_wire,qk_ipc_endpoint_state'

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
      --render-m29) mode=render_m29 ;;
      --render-m30) mode=render_m30 ;;
      --render-v2-s4) mode=render_v2s4 ;;
      --render-v2-s5) mode=render_v2s5 ;;
      --render-v2-s6) mode=render_v2s6 ;;
      --render-v2-s7) mode=render_v2s7 ;;
      --render-v2-s8) mode=render_v2s8 ;;
      --render-v2-s9) mode=render_v2s9 ;;
      --render-v2-s10) mode=render_v2s10 ;;
      --render-v2-s11) mode=render_v2s11 ;;
      --render-firmware-v1) mode=render_firmware_v1 ;;
      --render-process-s1) mode=render_process_s1 ;;
      --render-qk-descriptor) mode=render_qk_descriptor ;;
      --render-qk-psbt-v3) mode=render_qk_psbt_v3 ;;
      *) fail 'usage: check-fuzz-corpora.sh [--render SOURCE_COMMIT | --render-qk-descriptor SOURCE_COMMIT | --render-qk-psbt-v3 SOURCE_COMMIT | --render-m22 SOURCE_COMMIT | --render-m23 SOURCE_COMMIT | --render-m24 SOURCE_COMMIT | --render-m25 SOURCE_COMMIT | --render-m26 SOURCE_COMMIT | --render-m27 SOURCE_COMMIT | --render-m28 SOURCE_COMMIT | --render-m29 SOURCE_COMMIT | --render-m30 SOURCE_COMMIT | --render-v2-s4 SOURCE_COMMIT | --render-v2-s5 SOURCE_COMMIT | --render-v2-s6 SOURCE_COMMIT | --render-v2-s7 SOURCE_COMMIT | --render-v2-s8 SOURCE_COMMIT | --render-v2-s9 SOURCE_COMMIT | --render-v2-s10 SOURCE_COMMIT | --render-v2-s11 SOURCE_COMMIT | --render-firmware-v1 SOURCE_COMMIT | --render-process-s1 SOURCE_COMMIT]' ;;
    esac
    render_source=$2
    if [ "$mode" = render_qk_descriptor ] || [ "$mode" = render_qk_psbt_v3 ]; then
      validate_source_commit "$render_source" target_source
    else
      validate_source_commit "$render_source"
    fi
    ;;
  *) fail 'usage: check-fuzz-corpora.sh [--render SOURCE_COMMIT | --render-qk-descriptor SOURCE_COMMIT | --render-qk-psbt-v3 SOURCE_COMMIT | --render-m22 SOURCE_COMMIT | --render-m23 SOURCE_COMMIT | --render-m24 SOURCE_COMMIT | --render-m25 SOURCE_COMMIT | --render-m26 SOURCE_COMMIT | --render-m27 SOURCE_COMMIT | --render-m28 SOURCE_COMMIT | --render-m29 SOURCE_COMMIT | --render-m30 SOURCE_COMMIT | --render-v2-s4 SOURCE_COMMIT | --render-v2-s5 SOURCE_COMMIT | --render-v2-s6 SOURCE_COMMIT | --render-v2-s7 SOURCE_COMMIT | --render-v2-s8 SOURCE_COMMIT | --render-v2-s9 SOURCE_COMMIT | --render-v2-s10 SOURCE_COMMIT | --render-v2-s11 SOURCE_COMMIT | --render-firmware-v1 SOURCE_COMMIT | --render-process-s1 SOURCE_COMMIT]' ;;
esac

firmware_registered=no
process_s1_registered=no
if [ "$mode" = check ]; then
  for manifest in "$m21_manifest" "$m22_manifest" "$m23_manifest" "$m24_manifest" \
    "$m25_manifest" "$m26_manifest" "$m27_manifest" "$m28_manifest" \
    "$m29_manifest" "$m30_manifest" "$v2s4_manifest" "$v2s5_manifest" \
    "$v2s6_manifest" "$v2s7_manifest" "$v2s8_manifest" "$v2s9_manifest" \
    "$v2s10_manifest" "$v2s11_manifest"; do
    [ -f "$manifest" ] || fail "$manifest is missing"
    [ ! -L "$manifest" ] || fail "$manifest must not be a symlink"
    git ls-files --error-unmatch -- "$manifest" >/dev/null 2>&1 || \
      fail "$manifest is untracked"
  done
  [ -f fuzz/CAMPAIGN-018.md ] || fail 'fuzz/CAMPAIGN-018.md is missing'
  [ ! -L fuzz/CAMPAIGN-018.md ] || fail 'fuzz/CAMPAIGN-018.md must not be a symlink'
  git ls-files --error-unmatch -- fuzz/CAMPAIGN-018.md >/dev/null 2>&1 || \
    fail 'fuzz/CAMPAIGN-018.md is untracked'
  [ -f fuzz/CAMPAIGN-020.md ] || fail 'fuzz/CAMPAIGN-020.md is missing'
  [ ! -L fuzz/CAMPAIGN-020.md ] || fail 'fuzz/CAMPAIGN-020.md must not be a symlink'
  git ls-files --error-unmatch -- fuzz/CAMPAIGN-020.md >/dev/null 2>&1 || \
    fail 'fuzz/CAMPAIGN-020.md is untracked'
  if [ -e "$firmware_manifest" ]; then
    [ -f "$firmware_manifest" ] || fail "$firmware_manifest is not a regular file"
    [ ! -L "$firmware_manifest" ] || fail "$firmware_manifest must not be a symlink"
    git ls-files --error-unmatch -- "$firmware_manifest" >/dev/null 2>&1 || \
      fail "$firmware_manifest is untracked"
    grep -Fqx 'Status: EXECUTED — QUALIFYING RUN COMPLETE.' fuzz/CAMPAIGN-018.md || \
      fail 'registered firmware corpus requires completed campaign status'
    firmware_registered=yes
  else
    grep -Fqx 'Status: PLANNED — NOT EXECUTED.' fuzz/CAMPAIGN-018.md || \
      fail 'firmware corpus manifest is absent without the planned campaign status'
  fi
  if [ -e "$process_s1_manifest" ]; then
    [ -f "$process_s1_manifest" ] || fail "$process_s1_manifest is not a regular file"
    [ ! -L "$process_s1_manifest" ] || fail "$process_s1_manifest must not be a symlink"
    git ls-files --error-unmatch -- "$process_s1_manifest" >/dev/null 2>&1 || \
      fail "$process_s1_manifest is untracked"
    grep -Fqx 'Status: EXECUTED — QUALIFYING RUN COMPLETE.' fuzz/CAMPAIGN-020.md || \
      fail 'registered process slice-1 corpus requires completed campaign status'
    process_s1_registered=yes
  else
    grep -Fqx 'Status: PLANNED — NOT EXECUTED.' fuzz/CAMPAIGN-020.md || \
      fail 'process slice-1 corpus manifest is absent without the planned campaign status'
  fi
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
  ! -name qk_host_sim_m27 ! -name qk_host_sim_m28 \
  ! -name qk_host_sim_m29 ! -name qk_bbqr_m30 \
  ! -name qk_host_sim_m30 \
  ! -name qk_provisioning_v2_inputs ! -name qk_provisioning_v2_chain \
  ! -name qk_host_sim_v2_s5_screen ! -name qk_host_sim_v2_s5_manual_keypad \
  ! -name qk_host_sim_v2_s6_watch_only \
  ! -name qk_kit_v2_s7_codec ! -name qk_kit_v2_s7_combine \
  ! -name qk_provisioning_v2_s8_kit_setup \
  ! -name qk_host_sim_v2_s9_kit_intake \
  ! -name qk_host_sim_v2_s10_kit_restore \
  ! -name qk_host_sim_v2_s11_kit_spend \
  ! -name qk_update_package ! -name qk_update_lifecycle \
  ! -name qk_ipc_wire ! -name qk_ipc_endpoint_state \
  -print -quit) || \
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
    ! -name qk_host_sim_m27 ! -name qk_host_sim_m28 \
    ! -name qk_host_sim_m29 ! -name qk_bbqr_m30 \
    ! -name qk_host_sim_m30 \
    ! -name qk_provisioning_v2_inputs ! -name qk_provisioning_v2_chain \
    ! -name qk_host_sim_v2_s5_screen ! -name qk_host_sim_v2_s5_manual_keypad \
    ! -name qk_host_sim_v2_s6_watch_only \
    ! -name qk_kit_v2_s7_codec ! -name qk_kit_v2_s7_combine \
    ! -name qk_provisioning_v2_s8_kit_setup \
    ! -name qk_host_sim_v2_s9_kit_intake \
    ! -name qk_host_sim_v2_s10_kit_restore \
    ! -name qk_host_sim_v2_s11_kit_spend \
    ! -name qk_update_package ! -name qk_update_lifecycle \
    ! -name qk_ipc_wire ! -name qk_ipc_endpoint_state \
    -print -quit) || \
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
m29_entries=$(mktemp) || fail 'mktemp failed for M29 corpus entries'
m30_entries=$(mktemp) || fail 'mktemp failed for M30 corpus entries'
v2s4_entries=$(mktemp) || fail 'mktemp failed for v2 slice-4 corpus entries'
v2s5_entries=$(mktemp) || fail 'mktemp failed for v2 slice-5 corpus entries'
v2s6_entries=$(mktemp) || fail 'mktemp failed for v2 slice-6 corpus entries'
v2s7_entries=$(mktemp) || fail 'mktemp failed for v2 slice-7 corpus entries'
v2s8_entries=$(mktemp) || fail 'mktemp failed for v2 slice-8 corpus entries'
v2s9_entries=$(mktemp) || fail 'mktemp failed for v2 slice-9 corpus entries'
v2s10_entries=$(mktemp) || fail 'mktemp failed for v2 slice-10 corpus entries'
v2s11_entries=$(mktemp) || fail 'mktemp failed for v2 slice-11 corpus entries'
firmware_entries=$(mktemp) || fail 'mktemp failed for firmware corpus entries'
process_s1_entries=$(mktemp) || fail 'mktemp failed for process slice-1 corpus entries'
m21_expected=$(mktemp) || fail 'mktemp failed for M21 corpus manifest'
m22_expected=$(mktemp) || fail 'mktemp failed for M22 corpus manifest'
m23_expected=$(mktemp) || fail 'mktemp failed for M23 corpus manifest'
m24_expected=$(mktemp) || fail 'mktemp failed for M24 corpus manifest'
m25_expected=$(mktemp) || fail 'mktemp failed for M25 corpus manifest'
m26_expected=$(mktemp) || fail 'mktemp failed for M26 corpus manifest'
m27_expected=$(mktemp) || fail 'mktemp failed for M27 corpus manifest'
m28_expected=$(mktemp) || fail 'mktemp failed for M28 corpus manifest'
m29_expected=$(mktemp) || fail 'mktemp failed for M29 corpus manifest'
m30_expected=$(mktemp) || fail 'mktemp failed for M30 corpus manifest'
v2s4_expected=$(mktemp) || fail 'mktemp failed for v2 slice-4 corpus manifest'
v2s5_expected=$(mktemp) || fail 'mktemp failed for v2 slice-5 corpus manifest'
v2s6_expected=$(mktemp) || fail 'mktemp failed for v2 slice-6 corpus manifest'
v2s7_expected=$(mktemp) || fail 'mktemp failed for v2 slice-7 corpus manifest'
v2s8_expected=$(mktemp) || fail 'mktemp failed for v2 slice-8 corpus manifest'
v2s9_expected=$(mktemp) || fail 'mktemp failed for v2 slice-9 corpus manifest'
v2s10_expected=$(mktemp) || fail 'mktemp failed for v2 slice-10 corpus manifest'
v2s11_expected=$(mktemp) || fail 'mktemp failed for v2 slice-11 corpus manifest'
firmware_expected=$(mktemp) || fail 'mktemp failed for firmware corpus manifest'
process_s1_expected=$(mktemp) || fail 'mktemp failed for process slice-1 corpus manifest'
m21_paths=$(mktemp) || fail 'mktemp failed for M21 corpus paths'
m22_paths=$(mktemp) || fail 'mktemp failed for M22 corpus paths'
m23_paths=$(mktemp) || fail 'mktemp failed for M23 corpus paths'
m24_paths=$(mktemp) || fail 'mktemp failed for M24 corpus paths'
m25_paths=$(mktemp) || fail 'mktemp failed for M25 corpus paths'
m26_paths=$(mktemp) || fail 'mktemp failed for M26 corpus paths'
m27_paths=$(mktemp) || fail 'mktemp failed for M27 corpus paths'
m28_paths=$(mktemp) || fail 'mktemp failed for M28 corpus paths'
m29_paths=$(mktemp) || fail 'mktemp failed for M29 corpus paths'
m30_paths=$(mktemp) || fail 'mktemp failed for M30 corpus paths'
v2s4_paths=$(mktemp) || fail 'mktemp failed for v2 slice-4 corpus paths'
v2s5_paths=$(mktemp) || fail 'mktemp failed for v2 slice-5 corpus paths'
v2s6_paths=$(mktemp) || fail 'mktemp failed for v2 slice-6 corpus paths'
v2s7_paths=$(mktemp) || fail 'mktemp failed for v2 slice-7 corpus paths'
v2s8_paths=$(mktemp) || fail 'mktemp failed for v2 slice-8 corpus paths'
v2s9_paths=$(mktemp) || fail 'mktemp failed for v2 slice-9 corpus paths'
v2s10_paths=$(mktemp) || fail 'mktemp failed for v2 slice-10 corpus paths'
v2s11_paths=$(mktemp) || fail 'mktemp failed for v2 slice-11 corpus paths'
firmware_paths=$(mktemp) || fail 'mktemp failed for firmware corpus paths'
process_s1_paths=$(mktemp) || fail 'mktemp failed for process slice-1 corpus paths'
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
manifest_m29_paths=$(mktemp) || fail 'mktemp failed for M29 manifest paths'
manifest_m30_paths=$(mktemp) || fail 'mktemp failed for M30 manifest paths'
manifest_v2s4_paths=$(mktemp) || fail 'mktemp failed for v2 slice-4 manifest paths'
manifest_v2s5_paths=$(mktemp) || fail 'mktemp failed for v2 slice-5 manifest paths'
manifest_v2s6_paths=$(mktemp) || fail 'mktemp failed for v2 slice-6 manifest paths'
manifest_v2s7_paths=$(mktemp) || fail 'mktemp failed for v2 slice-7 manifest paths'
manifest_v2s8_paths=$(mktemp) || fail 'mktemp failed for v2 slice-8 manifest paths'
manifest_v2s9_paths=$(mktemp) || fail 'mktemp failed for v2 slice-9 manifest paths'
manifest_v2s10_paths=$(mktemp) || fail 'mktemp failed for v2 slice-10 manifest paths'
manifest_v2s11_paths=$(mktemp) || fail 'mktemp failed for v2 slice-11 manifest paths'
manifest_firmware_paths=$(mktemp) || fail 'mktemp failed for firmware manifest paths'
manifest_process_s1_paths=$(mktemp) || fail 'mktemp failed for process slice-1 manifest paths'
trap 'rm -f "$m21_entries" "$m22_entries" "$m21_expected" "$m22_expected" \
  "$m23_entries" "$m23_expected" "$m24_entries" "$m24_expected" \
  "$m25_entries" "$m25_expected" "$m26_entries" "$m26_expected" \
  "$m27_entries" "$m27_expected" "$m28_entries" "$m28_expected" \
  "$m29_entries" "$m29_expected" "$m30_entries" "$m30_expected" \
  "$v2s4_entries" "$v2s4_expected" "$v2s5_entries" "$v2s5_expected" \
  "$v2s6_entries" "$v2s6_expected" "$v2s7_entries" "$v2s7_expected" \
  "$v2s8_entries" "$v2s8_expected" "$v2s9_entries" "$v2s9_expected" \
  "$v2s10_entries" "$v2s10_expected" "$v2s11_entries" "$v2s11_expected" \
  "$firmware_entries" "$firmware_expected" \
  "$process_s1_entries" "$process_s1_expected" \
  "$m21_paths" "$m22_paths" "$m23_paths" "$m24_paths" "$m25_paths" \
  "$m26_paths" "$m27_paths" "$m28_paths" "$m29_paths" "$m30_paths" \
  "$v2s4_paths" "$v2s5_paths" "$v2s6_paths" "$v2s7_paths" "$v2s8_paths" \
  "$v2s9_paths" "$v2s10_paths" "$v2s11_paths" "$firmware_paths" \
  "$process_s1_paths" \
  "$all_paths" "$tracked_tmp" "$target_tmp" "$manifest_m21_paths" \
  "$manifest_m22_paths" "$manifest_m23_paths" "$manifest_m24_paths" \
  "$manifest_m25_paths" "$manifest_m26_paths" "$manifest_m27_paths" \
  "$manifest_m28_paths" "$manifest_m29_paths" "$manifest_m30_paths" \
  "$manifest_v2s4_paths" "$manifest_v2s5_paths" \
  "$manifest_v2s6_paths" "$manifest_v2s7_paths" \
  "$manifest_v2s8_paths" "$manifest_v2s9_paths" "$manifest_v2s10_paths" \
  "$manifest_v2s11_paths" "$manifest_firmware_paths" \
  "$manifest_process_s1_paths"' EXIT HUP INT TERM

emit_partition_entries "$m21_targets" "$m21_entries"
emit_partition_entries "$m22_targets" "$m22_entries"
emit_partition_entries "$m23_targets" "$m23_entries"
emit_partition_entries "$m24_targets" "$m24_entries"
emit_partition_entries "$m25_targets" "$m25_entries"
emit_partition_entries "$m26_targets" "$m26_entries"
emit_partition_entries "$m27_targets" "$m27_entries"
emit_partition_entries "$m28_targets" "$m28_entries"
emit_partition_entries "$m29_targets" "$m29_entries"
emit_partition_entries "$m30_targets" "$m30_entries"
emit_partition_entries "$v2s4_targets" "$v2s4_entries"
emit_partition_entries "$v2s5_targets" "$v2s5_entries"
emit_partition_entries "$v2s6_targets" "$v2s6_entries"
emit_partition_entries "$v2s7_targets" "$v2s7_entries"
emit_partition_entries "$v2s8_targets" "$v2s8_entries"
emit_partition_entries "$v2s9_targets" "$v2s9_entries"
emit_partition_entries "$v2s10_targets" "$v2s10_entries"
emit_partition_entries "$v2s11_targets" "$v2s11_entries"
emit_partition_entries "$firmware_targets" "$firmware_entries"
emit_partition_entries "$process_s1_targets" "$process_s1_entries"
cut -f 5 "$m21_entries" | LC_ALL=C sort > "$m21_paths" || fail 'cannot list M21 corpus paths'
cut -f 5 "$m22_entries" | LC_ALL=C sort > "$m22_paths" || fail 'cannot list M22 corpus paths'
cut -f 5 "$m23_entries" | LC_ALL=C sort > "$m23_paths" || fail 'cannot list M23 corpus paths'
cut -f 5 "$m24_entries" | LC_ALL=C sort > "$m24_paths" || fail 'cannot list M24 corpus paths'
cut -f 5 "$m25_entries" | LC_ALL=C sort > "$m25_paths" || fail 'cannot list M25 corpus paths'
cut -f 5 "$m26_entries" | LC_ALL=C sort > "$m26_paths" || fail 'cannot list M26 corpus paths'
cut -f 5 "$m27_entries" | LC_ALL=C sort > "$m27_paths" || fail 'cannot list M27 corpus paths'
cut -f 5 "$m28_entries" | LC_ALL=C sort > "$m28_paths" || fail 'cannot list M28 corpus paths'
cut -f 5 "$m29_entries" | LC_ALL=C sort > "$m29_paths" || fail 'cannot list M29 corpus paths'
cut -f 5 "$m30_entries" | LC_ALL=C sort > "$m30_paths" || fail 'cannot list M30 corpus paths'
cut -f 5 "$v2s4_entries" | LC_ALL=C sort > "$v2s4_paths" || \
  fail 'cannot list v2 slice-4 corpus paths'
cut -f 5 "$v2s5_entries" | LC_ALL=C sort > "$v2s5_paths" || \
  fail 'cannot list v2 slice-5 corpus paths'
cut -f 5 "$v2s6_entries" | LC_ALL=C sort > "$v2s6_paths" || \
  fail 'cannot list v2 slice-6 corpus paths'
cut -f 5 "$v2s7_entries" | LC_ALL=C sort > "$v2s7_paths" || \
  fail 'cannot list v2 slice-7 corpus paths'
cut -f 5 "$v2s8_entries" | LC_ALL=C sort > "$v2s8_paths" || \
  fail 'cannot list v2 slice-8 corpus paths'
cut -f 5 "$v2s9_entries" | LC_ALL=C sort > "$v2s9_paths" || \
  fail 'cannot list v2 slice-9 corpus paths'
cut -f 5 "$v2s10_entries" | LC_ALL=C sort > "$v2s10_paths" || \
  fail 'cannot list v2 slice-10 corpus paths'
cut -f 5 "$v2s11_entries" | LC_ALL=C sort > "$v2s11_paths" || \
  fail 'cannot list v2 slice-11 corpus paths'
cut -f 5 "$firmware_entries" | LC_ALL=C sort > "$firmware_paths" || \
  fail 'cannot list firmware corpus paths'
cut -f 5 "$process_s1_entries" | LC_ALL=C sort > "$process_s1_paths" || \
  fail 'cannot list process slice-1 corpus paths'
cat "$m21_paths" "$m22_paths" "$m23_paths" "$m24_paths" "$m25_paths" \
  "$m26_paths" "$m27_paths" "$m28_paths" "$m29_paths" "$m30_paths" \
  "$v2s4_paths" "$v2s5_paths" "$v2s6_paths" "$v2s7_paths" "$v2s8_paths" \
  "$v2s9_paths" "$v2s10_paths" "$v2s11_paths" "$firmware_paths" \
  "$process_s1_paths" | \
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
    m21_descriptor_source=$(manifest_target_source "$m21_manifest" qk_descriptor)
    m22_source=$(manifest_source "$m22_manifest")
    m23_source=$(manifest_source "$m23_manifest")
    m23_review_v3_source=$(manifest_target_source "$m23_manifest" qk_psbt_m23)
    m24_source=$(manifest_source "$m24_manifest")
    m25_source=$(manifest_source "$m25_manifest")
    m26_source=$(manifest_source "$m26_manifest")
    m27_source=$(manifest_source "$m27_manifest")
    m28_source=$(manifest_source "$m28_manifest")
    m29_source=$(manifest_source "$m29_manifest")
    m30_source=$(manifest_source "$m30_manifest")
    v2s4_source=$(manifest_source "$v2s4_manifest")
    v2s5_source=$(manifest_source "$v2s5_manifest")
    v2s6_source=$(manifest_source "$v2s6_manifest")
    v2s7_source=$(manifest_source "$v2s7_manifest")
    v2s8_source=$(manifest_source "$v2s8_manifest")
    v2s9_source=$(manifest_source "$v2s9_manifest")
    v2s10_source=$(manifest_source "$v2s10_manifest")
    v2s11_source=$(manifest_source "$v2s11_manifest")
    if [ "$firmware_registered" = yes ]; then
      firmware_source=$(manifest_source "$firmware_manifest")
    fi
    if [ "$process_s1_registered" = yes ]; then
      process_s1_source=$(manifest_source "$process_s1_manifest")
    fi
    render_partition 'QK-M21-CORPUS-MANIFEST-V2' "$m21_source" "$m21_targets" \
      "$m21_order" "$m21_entries" "$m21_expected" qk_descriptor \
      "$m21_descriptor_source"
    render_partition 'QK-M22-CORPUS-MANIFEST-V1' "$m22_source" "$m22_targets" \
      "$m22_order" "$m22_entries" "$m22_expected"
    render_partition 'QK-M23-CORPUS-MANIFEST-V2' "$m23_source" "$m23_targets" \
      "$m23_order" "$m23_entries" "$m23_expected" qk_psbt_m23 \
      "$m23_review_v3_source"
    render_partition 'QK-M24-CORPUS-MANIFEST-V2' "$m24_source" "$m24_targets" \
      "$m24_order" "$m24_entries" "$m24_expected"
    render_partition 'QK-M25-CORPUS-MANIFEST-V1' "$m25_source" "$m25_targets" \
      "$m25_order" "$m25_entries" "$m25_expected"
    render_partition 'QK-M26-CORPUS-MANIFEST-V1' "$m26_source" "$m26_targets" \
      "$m26_order" "$m26_entries" "$m26_expected"
    render_partition 'QK-M27-CORPUS-MANIFEST-V1' "$m27_source" "$m27_targets" \
      "$m27_order" "$m27_entries" "$m27_expected"
    render_partition 'QK-M28-CORPUS-MANIFEST-V1' "$m28_source" "$m28_targets" \
      "$m28_order" "$m28_entries" "$m28_expected"
    render_partition 'QK-M29-CORPUS-MANIFEST-V1' "$m29_source" "$m29_targets" \
      "$m29_order" "$m29_entries" "$m29_expected"
    render_partition 'QK-M30-CORPUS-MANIFEST-V1' "$m30_source" "$m30_targets" \
      "$m30_order" "$m30_entries" "$m30_expected"
    render_partition 'QK-V2-S4-CORPUS-MANIFEST-V1' "$v2s4_source" "$v2s4_targets" \
      "$v2s4_order" "$v2s4_entries" "$v2s4_expected"
    render_partition 'QK-V2-S5-CORPUS-MANIFEST-V1' "$v2s5_source" "$v2s5_targets" \
      "$v2s5_order" "$v2s5_entries" "$v2s5_expected"
    render_partition 'QK-V2-S6-CORPUS-MANIFEST-V1' "$v2s6_source" "$v2s6_targets" \
      "$v2s6_order" "$v2s6_entries" "$v2s6_expected"
    render_partition 'QK-V2-S7-CORPUS-MANIFEST-V1' "$v2s7_source" "$v2s7_targets" \
      "$v2s7_order" "$v2s7_entries" "$v2s7_expected"
    render_partition 'QK-V2-S8-CORPUS-MANIFEST-V1' "$v2s8_source" "$v2s8_targets" \
      "$v2s8_order" "$v2s8_entries" "$v2s8_expected"
    render_partition 'QK-V2-S9-CORPUS-MANIFEST-V1' "$v2s9_source" "$v2s9_targets" \
      "$v2s9_order" "$v2s9_entries" "$v2s9_expected"
    render_partition 'QK-V2-S10-CORPUS-MANIFEST-V1' "$v2s10_source" "$v2s10_targets" \
      "$v2s10_order" "$v2s10_entries" "$v2s10_expected"
    render_partition 'QK-V2-S11-CORPUS-MANIFEST-V1' "$v2s11_source" "$v2s11_targets" \
      "$v2s11_order" "$v2s11_entries" "$v2s11_expected"
    if [ "$firmware_registered" = yes ]; then
      render_partition 'QK-FIRMWARE-V1-CORPUS-MANIFEST-V1' "$firmware_source" \
        "$firmware_targets" "$firmware_order" "$firmware_entries" "$firmware_expected"
    fi
    if [ "$process_s1_registered" = yes ]; then
      render_partition 'QK-PROCESS-S1-CORPUS-MANIFEST-V1' "$process_s1_source" \
        "$process_s1_targets" "$process_s1_order" "$process_s1_entries" \
        "$process_s1_expected"
    fi
    extract_manifest_paths "$m21_manifest" "$m21_order" "$manifest_m21_paths"
    extract_manifest_paths "$m22_manifest" "$m22_order" "$manifest_m22_paths"
    extract_manifest_paths "$m23_manifest" "$m23_order" "$manifest_m23_paths"
    extract_manifest_paths "$m24_manifest" "$m24_order" "$manifest_m24_paths"
    extract_manifest_paths "$m25_manifest" "$m25_order" "$manifest_m25_paths"
    extract_manifest_paths "$m26_manifest" "$m26_order" "$manifest_m26_paths"
    extract_manifest_paths "$m27_manifest" "$m27_order" "$manifest_m27_paths"
    extract_manifest_paths "$m28_manifest" "$m28_order" "$manifest_m28_paths"
    extract_manifest_paths "$m29_manifest" "$m29_order" "$manifest_m29_paths"
    extract_manifest_paths "$m30_manifest" "$m30_order" "$manifest_m30_paths"
    extract_manifest_paths "$v2s4_manifest" "$v2s4_order" "$manifest_v2s4_paths"
    extract_manifest_paths "$v2s5_manifest" "$v2s5_order" "$manifest_v2s5_paths"
    extract_manifest_paths "$v2s6_manifest" "$v2s6_order" "$manifest_v2s6_paths"
    extract_manifest_paths "$v2s7_manifest" "$v2s7_order" "$manifest_v2s7_paths"
    extract_manifest_paths "$v2s8_manifest" "$v2s8_order" "$manifest_v2s8_paths"
    extract_manifest_paths "$v2s9_manifest" "$v2s9_order" "$manifest_v2s9_paths"
    extract_manifest_paths "$v2s10_manifest" "$v2s10_order" "$manifest_v2s10_paths"
    extract_manifest_paths "$v2s11_manifest" "$v2s11_order" "$manifest_v2s11_paths"
    if [ "$firmware_registered" = yes ]; then
      extract_manifest_paths "$firmware_manifest" "$firmware_order" \
        "$manifest_firmware_paths"
    fi
    if [ "$process_s1_registered" = yes ]; then
      extract_manifest_paths "$process_s1_manifest" "$process_s1_order" \
        "$manifest_process_s1_paths"
    fi
    duplicate=$(cat "$manifest_m21_paths" "$manifest_m22_paths" "$manifest_m23_paths" \
      "$manifest_m24_paths" "$manifest_m25_paths" "$manifest_m26_paths" \
      "$manifest_m27_paths" "$manifest_m28_paths" "$manifest_m29_paths" \
      "$manifest_m30_paths" "$manifest_v2s4_paths" "$manifest_v2s5_paths" \
      "$manifest_v2s6_paths" "$manifest_v2s7_paths" "$manifest_v2s8_paths" \
      "$manifest_v2s9_paths" "$manifest_v2s10_paths" "$manifest_v2s11_paths" \
      "$manifest_firmware_paths" "$manifest_process_s1_paths" | \
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
    cmp -s "$m29_manifest" "$m29_expected" || \
      fail "$m29_manifest does not match the tracked M29 corpus bytes"
    cmp -s "$m30_manifest" "$m30_expected" || \
      fail "$m30_manifest does not match the tracked M30 corpus bytes"
    cmp -s "$v2s4_manifest" "$v2s4_expected" || \
      fail "$v2s4_manifest does not match the tracked v2 slice-4 corpus bytes"
    cmp -s "$v2s5_manifest" "$v2s5_expected" || \
      fail "$v2s5_manifest does not match the tracked v2 slice-5 corpus bytes"
    cmp -s "$v2s6_manifest" "$v2s6_expected" || \
      fail "$v2s6_manifest does not match the tracked v2 slice-6 corpus bytes"
    cmp -s "$v2s7_manifest" "$v2s7_expected" || \
      fail "$v2s7_manifest does not match the tracked v2 slice-7 corpus bytes"
    cmp -s "$v2s8_manifest" "$v2s8_expected" || \
      fail "$v2s8_manifest does not match the tracked v2 slice-8 corpus bytes"
    cmp -s "$v2s9_manifest" "$v2s9_expected" || \
      fail "$v2s9_manifest does not match the tracked v2 slice-9 corpus bytes"
    cmp -s "$v2s10_manifest" "$v2s10_expected" || \
      fail "$v2s10_manifest does not match the tracked v2 slice-10 corpus bytes"
    cmp -s "$v2s11_manifest" "$v2s11_expected" || \
      fail "$v2s11_manifest does not match the tracked v2 slice-11 corpus bytes"
    if [ "$firmware_registered" = yes ]; then
      cmp -s "$firmware_manifest" "$firmware_expected" || \
        fail "$firmware_manifest does not match the tracked firmware corpus bytes"
    fi
    if [ "$process_s1_registered" = yes ]; then
      cmp -s "$process_s1_manifest" "$process_s1_expected" || \
        fail "$process_s1_manifest does not match the tracked process slice-1 corpus bytes"
    fi
    ;;
  render_m21)
    m21_descriptor_source=$(manifest_target_source "$m21_manifest" qk_descriptor)
    render_partition 'QK-M21-CORPUS-MANIFEST-V2' "$render_source" "$m21_targets" \
      "$m21_order" "$m21_entries" "$m21_expected" qk_descriptor \
      "$m21_descriptor_source"
    sed -n 'p' "$m21_expected"
    ;;
  render_qk_descriptor)
    m21_source=$(manifest_source "$m21_manifest")
    render_partition 'QK-M21-CORPUS-MANIFEST-V2' "$m21_source" "$m21_targets" \
      "$m21_order" "$m21_entries" "$m21_expected" qk_descriptor "$render_source"
    sed -n 'p' "$m21_expected"
    ;;
  render_m22)
    render_partition 'QK-M22-CORPUS-MANIFEST-V1' "$render_source" "$m22_targets" \
      "$m22_order" "$m22_entries" "$m22_expected"
    sed -n 'p' "$m22_expected"
    ;;
  render_m23)
    m23_review_v3_source=$(manifest_target_source "$m23_manifest" qk_psbt_m23)
    render_partition 'QK-M23-CORPUS-MANIFEST-V2' "$render_source" "$m23_targets" \
      "$m23_order" "$m23_entries" "$m23_expected" qk_psbt_m23 \
      "$m23_review_v3_source"
    sed -n 'p' "$m23_expected"
    ;;
  render_qk_psbt_v3)
    m23_source=$(manifest_source "$m23_manifest")
    render_partition 'QK-M23-CORPUS-MANIFEST-V2' "$m23_source" "$m23_targets" \
      "$m23_order" "$m23_entries" "$m23_expected" qk_psbt_m23 "$render_source"
    sed -n 'p' "$m23_expected"
    ;;
  render_m24)
    render_partition 'QK-M24-CORPUS-MANIFEST-V2' "$render_source" "$m24_targets" \
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
  render_m29)
    render_partition 'QK-M29-CORPUS-MANIFEST-V1' "$render_source" "$m29_targets" \
      "$m29_order" "$m29_entries" "$m29_expected"
    sed -n 'p' "$m29_expected"
    ;;
  render_m30)
    render_partition 'QK-M30-CORPUS-MANIFEST-V1' "$render_source" "$m30_targets" \
      "$m30_order" "$m30_entries" "$m30_expected"
    sed -n 'p' "$m30_expected"
    ;;
  render_v2s4)
    render_partition 'QK-V2-S4-CORPUS-MANIFEST-V1' "$render_source" "$v2s4_targets" \
      "$v2s4_order" "$v2s4_entries" "$v2s4_expected"
    sed -n 'p' "$v2s4_expected"
    ;;
  render_v2s5)
    render_partition 'QK-V2-S5-CORPUS-MANIFEST-V1' "$render_source" "$v2s5_targets" \
      "$v2s5_order" "$v2s5_entries" "$v2s5_expected"
    sed -n 'p' "$v2s5_expected"
    ;;
  render_v2s6)
    render_partition 'QK-V2-S6-CORPUS-MANIFEST-V1' "$render_source" "$v2s6_targets" \
      "$v2s6_order" "$v2s6_entries" "$v2s6_expected"
    sed -n 'p' "$v2s6_expected"
    ;;
  render_v2s7)
    render_partition 'QK-V2-S7-CORPUS-MANIFEST-V1' "$render_source" "$v2s7_targets" \
      "$v2s7_order" "$v2s7_entries" "$v2s7_expected"
    sed -n 'p' "$v2s7_expected"
    ;;
  render_v2s8)
    render_partition 'QK-V2-S8-CORPUS-MANIFEST-V1' "$render_source" "$v2s8_targets" \
      "$v2s8_order" "$v2s8_entries" "$v2s8_expected"
    sed -n 'p' "$v2s8_expected"
    ;;
  render_v2s9)
    render_partition 'QK-V2-S9-CORPUS-MANIFEST-V1' "$render_source" "$v2s9_targets" \
      "$v2s9_order" "$v2s9_entries" "$v2s9_expected"
    sed -n 'p' "$v2s9_expected"
    ;;
  render_v2s10)
    render_partition 'QK-V2-S10-CORPUS-MANIFEST-V1' "$render_source" "$v2s10_targets" \
      "$v2s10_order" "$v2s10_entries" "$v2s10_expected"
    sed -n 'p' "$v2s10_expected"
    ;;
  render_v2s11)
    render_partition 'QK-V2-S11-CORPUS-MANIFEST-V1' "$render_source" "$v2s11_targets" \
      "$v2s11_order" "$v2s11_entries" "$v2s11_expected"
    sed -n 'p' "$v2s11_expected"
    ;;
  render_firmware_v1)
    render_partition 'QK-FIRMWARE-V1-CORPUS-MANIFEST-V1' "$render_source" \
      "$firmware_targets" "$firmware_order" "$firmware_entries" "$firmware_expected"
    sed -n 'p' "$firmware_expected"
    ;;
  render_process_s1)
    render_partition 'QK-PROCESS-S1-CORPUS-MANIFEST-V1' "$render_source" \
      "$process_s1_targets" "$process_s1_order" "$process_s1_entries" \
      "$process_s1_expected"
    sed -n 'p' "$process_s1_expected"
    ;;
esac

exit 0
