#!/bin/sh
# Recompute and verify the partitioned QK-DEC-106/QK-DEC-109..113/QK-DEC-116/QK-DEC-118..134/QK-DEC-136/QK-DEC-140/QK-DEC-142/QK-DEC-144/QK-DEC-145/QK-DEC-151/QK-DEC-154/QK-DEC-156/QK-DEC-161 corpus registries.
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
  source_type=$(git cat-file -t "$validated_source_value" 2>/dev/null) || \
    fail "$source_label commit does not exist: $validated_source_value"
  [ "$source_type" = commit ] || \
    fail "$source_label must name a commit object: $validated_source_value"
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

manifest_target_source_pairs() {
  manifest=$1
  configured_targets=$2
  override_target=${3:-}
  override_commit=${4:-}
  if ! awk -F '\t' -v configured="$configured_targets" '
    BEGIN {
      count = split(configured, list, " ")
      for (item = 1; item <= count; item++) expected[list[item]] = 1
    }
    $1 == "target_source" {
      if (NF != 3 || !($2 in expected) || seen[$2]) bad = 1
      seen[$2] = 1
      rows++
    }
    END {
      if (rows != count) bad = 1
      for (item = 1; item <= count; item++) {
        if (!seen[list[item]]) bad = 1
      }
      if (bad) exit 1
    }
  ' "$manifest"; then
    fail "$manifest contains malformed, unknown, duplicate, or missing target_source rows"
  fi
  if [ -n "$override_target" ] || [ -n "$override_commit" ]; then
    [ -n "$override_target" ] && [ -n "$override_commit" ] || \
      fail 'target_source override requires both target and commit'
    case " $configured_targets " in
      *" $override_target "*) ;;
      *) fail "target_source override names unknown target: $override_target" ;;
    esac
    validate_source_commit "$override_commit" target_source
  fi
  target_source_pairs=''
  for target_source_target in $configured_targets; do
    if [ "$target_source_target" = "$override_target" ]; then
      target_source_commit=$override_commit
    else
      target_source_commit=$(awk -F '\t' -v expected="$target_source_target" \
        '$1 == "target_source" && $2 == expected { print $3 }' "$manifest") || \
        fail "cannot read target_source from $manifest"
      validate_source_commit "$target_source_commit" target_source
    fi
    target_source_pairs="${target_source_pairs}${target_source_pairs:+ }${target_source_target} ${target_source_commit}"
  done
  printf '%s\n' "$target_source_pairs"
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
  target_source_pairs=${7:-}

  validate_source_commit "$source_commit"
  seen_target_sources=''
  set -- $target_source_pairs
  while [ "$#" -gt 0 ]; do
    [ "$#" -ge 2 ] || fail 'target_source pairs have odd arity'
    target_source_target=$1
    target_source_commit=$2
    shift 2
    validate_source_commit "$target_source_commit" target_source
    case " $targets " in
      *" $target_source_target "*) ;;
      *) fail "target_source names unknown target: $target_source_target" ;;
    esac
    case " $seen_target_sources " in
      *" $target_source_target "*) fail "duplicate target_source: $target_source_target" ;;
      *) seen_target_sources="${seen_target_sources}${seen_target_sources:+ }$target_source_target" ;;
    esac
  done
  total_count=$(wc -l < "$entries" | tr -d ' ')
  total_bytes=$(awk -F '\t' '{ sum += $3 } END { print sum + 0 }' "$entries")
  total_hash=$(sha256_file "$entries") || fail 'cannot hash aggregate corpus entries'

  {
    printf '%s\n' "$version"
    printf 'campaign_source\t%s\n' "$source_commit"
    set -- $target_source_pairs
    while [ "$#" -gt 0 ]; do
      target_source_target=$1
      target_source_commit=$2
      shift 2
      printf 'target_source\t%s\t%s\n' "$target_source_target" "$target_source_commit"
    done
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
process_s2_manifest='fuzz/CORPUS-MANIFEST-PROCESS-S2.tsv'
process_s3_manifest='fuzz/CORPUS-MANIFEST-PROCESS-S3.tsv'
process_s4_manifest='fuzz/CORPUS-MANIFEST-PROCESS-S4.tsv'
process_s5_manifest='fuzz/CORPUS-MANIFEST-PROCESS-S5.tsv'
process_s5_campaign='fuzz/CAMPAIGN-024.md'
process_s6_manifest='fuzz/CORPUS-MANIFEST-PROCESS-S6.tsv'
process_s6_campaign='fuzz/CAMPAIGN-025.md'
process_s7_manifest='fuzz/CORPUS-MANIFEST-PROCESS-S7.tsv'
process_s7_campaign='fuzz/CAMPAIGN-026.md'
process_s8_manifest='fuzz/CORPUS-MANIFEST-PROCESS-S8.tsv'
process_s8_campaign='fuzz/CAMPAIGN-027.md'
process_s8_target='fuzz/fuzz_targets/qk_supervisor_process_lifecycle.rs'
process_s9_manifest='fuzz/CORPUS-MANIFEST-PROCESS-S9.tsv'
process_s9_campaign='fuzz/CAMPAIGN-028.md'
process_s9_wire_target='fuzz/fuzz_targets/qk_device_wire.rs'
process_s9_core_target='fuzz/fuzz_targets/qk_core_normal_process.rs'
card_s1_manifest='fuzz/CORPUS-MANIFEST-CARD-S1.tsv'
card_s1_campaign='fuzz/CAMPAIGN-029.md'
card_s1_protocol_target='fuzz/fuzz_targets/qk_card_protocol.rs'
card_s1_model_target='fuzz/fuzz_targets/qk_card_model.rs'
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
process_s2_targets='qk_supervisor_lifecycle qk_decoy_calculator'
process_s3_targets='qk_io_ingress qk_io_egress qk_io_session'
process_s4_targets='qk_core_io_peer qk_core_session'
process_s5_targets='qk_core_provisioning_entry qk_core_provisioning_run'
process_s6_targets='qk_core_normal_entry qk_core_normal_run'
process_s7_targets='qk_core_io_peer qk_core_session qk_core_provisioning_entry qk_core_provisioning_run qk_core_normal_entry qk_core_normal_run qk_core_kit_intake qk_core_kit_restore qk_core_kit_spend'
process_s7_new_targets='qk_core_kit_intake qk_core_kit_restore qk_core_kit_spend'
process_s8_targets='qk_supervisor_lifecycle qk_supervisor_process_lifecycle'
process_s8_new_targets='qk_supervisor_process_lifecycle'
process_s9_targets='qk_device_wire qk_core_normal_process'
card_s1_targets='qk_card_protocol qk_card_model qk_device_wire qk_core_normal_process'
card_s1_new_targets='qk_card_protocol qk_card_model'
base_targets="$m21_targets $m22_targets $m23_targets $m24_targets $m25_targets $m26_targets $m27_targets $m28_targets $m29_targets $m30_targets $v2s4_targets $v2s5_targets $v2s6_targets $v2s7_targets $v2s8_targets $v2s9_targets $v2s10_targets $v2s11_targets $firmware_targets $process_s1_targets $process_s2_targets $process_s3_targets $process_s4_targets"
all_targets="$base_targets $process_s8_new_targets"
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
process_s2_order='qk_supervisor_lifecycle,qk_decoy_calculator'
process_s3_order='qk_io_ingress,qk_io_egress,qk_io_session'
process_s4_order='qk_core_io_peer,qk_core_session'
process_s5_order='qk_core_provisioning_entry,qk_core_provisioning_run'
process_s6_order='qk_core_normal_entry,qk_core_normal_run'
process_s7_order='qk_core_io_peer,qk_core_session,qk_core_provisioning_entry,qk_core_provisioning_run,qk_core_normal_entry,qk_core_normal_run,qk_core_kit_intake,qk_core_kit_restore,qk_core_kit_spend'
process_s8_order='qk_supervisor_lifecycle,qk_supervisor_process_lifecycle'
process_s9_order='qk_device_wire,qk_core_normal_process'
card_s1_order='qk_card_protocol,qk_card_model,qk_device_wire,qk_core_normal_process'

usage='usage: check-fuzz-corpora.sh [--render SOURCE_COMMIT | --render-qk-descriptor SOURCE_COMMIT | --render-qk-psbt-v3 SOURCE_COMMIT | --render-m22 SOURCE_COMMIT | --render-m23 SOURCE_COMMIT | --render-m24 SOURCE_COMMIT | --render-m25 SOURCE_COMMIT | --render-m26 SOURCE_COMMIT | --render-m27 SOURCE_COMMIT | --render-m28 SOURCE_COMMIT | --render-m29 SOURCE_COMMIT | --render-m30 SOURCE_COMMIT | --render-v2-s4 SOURCE_COMMIT | --render-v2-s5 SOURCE_COMMIT | --render-v2-s6 SOURCE_COMMIT | --render-v2-s7 SOURCE_COMMIT | --render-v2-s8 SOURCE_COMMIT | --render-v2-s9 SOURCE_COMMIT | --render-v2-s10 SOURCE_COMMIT | --render-v2-s11 SOURCE_COMMIT | --render-firmware-v1 SOURCE_COMMIT | --render-process-s1 SOURCE_COMMIT | --render-process-s2 SOURCE_COMMIT | --render-process-s3 SOURCE_COMMIT | --render-process-s4 SOURCE_COMMIT | --render-process-s5 SOURCE_COMMIT | --render-process-s6 SOURCE_COMMIT | --render-process-s7 SOURCE_COMMIT | --render-process-s8 SOURCE_COMMIT | --render-process-s9 SOURCE_COMMIT | --render-card-s1 SOURCE_COMMIT]'

# id | report label | manifest version | registration flag | target-source target |
# manifest-ownership check. This is the single ordered partition registry used
# by every table-driven render, path-extraction, and comparison pass below.
partition_ids=''
while IFS='|' read -r id label version registration target_source manifest_owner; do
  [ -n "$id" ] || continue
  partition_ids="${partition_ids}${partition_ids:+ }$id"
  eval "${id}_label=\$label"
  eval "${id}_version=\$version"
  eval "${id}_registration=\$registration"
  eval "${id}_target_source=\$target_source"
  eval "${id}_manifest_owner=\$manifest_owner"
done <<'PARTITIONS'
m21|M21|QK-M21-CORPUS-MANIFEST-V2|always|qk_descriptor|yes
m22|M22|QK-M22-CORPUS-MANIFEST-V1|always||yes
m23|M23|QK-M23-CORPUS-MANIFEST-V2|always|qk_psbt_m23|yes
m24|M24|QK-M24-CORPUS-MANIFEST-V2|always||yes
m25|M25|QK-M25-CORPUS-MANIFEST-V1|always||yes
m26|M26|QK-M26-CORPUS-MANIFEST-V1|always||yes
m27|M27|QK-M27-CORPUS-MANIFEST-V1|always||yes
m28|M28|QK-M28-CORPUS-MANIFEST-V1|always||yes
m29|M29|QK-M29-CORPUS-MANIFEST-V1|always||yes
m30|M30|QK-M30-CORPUS-MANIFEST-V1|always||yes
v2s4|v2 slice-4|QK-V2-S4-CORPUS-MANIFEST-V1|always||yes
v2s5|v2 slice-5|QK-V2-S5-CORPUS-MANIFEST-V1|always||yes
v2s6|v2 slice-6|QK-V2-S6-CORPUS-MANIFEST-V1|always||yes
v2s7|v2 slice-7|QK-V2-S7-CORPUS-MANIFEST-V1|always||yes
v2s8|v2 slice-8|QK-V2-S8-CORPUS-MANIFEST-V1|always||yes
v2s9|v2 slice-9|QK-V2-S9-CORPUS-MANIFEST-V1|always||yes
v2s10|v2 slice-10|QK-V2-S10-CORPUS-MANIFEST-V1|always||yes
v2s11|v2 slice-11|QK-V2-S11-CORPUS-MANIFEST-V1|always||yes
firmware|firmware|QK-FIRMWARE-V1-CORPUS-MANIFEST-V1|firmware_registered||yes
process_s1|process slice-1|QK-PROCESS-S1-CORPUS-MANIFEST-V1|process_s1_registered||yes
process_s2|process slice-2|QK-PROCESS-S2-CORPUS-MANIFEST-V1|process_s2_registered||yes
process_s3|process slice-3|QK-PROCESS-S3-CORPUS-MANIFEST-V1|process_s3_registered||yes
process_s4|process slice-4|QK-PROCESS-S4-CORPUS-MANIFEST-V1|process_s4_registered||yes
process_s5|process slice-5|QK-PROCESS-S5-CORPUS-MANIFEST-V1|process_s5_registered||yes
process_s6|process slice-6|QK-PROCESS-S6-CORPUS-MANIFEST-V1|process_s6_registered||yes
process_s7|process slice-7|QK-PROCESS-S7-CORPUS-MANIFEST-V1|process_s7_registered||no
process_s8|process slice-8|QK-PROCESS-S8-CORPUS-MANIFEST-V1|process_s8_registered||no
process_s9|process slice-9|QK-PROCESS-S9-CORPUS-MANIFEST-V1|process_s9_registered|qk_core_normal_process|yes
card_s1|card slice-1|QK-CARD-S1-CORPUS-MANIFEST-V1|card_s1_registered|qk_card_model qk_core_normal_process|no
PARTITIONS

partition_values() {
  partition_id=$1
  eval "partition_label=\${${partition_id}_label}"
  eval "partition_version=\${${partition_id}_version}"
  eval "partition_registration=\${${partition_id}_registration}"
  eval "partition_target_source=\${${partition_id}_target_source}"
  eval "partition_manifest_owner=\${${partition_id}_manifest_owner}"
  eval "partition_manifest=\${${partition_id}_manifest}"
  eval "partition_targets=\${${partition_id}_targets}"
  eval "partition_order=\${${partition_id}_order}"
  eval "partition_entries=\${${partition_id}_entries}"
  eval "partition_expected=\${${partition_id}_expected}"
  eval "partition_paths=\${${partition_id}_paths}"
  eval "partition_manifest_paths=\${manifest_${partition_id}_paths}"
}

partition_registered() {
  [ "$partition_registration" = always ] && return 0
  eval "[ \"\${$partition_registration}\" = yes ]"
}

select_render_mode() {
  selected_option=$1
  mode=''
  render_partition_id=''
  render_target_override=''
  while IFS='|' read -r option option_mode option_partition option_target; do
    if [ "$selected_option" = "$option" ]; then
      mode=$option_mode
      render_partition_id=$option_partition
      render_target_override=$option_target
      break
    fi
  done <<'RENDER_MODES'
--render|render_m21|m21|
--render-qk-descriptor|render_qk_descriptor|m21|qk_descriptor
--render-qk-psbt-v3|render_qk_psbt_v3|m23|qk_psbt_m23
--render-m22|render_m22|m22|
--render-m23|render_m23|m23|
--render-m24|render_m24|m24|
--render-m25|render_m25|m25|
--render-m26|render_m26|m26|
--render-m27|render_m27|m27|
--render-m28|render_m28|m28|
--render-m29|render_m29|m29|
--render-m30|render_m30|m30|
--render-v2-s4|render_v2s4|v2s4|
--render-v2-s5|render_v2s5|v2s5|
--render-v2-s6|render_v2s6|v2s6|
--render-v2-s7|render_v2s7|v2s7|
--render-v2-s8|render_v2s8|v2s8|
--render-v2-s9|render_v2s9|v2s9|
--render-v2-s10|render_v2s10|v2s10|
--render-v2-s11|render_v2s11|v2s11|
--render-firmware-v1|render_firmware_v1|firmware|
--render-process-s1|render_process_s1|process_s1|
--render-process-s2|render_process_s2|process_s2|
--render-process-s3|render_process_s3|process_s3|
--render-process-s4|render_process_s4|process_s4|
--render-process-s5|render_process_s5|process_s5|
--render-process-s6|render_process_s6|process_s6|
--render-process-s7|render_process_s7|process_s7|
--render-process-s8|render_process_s8|process_s8|
--render-process-s9|render_process_s9|process_s9|
--render-card-s1|render_card_s1|card_s1|qk_card_model
RENDER_MODES
  [ -n "$mode" ] || fail "$usage"
}

mode=check
render_source=''
render_partition_id=''
render_target_override=''
case "$#" in
  0) ;;
  2)
    select_render_mode "$1"
    render_source=$2
    if [ -n "$render_target_override" ]; then
      validate_source_commit "$render_source" target_source
    else
      validate_source_commit "$render_source"
    fi
    ;;
  *) fail "$usage" ;;
esac

# QK-DEC-151 pre-campaign renderer. Campaign 026 activates this partition in
# the full checker only after the final-code campaigns and minimizations.
if [ "$mode" = render_process_s7 ]; then
  process_s7_entries=$(mktemp) || fail 'mktemp failed for process slice-7 corpus entries'
  process_s7_expected=$(mktemp) || fail 'mktemp failed for process slice-7 corpus manifest'
  target_tmp=$(mktemp) || fail 'mktemp failed for process slice-7 target entries'
  trap 'rm -f "$process_s7_entries" "$process_s7_expected" "$target_tmp"' EXIT HUP INT TERM
  emit_partition_entries "$process_s7_targets" "$process_s7_entries"
  render_partition 'QK-PROCESS-S7-CORPUS-MANIFEST-V1' "$render_source" \
    "$process_s7_targets" "$process_s7_order" "$process_s7_entries" \
    "$process_s7_expected"
  sed -n 'p' "$process_s7_expected"
  exit 0
fi

# QK-DEC-154 pre-campaign renderer. Campaign 027 activates this partition in
# the full checker only after the final-code campaigns and minimizations.
if [ "$mode" = render_process_s8 ]; then
  process_s8_entries=$(mktemp) || fail 'mktemp failed for process slice-8 corpus entries'
  process_s8_expected=$(mktemp) || fail 'mktemp failed for process slice-8 corpus manifest'
  target_tmp=$(mktemp) || fail 'mktemp failed for process slice-8 target entries'
  trap 'rm -f "$process_s8_entries" "$process_s8_expected" "$target_tmp"' EXIT HUP INT TERM
  emit_partition_entries "$process_s8_targets" "$process_s8_entries"
  render_partition 'QK-PROCESS-S8-CORPUS-MANIFEST-V1' "$render_source" \
    "$process_s8_targets" "$process_s8_order" "$process_s8_entries" \
    "$process_s8_expected"
  sed -n 'p' "$process_s8_expected"
  exit 0
fi

# QK-DEC-156 pre-campaign renderer. Campaign 028 activates this partition in
# the full checker only after the final-code campaigns and minimizations.
if [ "$mode" = render_process_s9 ]; then
  process_s9_entries=$(mktemp) || fail 'mktemp failed for process slice-9 corpus entries'
  process_s9_expected=$(mktemp) || fail 'mktemp failed for process slice-9 corpus manifest'
  target_tmp=$(mktemp) || fail 'mktemp failed for process slice-9 target entries'
  trap 'rm -f "$process_s9_entries" "$process_s9_expected" "$target_tmp"' EXIT HUP INT TERM
  emit_partition_entries "$process_s9_targets" "$process_s9_entries"
  process_s9_target_source_pairs=$(
    manifest_target_source_pairs "$process_s9_manifest" "$process_s9_target_source"
  )
  render_partition 'QK-PROCESS-S9-CORPUS-MANIFEST-V1' "$render_source" \
    "$process_s9_targets" "$process_s9_order" "$process_s9_entries" \
    "$process_s9_expected" "$process_s9_target_source_pairs"
  sed -n 'p' "$process_s9_expected"
  exit 0
fi

# QK-DEC-161 pre-campaign renderer. Campaign 029 activates this partition in
# the full checker only after the final-code campaigns and minimizations.
if [ "$mode" = render_card_s1 ]; then
  card_s1_entries=$(mktemp) || fail 'mktemp failed for card slice-1 corpus entries'
  card_s1_expected=$(mktemp) || fail 'mktemp failed for card slice-1 corpus manifest'
  target_tmp=$(mktemp) || fail 'mktemp failed for card slice-1 target entries'
  trap 'rm -f "$card_s1_entries" "$card_s1_expected" "$target_tmp"' EXIT HUP INT TERM
  emit_partition_entries "$card_s1_targets" "$card_s1_entries"
  card_s1_source=$(manifest_source "$card_s1_manifest")
  card_s1_target_source_pairs=$(
    manifest_target_source_pairs "$card_s1_manifest" "$card_s1_target_source" \
      qk_card_model "$render_source"
  )
  render_partition 'QK-CARD-S1-CORPUS-MANIFEST-V1' "$card_s1_source" \
    "$card_s1_targets" "$card_s1_order" "$card_s1_entries" \
    "$card_s1_expected" "$card_s1_target_source_pairs"
  sed -n 'p' "$card_s1_expected"
  exit 0
fi

firmware_registered=no
process_s1_registered=no
process_s2_registered=no
process_s3_registered=no
process_s4_registered=no
process_s5_registered=no
process_s5_active=no
process_s6_registered=no
process_s6_active=no
process_s7_registered=no
process_s7_active=no
process_s8_registered=no
process_s9_registered=no
process_s9_active=no
card_s1_registered=no
card_s1_active=no
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
  [ -f fuzz/CAMPAIGN-021.md ] || fail 'fuzz/CAMPAIGN-021.md is missing'
  [ ! -L fuzz/CAMPAIGN-021.md ] || fail 'fuzz/CAMPAIGN-021.md must not be a symlink'
  git ls-files --error-unmatch -- fuzz/CAMPAIGN-021.md >/dev/null 2>&1 || \
    fail 'fuzz/CAMPAIGN-021.md is untracked'
  [ -f fuzz/CAMPAIGN-022.md ] || fail 'fuzz/CAMPAIGN-022.md is missing'
  [ ! -L fuzz/CAMPAIGN-022.md ] || fail 'fuzz/CAMPAIGN-022.md must not be a symlink'
  git ls-files --error-unmatch -- fuzz/CAMPAIGN-022.md >/dev/null 2>&1 || \
    fail 'fuzz/CAMPAIGN-022.md is untracked'
  [ -f fuzz/CAMPAIGN-023.md ] || fail 'fuzz/CAMPAIGN-023.md is missing'
  [ ! -L fuzz/CAMPAIGN-023.md ] || fail 'fuzz/CAMPAIGN-023.md must not be a symlink'
  git ls-files --error-unmatch -- fuzz/CAMPAIGN-023.md >/dev/null 2>&1 || \
    fail 'fuzz/CAMPAIGN-023.md is untracked'
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
  if [ -e "$process_s2_manifest" ]; then
    [ -f "$process_s2_manifest" ] || fail "$process_s2_manifest is not a regular file"
    [ ! -L "$process_s2_manifest" ] || fail "$process_s2_manifest must not be a symlink"
    git ls-files --error-unmatch -- "$process_s2_manifest" >/dev/null 2>&1 || \
      fail "$process_s2_manifest is untracked"
    grep -Fqx 'Status: EXECUTED — QUALIFYING RUN COMPLETE.' fuzz/CAMPAIGN-021.md || \
      fail 'registered process slice-2 corpus requires completed campaign status'
    process_s2_registered=yes
  else
    grep -Fqx 'Status: PLANNED — NOT EXECUTED.' fuzz/CAMPAIGN-021.md || \
      fail 'process slice-2 corpus manifest is absent without the planned campaign status'
  fi
  if [ -e "$process_s3_manifest" ]; then
    [ -f "$process_s3_manifest" ] || fail "$process_s3_manifest is not a regular file"
    [ ! -L "$process_s3_manifest" ] || fail "$process_s3_manifest must not be a symlink"
    git ls-files --error-unmatch -- "$process_s3_manifest" >/dev/null 2>&1 || \
      fail "$process_s3_manifest is untracked"
    grep -Fqx 'Status: EXECUTED — QUALIFYING RUN COMPLETE.' fuzz/CAMPAIGN-022.md || \
      fail 'registered process slice-3 corpus requires completed campaign status'
    process_s3_registered=yes
  else
    grep -Fqx 'Status: PLANNED — NOT EXECUTED.' fuzz/CAMPAIGN-022.md || \
      fail 'process slice-3 corpus manifest is absent without the planned campaign status'
  fi
  if [ -e "$process_s4_manifest" ]; then
    [ -f "$process_s4_manifest" ] || fail "$process_s4_manifest is not a regular file"
    [ ! -L "$process_s4_manifest" ] || fail "$process_s4_manifest must not be a symlink"
    git ls-files --error-unmatch -- "$process_s4_manifest" >/dev/null 2>&1 || \
      fail "$process_s4_manifest is untracked"
    grep -Fqx 'Status: EXECUTED — QUALIFYING RUN COMPLETE.' fuzz/CAMPAIGN-023.md || \
      fail 'registered process slice-4 corpus requires completed campaign status'
    process_s4_registered=yes
  else
    grep -Fqx 'Status: PLANNED — NOT EXECUTED.' fuzz/CAMPAIGN-023.md || \
      fail 'process slice-4 corpus manifest is absent without the planned campaign status'
  fi
  [ -f "$process_s5_campaign" ] || fail "$process_s5_campaign is missing"
  [ ! -L "$process_s5_campaign" ] || fail "$process_s5_campaign must not be a symlink"
  git ls-files --error-unmatch -- "$process_s5_campaign" >/dev/null 2>&1 || \
    fail "$process_s5_campaign is untracked"
  if [ -e "$process_s5_manifest" ] || [ -L "$process_s5_manifest" ]; then
    [ -f "$process_s5_manifest" ] || fail "$process_s5_manifest is not a regular file"
    [ ! -L "$process_s5_manifest" ] || fail "$process_s5_manifest must not be a symlink"
    git ls-files --error-unmatch -- "$process_s5_manifest" >/dev/null 2>&1 || \
      fail "$process_s5_manifest is untracked"
    grep -Fqx 'Status: EXECUTED — QUALIFYING RUN COMPLETE.' "$process_s5_campaign" || \
      fail 'registered process slice-5 corpus requires completed campaign status'
    process_s5_active=yes
    process_s5_registered=yes
  else
    grep -Fqx 'Status: PLANNED — NOT EXECUTED.' "$process_s5_campaign" || \
      fail 'process slice-5 corpus manifest is absent without the planned campaign status'
    process_s5_active=yes
  fi
  [ -f "$process_s6_campaign" ] || fail "$process_s6_campaign is missing"
  [ ! -L "$process_s6_campaign" ] || fail "$process_s6_campaign must not be a symlink"
  git ls-files --error-unmatch -- "$process_s6_campaign" >/dev/null 2>&1 || \
    fail "$process_s6_campaign is untracked"
  process_s6_active=yes
  if [ -e "$process_s6_manifest" ] || [ -L "$process_s6_manifest" ]; then
    [ -f "$process_s6_manifest" ] || fail "$process_s6_manifest is not a regular file"
    [ ! -L "$process_s6_manifest" ] || fail "$process_s6_manifest must not be a symlink"
    git ls-files --error-unmatch -- "$process_s6_manifest" >/dev/null 2>&1 || \
      fail "$process_s6_manifest is untracked"
    grep -Fqx 'Status: EXECUTED — QUALIFYING RUN COMPLETE.' "$process_s6_campaign" || \
      fail 'registered process slice-6 corpus requires completed campaign status'
    process_s6_registered=yes
  else
    grep -Fqx 'Status: PLANNED — NOT EXECUTED.' "$process_s6_campaign" || \
      fail 'process slice-6 corpus manifest is absent without the planned campaign status'
  fi
  [ -f "$process_s7_campaign" ] || fail "$process_s7_campaign is missing"
  [ ! -L "$process_s7_campaign" ] || fail "$process_s7_campaign must not be a symlink"
  git ls-files --error-unmatch -- "$process_s7_campaign" >/dev/null 2>&1 || \
    fail "$process_s7_campaign is untracked"
  process_s7_active=yes
  if [ -e "$process_s7_manifest" ] || [ -L "$process_s7_manifest" ]; then
    [ -f "$process_s7_manifest" ] || fail "$process_s7_manifest is not a regular file"
    [ ! -L "$process_s7_manifest" ] || fail "$process_s7_manifest must not be a symlink"
    git ls-files --error-unmatch -- "$process_s7_manifest" >/dev/null 2>&1 || \
      fail "$process_s7_manifest is untracked"
    grep -Fqx 'Status: EXECUTED — QUALIFYING RUN COMPLETE.' "$process_s7_campaign" || \
      fail 'registered process slice-7 corpus requires completed campaign status'
    process_s7_registered=yes
  else
    grep -Fqx 'Status: PLANNED — NOT EXECUTED.' "$process_s7_campaign" || \
      fail 'process slice-7 corpus manifest is absent without the planned campaign status'
  fi
  if git ls-files --error-unmatch -- "$process_s8_target" >/dev/null 2>&1; then
    [ -f "$process_s8_target" ] || fail "$process_s8_target is missing or is not a regular file"
    [ ! -L "$process_s8_target" ] || fail "$process_s8_target must not be a symlink"
    [ -f "$process_s8_campaign" ] || fail "$process_s8_campaign is not a regular file"
    [ ! -L "$process_s8_campaign" ] || fail "$process_s8_campaign must not be a symlink"
    git ls-files --error-unmatch -- "$process_s8_campaign" >/dev/null 2>&1 || \
      fail "$process_s8_campaign is untracked"
    [ -f "$process_s8_manifest" ] || fail "$process_s8_manifest is not a regular file"
    [ ! -L "$process_s8_manifest" ] || fail "$process_s8_manifest must not be a symlink"
    git ls-files --error-unmatch -- "$process_s8_manifest" >/dev/null 2>&1 || \
      fail "$process_s8_manifest is untracked"
    grep -Fqx 'Status: EXECUTED — QUALIFYING RUN COMPLETE.' "$process_s8_campaign" || \
      fail 'registered process slice-8 corpus requires completed campaign status'
    process_s8_registered=yes
  elif git ls-files --error-unmatch -- "$process_s8_campaign" >/dev/null 2>&1 || \
       git ls-files --error-unmatch -- "$process_s8_manifest" >/dev/null 2>&1 || \
       [ -e "$process_s8_campaign" ] || [ -L "$process_s8_campaign" ] || \
       [ -e "$process_s8_manifest" ] || [ -L "$process_s8_manifest" ]; then
    fail 'process slice-8 evidence exists before its target is tracked'
  fi
  process_s9_tracked=0
  for target_path in "$process_s9_wire_target" "$process_s9_core_target"; do
    if git ls-files --error-unmatch -- "$target_path" >/dev/null 2>&1; then
      process_s9_tracked=$((process_s9_tracked + 1))
      [ -f "$target_path" ] || fail "$target_path is missing or is not a regular file"
      [ ! -L "$target_path" ] || fail "$target_path must not be a symlink"
    fi
  done
  if [ "$process_s9_tracked" = 2 ]; then
    [ -f "$process_s9_campaign" ] || fail "$process_s9_campaign is not a regular file"
    [ ! -L "$process_s9_campaign" ] || fail "$process_s9_campaign must not be a symlink"
    git ls-files --error-unmatch -- "$process_s9_campaign" >/dev/null 2>&1 || \
      fail "$process_s9_campaign is untracked"
    process_s9_active=yes
    if [ -e "$process_s9_manifest" ] || [ -L "$process_s9_manifest" ]; then
      [ -f "$process_s9_manifest" ] || fail "$process_s9_manifest is not a regular file"
      [ ! -L "$process_s9_manifest" ] || fail "$process_s9_manifest must not be a symlink"
      git ls-files --error-unmatch -- "$process_s9_manifest" >/dev/null 2>&1 || \
        fail "$process_s9_manifest is untracked"
      grep -Fqx 'Status: EXECUTED — QUALIFYING RUN COMPLETE.' "$process_s9_campaign" || \
        fail 'registered process slice-9 corpus requires completed campaign status'
      process_s9_registered=yes
    else
      grep -Fqx 'Status: PLANNED — NOT EXECUTED.' "$process_s9_campaign" || \
        fail 'process slice-9 corpus manifest is absent without the planned campaign status'
    fi
  elif [ "$process_s9_tracked" != 0 ] || \
       git ls-files --error-unmatch -- "$process_s9_campaign" >/dev/null 2>&1 || \
       git ls-files --error-unmatch -- "$process_s9_manifest" >/dev/null 2>&1 || \
       [ -e "$process_s9_campaign" ] || [ -L "$process_s9_campaign" ] || \
       [ -e "$process_s9_manifest" ] || [ -L "$process_s9_manifest" ]; then
    fail 'process slice-9 target or evidence set is incomplete'
  fi
  card_s1_tracked=0
  for target_path in "$card_s1_protocol_target" "$card_s1_model_target"; do
    if git ls-files --error-unmatch -- "$target_path" >/dev/null 2>&1; then
      card_s1_tracked=$((card_s1_tracked + 1))
      [ -f "$target_path" ] || fail "$target_path is missing or is not a regular file"
      [ ! -L "$target_path" ] || fail "$target_path must not be a symlink"
    fi
  done
  if [ "$card_s1_tracked" = 2 ]; then
    [ -f "$card_s1_campaign" ] || fail "$card_s1_campaign is not a regular file"
    [ ! -L "$card_s1_campaign" ] || fail "$card_s1_campaign must not be a symlink"
    git ls-files --error-unmatch -- "$card_s1_campaign" >/dev/null 2>&1 || \
      fail "$card_s1_campaign is untracked"
    card_s1_active=yes
    if [ -e "$card_s1_manifest" ] || [ -L "$card_s1_manifest" ]; then
      [ -f "$card_s1_manifest" ] || fail "$card_s1_manifest is not a regular file"
      [ ! -L "$card_s1_manifest" ] || fail "$card_s1_manifest must not be a symlink"
      git ls-files --error-unmatch -- "$card_s1_manifest" >/dev/null 2>&1 || \
        fail "$card_s1_manifest is untracked"
      grep -Fqx 'Status: EXECUTED — QUALIFYING RUN COMPLETE.' "$card_s1_campaign" || \
        fail 'registered card slice-1 corpus requires completed campaign status'
      card_s1_registered=yes
    else
      grep -Fqx 'Status: PLANNED — NOT EXECUTED.' "$card_s1_campaign" || \
        fail 'card slice-1 corpus manifest is absent without the planned campaign status'
    fi
  elif [ "$card_s1_tracked" != 0 ] || \
       git ls-files --error-unmatch -- "$card_s1_campaign" >/dev/null 2>&1 || \
       git ls-files --error-unmatch -- "$card_s1_manifest" >/dev/null 2>&1 || \
       [ -e "$card_s1_campaign" ] || [ -L "$card_s1_campaign" ] || \
       [ -e "$card_s1_manifest" ] || [ -L "$card_s1_manifest" ]; then
    fail 'card slice-1 target or evidence set is incomplete'
  fi
elif [ "$mode" = render_process_s1 ] || [ "$mode" = render_process_s2 ] ||
     [ "$mode" = render_process_s3 ] || [ "$mode" = render_process_s4 ]; then
  process_s5_active=yes
  process_s5_registered=yes
  process_s6_active=yes
  process_s6_registered=yes
  process_s7_active=yes
elif [ "$mode" = render_process_s5 ]; then
  process_s5_active=yes
  process_s5_registered=yes
  process_s6_active=yes
  process_s6_registered=yes
  process_s7_active=yes
elif [ "$mode" = render_process_s6 ]; then
  process_s5_active=yes
  process_s5_registered=yes
  process_s6_active=yes
  process_s6_registered=yes
  process_s7_active=yes
fi

if [ "$process_s5_active" = yes ]; then
  all_targets="$all_targets $process_s5_targets"
else
  for target in $process_s5_targets; do
    if [ -e "fuzz/corpus/$target" ] || [ -L "fuzz/corpus/$target" ] || \
       [ -e "fuzz/findings/$target" ] || [ -L "fuzz/findings/$target" ]; then
      fail "unregistered process slice-5 corpus or finding root: $target"
    fi
  done
fi

if [ "$process_s6_active" = yes ]; then
  all_targets="$all_targets $process_s6_targets"
else
  for target in $process_s6_targets; do
    if [ -e "fuzz/corpus/$target" ] || [ -L "fuzz/corpus/$target" ] || \
       [ -e "fuzz/findings/$target" ] || [ -L "fuzz/findings/$target" ]; then
      fail "unregistered process slice-6 corpus or finding root: $target"
    fi
  done
fi

if [ "$process_s7_active" = yes ]; then
  all_targets="$all_targets $process_s7_new_targets"
else
  for target in $process_s7_new_targets; do
    if [ -e "fuzz/corpus/$target" ] || [ -L "fuzz/corpus/$target" ] || \
       [ -e "fuzz/findings/$target" ] || [ -L "fuzz/findings/$target" ]; then
      fail "unregistered process slice-7 corpus or finding root: $target"
    fi
  done
fi

if [ "$process_s9_active" = yes ]; then
  all_targets="$all_targets $process_s9_targets"
else
  for target in $process_s9_targets; do
    if [ -e "fuzz/corpus/$target" ] || [ -L "fuzz/corpus/$target" ] || \
       [ -e "fuzz/findings/$target" ] || [ -L "fuzz/findings/$target" ]; then
      fail "unregistered process slice-9 corpus or finding root: $target"
    fi
  done
fi

if [ "$card_s1_active" = yes ]; then
  all_targets="$all_targets $card_s1_new_targets"
else
  for target in $card_s1_new_targets; do
    if [ -e "fuzz/corpus/$target" ] || [ -L "fuzz/corpus/$target" ] || \
       [ -e "fuzz/findings/$target" ] || [ -L "fuzz/findings/$target" ]; then
      fail "unregistered card slice-1 corpus or finding root: $target"
    fi
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
  ! -name qk_supervisor_lifecycle ! -name qk_supervisor_process_lifecycle \
  ! -name qk_decoy_calculator \
  ! -name qk_io_ingress ! -name qk_io_egress ! -name qk_io_session \
  ! -name qk_core_io_peer ! -name qk_core_session \
  ! -name qk_core_provisioning_entry ! -name qk_core_provisioning_run \
  ! -name qk_core_normal_entry ! -name qk_core_normal_run \
  ! -name qk_core_kit_intake ! -name qk_core_kit_restore \
  ! -name qk_core_kit_spend \
  ! -name qk_device_wire ! -name qk_core_normal_process \
  ! -name qk_card_protocol ! -name qk_card_model \
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
    ! -name qk_supervisor_lifecycle ! -name qk_supervisor_process_lifecycle \
    ! -name qk_decoy_calculator \
    ! -name qk_io_ingress ! -name qk_io_egress ! -name qk_io_session \
    ! -name qk_core_io_peer ! -name qk_core_session \
    ! -name qk_core_provisioning_entry ! -name qk_core_provisioning_run \
    ! -name qk_core_normal_entry ! -name qk_core_normal_run \
    ! -name qk_core_kit_intake ! -name qk_core_kit_restore \
    ! -name qk_core_kit_spend \
    ! -name qk_device_wire ! -name qk_core_normal_process \
    ! -name qk_card_protocol ! -name qk_card_model \
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
process_s2_entries=$(mktemp) || fail 'mktemp failed for process slice-2 corpus entries'
process_s3_entries=$(mktemp) || fail 'mktemp failed for process slice-3 corpus entries'
process_s4_entries=$(mktemp) || fail 'mktemp failed for process slice-4 corpus entries'
process_s5_entries=$(mktemp) || fail 'mktemp failed for process slice-5 corpus entries'
process_s6_entries=$(mktemp) || fail 'mktemp failed for process slice-6 corpus entries'
process_s7_entries=$(mktemp) || fail 'mktemp failed for process slice-7 corpus entries'
process_s7_new_entries=$(mktemp) || fail 'mktemp failed for new process slice-7 corpus entries'
process_s8_entries=$(mktemp) || fail 'mktemp failed for process slice-8 corpus entries'
process_s8_new_entries=$(mktemp) || fail 'mktemp failed for new process slice-8 corpus entries'
process_s9_entries=$(mktemp) || fail 'mktemp failed for process slice-9 corpus entries'
card_s1_entries=$(mktemp) || fail 'mktemp failed for card slice-1 corpus entries'
card_s1_new_entries=$(mktemp) || fail 'mktemp failed for new card slice-1 corpus entries'
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
process_s2_expected=$(mktemp) || fail 'mktemp failed for process slice-2 corpus manifest'
process_s3_expected=$(mktemp) || fail 'mktemp failed for process slice-3 corpus manifest'
process_s4_expected=$(mktemp) || fail 'mktemp failed for process slice-4 corpus manifest'
process_s5_expected=$(mktemp) || fail 'mktemp failed for process slice-5 corpus manifest'
process_s6_expected=$(mktemp) || fail 'mktemp failed for process slice-6 corpus manifest'
process_s7_expected=$(mktemp) || fail 'mktemp failed for process slice-7 corpus manifest'
process_s8_expected=$(mktemp) || fail 'mktemp failed for process slice-8 corpus manifest'
process_s9_expected=$(mktemp) || fail 'mktemp failed for process slice-9 corpus manifest'
card_s1_expected=$(mktemp) || fail 'mktemp failed for card slice-1 corpus manifest'
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
process_s2_paths=$(mktemp) || fail 'mktemp failed for process slice-2 corpus paths'
process_s3_paths=$(mktemp) || fail 'mktemp failed for process slice-3 corpus paths'
process_s4_paths=$(mktemp) || fail 'mktemp failed for process slice-4 corpus paths'
process_s5_paths=$(mktemp) || fail 'mktemp failed for process slice-5 corpus paths'
process_s6_paths=$(mktemp) || fail 'mktemp failed for process slice-6 corpus paths'
process_s7_paths=$(mktemp) || fail 'mktemp failed for process slice-7 corpus paths'
process_s8_paths=$(mktemp) || fail 'mktemp failed for process slice-8 corpus paths'
process_s9_paths=$(mktemp) || fail 'mktemp failed for process slice-9 corpus paths'
card_s1_paths=$(mktemp) || fail 'mktemp failed for card slice-1 corpus paths'
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
manifest_process_s2_paths=$(mktemp) || fail 'mktemp failed for process slice-2 manifest paths'
manifest_process_s3_paths=$(mktemp) || fail 'mktemp failed for process slice-3 manifest paths'
manifest_process_s4_paths=$(mktemp) || fail 'mktemp failed for process slice-4 manifest paths'
manifest_process_s5_paths=$(mktemp) || fail 'mktemp failed for process slice-5 manifest paths'
manifest_process_s6_paths=$(mktemp) || fail 'mktemp failed for process slice-6 manifest paths'
manifest_process_s7_paths=$(mktemp) || fail 'mktemp failed for process slice-7 manifest paths'
manifest_process_s8_paths=$(mktemp) || fail 'mktemp failed for process slice-8 manifest paths'
manifest_process_s9_paths=$(mktemp) || fail 'mktemp failed for process slice-9 manifest paths'
manifest_card_s1_paths=$(mktemp) || fail 'mktemp failed for card slice-1 manifest paths'
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
  "$process_s2_entries" "$process_s2_expected" \
  "$process_s3_entries" "$process_s3_expected" \
  "$process_s4_entries" "$process_s4_expected" \
  "$process_s5_entries" "$process_s5_expected" \
  "$process_s6_entries" "$process_s6_expected" \
  "$process_s7_entries" "$process_s7_new_entries" "$process_s7_expected" \
  "$process_s8_entries" "$process_s8_new_entries" "$process_s8_expected" \
  "$process_s9_entries" "$process_s9_expected" \
  "$card_s1_entries" "$card_s1_new_entries" "$card_s1_expected" \
  "$m21_paths" "$m22_paths" "$m23_paths" "$m24_paths" "$m25_paths" \
  "$m26_paths" "$m27_paths" "$m28_paths" "$m29_paths" "$m30_paths" \
  "$v2s4_paths" "$v2s5_paths" "$v2s6_paths" "$v2s7_paths" "$v2s8_paths" \
  "$v2s9_paths" "$v2s10_paths" "$v2s11_paths" "$firmware_paths" \
  "$process_s1_paths" "$process_s2_paths" "$process_s3_paths" \
  "$process_s4_paths" "$process_s5_paths" "$process_s6_paths" \
  "$process_s7_paths" "$process_s8_paths" \
  "$process_s9_paths" \
  "$card_s1_paths" \
  "$all_paths" "$tracked_tmp" "$target_tmp" "$manifest_m21_paths" \
  "$manifest_m22_paths" "$manifest_m23_paths" "$manifest_m24_paths" \
  "$manifest_m25_paths" "$manifest_m26_paths" "$manifest_m27_paths" \
  "$manifest_m28_paths" "$manifest_m29_paths" "$manifest_m30_paths" \
  "$manifest_v2s4_paths" "$manifest_v2s5_paths" \
  "$manifest_v2s6_paths" "$manifest_v2s7_paths" \
  "$manifest_v2s8_paths" "$manifest_v2s9_paths" "$manifest_v2s10_paths" \
  "$manifest_v2s11_paths" "$manifest_firmware_paths" \
  "$manifest_process_s1_paths" "$manifest_process_s2_paths" \
  "$manifest_process_s3_paths" "$manifest_process_s4_paths" \
  "$manifest_process_s5_paths" "$manifest_process_s6_paths" \
  "$manifest_process_s7_paths" "$manifest_process_s8_paths" \
  "$manifest_process_s9_paths" "$manifest_card_s1_paths"' EXIT HUP INT TERM

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
emit_partition_entries "$process_s2_targets" "$process_s2_entries"
emit_partition_entries "$process_s3_targets" "$process_s3_entries"
emit_partition_entries "$process_s4_targets" "$process_s4_entries"
if [ "$process_s5_active" = yes ]; then
  emit_partition_entries "$process_s5_targets" "$process_s5_entries"
else
  : > "$process_s5_entries" || fail 'cannot initialize process slice-5 corpus entries'
fi
if [ "$process_s6_active" = yes ]; then
  emit_partition_entries "$process_s6_targets" "$process_s6_entries"
else
  : > "$process_s6_entries" || fail 'cannot initialize process slice-6 corpus entries'
fi
if [ "$process_s7_active" = yes ]; then
  emit_partition_entries "$process_s7_targets" "$process_s7_entries"
  emit_partition_entries "$process_s7_new_targets" "$process_s7_new_entries"
else
  : > "$process_s7_entries" || fail 'cannot initialize process slice-7 corpus entries'
  : > "$process_s7_new_entries" || \
    fail 'cannot initialize new process slice-7 corpus entries'
fi
emit_partition_entries "$process_s8_targets" "$process_s8_entries"
emit_partition_entries "$process_s8_new_targets" "$process_s8_new_entries"
if [ "$process_s9_active" = yes ]; then
  emit_partition_entries "$process_s9_targets" "$process_s9_entries"
else
  : > "$process_s9_entries" || fail 'cannot initialize process slice-9 corpus entries'
fi
if [ "$card_s1_active" = yes ]; then
  emit_partition_entries "$card_s1_targets" "$card_s1_entries"
  emit_partition_entries "$card_s1_new_targets" "$card_s1_new_entries"
else
  : > "$card_s1_entries" || fail 'cannot initialize card slice-1 corpus entries'
  : > "$card_s1_new_entries" || fail 'cannot initialize new card slice-1 corpus entries'
fi
if [ "$process_s5_active" = yes ] && [ "$process_s5_registered" = no ]; then
  planned_count=$(wc -l < "$process_s5_entries" | tr -d ' ')
  planned_bytes=$(awk -F '\t' '{ sum += $3 } END { print sum + 0 }' "$process_s5_entries")
  planned_hash=$(sha256_file "$process_s5_entries") || \
    fail 'cannot hash process slice-5 starting corpus entries'
  [ "$planned_count:$planned_bytes:$planned_hash" = \
    '247:7185:79dd9570b0f4e8f2cc1f0839852de5cc81ef2a32f2d234af7e7c9f56801172e4' ] || \
    fail 'process slice-5 starting corpora do not match the preregistered bytes'
fi
if [ "$process_s6_active" = yes ] && [ "$process_s6_registered" = no ]; then
  planned_count=$(wc -l < "$process_s6_entries" | tr -d ' ')
  planned_bytes=$(awk -F '\t' '{ sum += $3 } END { print sum + 0 }' "$process_s6_entries")
  planned_hash=$(sha256_file "$process_s6_entries") || \
    fail 'cannot hash process slice-6 starting corpus entries'
  [ "$planned_count:$planned_bytes:$planned_hash" = \
    '119:478:e191a95ad273833b2aeb2375f42db8aae70c6b6f2eac0edfa3c9bc926936157f' ] || \
    fail 'process slice-6 starting corpora do not match the preregistered bytes'
fi
if [ "$process_s9_active" = yes ] && [ "$process_s9_registered" = no ]; then
  planned_count=$(wc -l < "$process_s9_entries" | tr -d ' ')
  planned_bytes=$(awk -F '\t' '{ sum += $3 } END { print sum + 0 }' "$process_s9_entries")
  planned_hash=$(sha256_file "$process_s9_entries") || \
    fail 'cannot hash process slice-9 starting corpus entries'
  [ "$planned_count:$planned_bytes:$planned_hash" = \
    '14:409:40a72ec84daa6a86b0064d623ca5683817a520ca6204ebc259897a0c32910147' ] || \
    fail 'process slice-9 starting corpora do not match the preregistered bytes'
fi
if [ "$card_s1_active" = yes ] && [ "$card_s1_registered" = no ]; then
  planned_count=$(wc -l < "$card_s1_entries" | tr -d ' ')
  planned_bytes=$(awk -F '\t' '{ sum += $3 } END { print sum + 0 }' "$card_s1_entries")
  planned_hash=$(sha256_file "$card_s1_entries") || \
    fail 'cannot hash card slice-1 starting corpus entries'
  [ "$planned_count:$planned_bytes:$planned_hash" = \
    '393:26341:4213ac2a6bb1bbd22cd01bd3fdffb3cda9089c3d3f0ce0f9e025c8d6fd18fce9' ] || \
    fail 'card slice-1 starting corpora do not match the preregistered bytes'
fi
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
cut -f 5 "$process_s2_entries" | LC_ALL=C sort > "$process_s2_paths" || \
  fail 'cannot list process slice-2 corpus paths'
cut -f 5 "$process_s3_entries" | LC_ALL=C sort > "$process_s3_paths" || \
  fail 'cannot list process slice-3 corpus paths'
cut -f 5 "$process_s4_entries" | LC_ALL=C sort > "$process_s4_paths" || \
  fail 'cannot list process slice-4 corpus paths'
cut -f 5 "$process_s5_entries" | LC_ALL=C sort > "$process_s5_paths" || \
  fail 'cannot list process slice-5 corpus paths'
cut -f 5 "$process_s6_entries" | LC_ALL=C sort > "$process_s6_paths" || \
  fail 'cannot list process slice-6 corpus paths'
cut -f 5 "$process_s7_new_entries" | LC_ALL=C sort > "$process_s7_paths" || \
  fail 'cannot list process slice-7 corpus paths'
cut -f 5 "$process_s8_new_entries" | LC_ALL=C sort > "$process_s8_paths" || \
  fail 'cannot list process slice-8 corpus paths'
cut -f 5 "$process_s9_entries" | LC_ALL=C sort > "$process_s9_paths" || \
  fail 'cannot list process slice-9 corpus paths'
cut -f 5 "$card_s1_new_entries" | LC_ALL=C sort > "$card_s1_paths" || \
  fail 'cannot list card slice-1 corpus paths'
cat "$m21_paths" "$m22_paths" "$m23_paths" "$m24_paths" "$m25_paths" \
  "$m26_paths" "$m27_paths" "$m28_paths" "$m29_paths" "$m30_paths" \
  "$v2s4_paths" "$v2s5_paths" "$v2s6_paths" "$v2s7_paths" "$v2s8_paths" \
  "$v2s9_paths" "$v2s10_paths" "$v2s11_paths" "$firmware_paths" \
  "$process_s1_paths" "$process_s2_paths" "$process_s3_paths" \
  "$process_s4_paths" "$process_s5_paths" "$process_s6_paths" \
  "$process_s7_paths" "$process_s8_paths" "$process_s9_paths" \
  "$card_s1_paths" | \
  LC_ALL=C sort > "$all_paths" || \
  fail 'cannot combine corpus paths'
duplicate=$(uniq -d "$all_paths" | sed -n '1p')
[ -z "$duplicate" ] || fail "corpus path is owned by both partitions: $duplicate"

git ls-files | LC_ALL=C sort > "$tracked_tmp" || fail 'cannot list tracked paths'
untracked=$(comm -23 "$all_paths" "$tracked_tmp") || fail 'cannot compare corpus paths with tracked files'
[ -z "$untracked" ] || fail "untracked corpus file: $(printf '%s\n' "$untracked" | sed -n '1p')"

case "$mode" in
  check)
    for partition_id in $partition_ids; do
      partition_values "$partition_id"
      partition_registered || continue
      partition_source_commit=$(manifest_source "$partition_manifest")
      eval "${partition_id}_source=\$partition_source_commit"
      if [ -n "$partition_target_source" ]; then
        partition_target_source_pairs=$(
          manifest_target_source_pairs "$partition_manifest" "$partition_target_source"
        )
        eval "${partition_id}_target_source_pairs=\$partition_target_source_pairs"
      fi
    done

    for partition_id in $partition_ids; do
      partition_values "$partition_id"
      partition_registered || continue
      eval "partition_source_commit=\${${partition_id}_source}"
      if [ -n "$partition_target_source" ]; then
        eval "partition_target_source_pairs=\${${partition_id}_target_source_pairs}"
        render_partition "$partition_version" "$partition_source_commit" \
          "$partition_targets" "$partition_order" "$partition_entries" \
          "$partition_expected" "$partition_target_source_pairs"
      else
        render_partition "$partition_version" "$partition_source_commit" \
          "$partition_targets" "$partition_order" "$partition_entries" \
          "$partition_expected"
      fi
    done

    for partition_id in $partition_ids; do
      partition_values "$partition_id"
      partition_registered || continue
      extract_manifest_paths "$partition_manifest" "$partition_order" \
        "$partition_manifest_paths"
    done
    set --
    for partition_id in $partition_ids; do
      partition_values "$partition_id"
      partition_registered || continue
      if [ "$partition_manifest_owner" = yes ]; then
        set -- "$@" "$partition_manifest_paths"
      fi
    done
    duplicate=$(cat "$@" | LC_ALL=C sort | uniq -d | sed -n '1p')
    [ -z "$duplicate" ] || fail "manifest path is owned by both partitions: $duplicate"

    for partition_id in $partition_ids; do
      partition_values "$partition_id"
      partition_registered || continue
      cmp -s "$partition_manifest" "$partition_expected" || \
        fail "$partition_manifest does not match the tracked $partition_label corpus bytes"
    done
    ;;
  *)
    partition_values "$render_partition_id"
    if [ -n "$render_target_override" ]; then
      partition_source_commit=$(manifest_source "$partition_manifest")
      partition_target_source_pairs=$(
        manifest_target_source_pairs "$partition_manifest" "$partition_target_source" \
          "$render_target_override" "$render_source"
      )
    else
      partition_source_commit=$render_source
      if [ -n "$partition_target_source" ]; then
        partition_target_source_pairs=$(
          manifest_target_source_pairs "$partition_manifest" "$partition_target_source"
        )
      else
        partition_target_source_pairs=''
      fi
    fi
    if [ -n "$partition_target_source" ]; then
      render_partition "$partition_version" "$partition_source_commit" \
        "$partition_targets" "$partition_order" "$partition_entries" \
        "$partition_expected" "$partition_target_source_pairs"
    else
      render_partition "$partition_version" "$partition_source_commit" \
        "$partition_targets" "$partition_order" "$partition_entries" \
        "$partition_expected"
    fi
    sed -n 'p' "$partition_expected"
    ;;
esac

exit 0
