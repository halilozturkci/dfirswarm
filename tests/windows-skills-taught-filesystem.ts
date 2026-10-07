/**
 * The fields and flags the filesystem leaves teach, each of which its tool must write or read: tool, skill id, names.
 * tests/pack-windows-skills.test.ts asserts that the leaf names every one and that the tool's script or manifest has it.
 */
export const TAUGHT: Array<[tool: string, skillId: string, names: string[]]> = [
  ["mft_records", "filesystem/mft", [
    "deleted_only", "with_resident", "record_size_from", "records_fixup_failed", "fixup_failed", "structural_errors", "slots_zeroed",
    "slots_unrecognised", "slots_without_signature", "alignment_offset", "trailing_bytes", "has_attribute_list", "attribute_list_resolved",
    "base_record", "base_sequence", "is_extension_record", "parent_entry", "parent_sequence", "allocated_size", "real_size",
    "initialised_size", "all_results", "in_use", "unreliable",
  ]],
  ["mft_records", "filesystem/timestamps", [
    "timestomp_only", "si_created_before_fn_created", "si_modified_before_si_created", "si_times_identical", "si_times_whole_seconds",
    "file_name_times_source",
  ]],
  ["mft_records", "filesystem/ads", ["streams_only", "instance", "resident", "has_attribute_list", "in_use"]],
  ["indx_carve", "filesystem/indx", [
    "fixup_ok", "node_ok", "salvaged", "include_unreliable", "blocks_salvaged", "entries_excluded_unreliable", "live_entries_unreadable",
    "live_entries_flagged_unreliable", "unreliable_reasons", "block_offset",
  ]],
  ["usn_journal", "filesystem/journals", [
    "records_read", "records_by_version", "nameless_excluded_by_filter", "include_nameless", "unsupported_version_records",
    "unsupported_versions", "unsupported_version_bytes", "unsupported_version_list", "all_unsupported_version_list", "unrecognised_bytes",
    "prefix_unrecognised_bytes", "unrecognised_ranges", "first_record_offset", "zero_bytes_skipped", "minor_version", "not_attempted",
    "reason_raw", "source_info", "security_id", "file_sequence", "parent_sequence", "RENAME_OLD_NAME", "RENAME_NEW_NAME", "all_results",
  ]],
  ["usn_journal", "filesystem/ads", ["STREAM_CHANGE", "NAMED_DATA"]],
  ["extract_stream", "filesystem/ads", ["partial_file"]],
  ["recyclebin_i", "filesystem/recycle-bin", [
    "original_path", "original_size", "deleted_at", "bin_directory_sid", "r_file", "records_truncated", "trailing_bytes", "unknown_header",
    "unreadable", "not_attempted", "truncated",
  ]],
  ["vss_stores", "filesystem/shadowcopies", [
    "exit_code", "store_count", "stores_claimed", "problems", "stdout_file", "stderr_file", "earlier_output_files", "mount_argv",
  ]],
  ["vss_stores", "filesystem/shadowcopies-open", ["mount_argv"]],
];
