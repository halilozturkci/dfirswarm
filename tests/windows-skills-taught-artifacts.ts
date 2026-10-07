/**
 * The tool fields and flags the artifacts, browser, memory and antiforensics leaves teach: each must be a name the leaf uses
 * and a name its tool writes or reads (tests/pack-windows-skills.test.ts asserts both).
 */
export const TAUGHT: Array<[tool: string, skillId: string, names: string[]]> = [
  ["lnk_parse", "artifacts/links", [
    "drive_type_name", "serial_number", "net_name", "linkinfo_target", "linkinfo_target_kind", "heuristic_fields", "idlist_ascii", "idlist_paths",
    "structure_complete", "arguments_present", "arguments_chars", "arguments_first_token", "arguments_first_token_withheld", "utf16_strings",
    "utf16_string_count", "finding_id", "sensitive_fields_withheld", "write_strings", "lnk-strings.jsonl",
  ]],
  ["jumplist", "artifacts/jumplists", ["entry_number", "pin_status", "out_dir", "carved", "not_read", "not_attempted", "files_not_attempted", "undecoded_"]],
  ["shellbags", "artifacts/shellbags", [
    "key_last_written", "mru_position", "values_without_subkey", "not_walked_below_max_depth", "max_depth", "extension_block_size", "long_name_from",
    "extension_layout", "localized_name",
  ]],
  ["regkv", "artifacts/shellbags", ["hive_dirty"]],
  ["browser_history", "browser/artefacts", [
    "sqlite_header", "wal_present", "wal_frames_replayed", "wal_refused", "journal_refused", "wal_inspection", "wal_not_established", "chrome_visits",
    "firefox_visits", "chrome_url_summary", "firefox_url_summary", "transition_raw", "transition_core", "typed_count", "sensitive_columns_withheld",
    "url_secrets_withheld", "write_url_secrets",
  ]],
  ["browser_history", "browser/downloads", ["chrome_downloads", "firefox_downloads", "tab_url"]],
  ["utf16_urls", "browser/strings", ["continued", "url_secrets_withheld"]],
  ["yara_scan", "memory/windows", ["finding_id", "write_matches", "scan_error_count", "not_attempted"]],
  ["regkv", "memory/windows", ["problems"]],
  ["amcache_apps", "antiforensics/wiping", ["sha1_raw"]],
  ["evtx_query", "antiforensics/traces", ["parse_errors"]],
  ["mft_records", "antiforensics/traces", ["structural_errors"]],
  ["evtx_query", "antiforensics/log-clearing", [
    "records_examined", "events_matched", "parse_errors", "chunks_read", "chunks_declared", "result_file", "highest_record_id_read", "next_record_number_declared",
  ]],
  ["vss_stores", "antiforensics/log-clearing", ["exit_code", "stdout_file", "stderr_file", "stores_claimed", "store_count"]],
  ["mft_records", "antiforensics/timestamps-clock", ["timestomp_only", "structural_errors", "si_"]],
];
