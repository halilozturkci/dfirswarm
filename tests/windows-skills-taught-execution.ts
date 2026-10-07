/**
 * The tool fields and flags the execution leaves teach, each of which its tool must write or read (asserted by
 * tests/pack-windows-skills.test.ts: the leaf names it, and the tool's run.py or manifest holds it).
 */
export const TAUGHT: Array<[tool: string, skillId: string, names: string[]]> = [
  ["prefetch_mam", "execution/prefetch", [
    "file_information_size", "run_count", "last_runs", "last_runs_detail", "filename_strings", "volumes_decoded", "volumes_claimed",
    "exe_name", "prefetch_hash", "unsupported", "problems",
  ]],
  ["mam_scan", "execution/prefetch-carved", [
    "min_uncomp", "max_uncomp", "size_out_of_range", "candidates", "parsed", "failed_by_reason", "failures", "filtered_by_name", "name_filter",
    "unsupported_variant_signatures", "scanned_from", "scanned_to", "attempted_range", "file_information_size", "supported",
  ]],
  ["amcache_apps", "execution/amcache", [
    "layouts_found", "rows_by_layout", "rows_failed", "sha1_raw", "file_id_sha1", "key_last_modified",
    "linker_compile_time_utc", "hive_dirty", "InventoryApplicationFile",
  ]],
  ["esedb_query", "execution/esedb", [
    "exporter_exit_status", "timed_out", "exporter_version", "db_sha256", "export_dir", "stdout_file", "stderr_file", "tables_in_partial_export",
    "export_reused", "export_timeout_seconds", "export_dir_sensitive", "columns_withheld", "url_secrets_withheld", "write_url_secrets", "_row",
  ]],
  ["esedb_query", "execution/srum", ["_row"]],
];
