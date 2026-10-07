/** The tool fields and flags the logs leaves name: each is written or read by its tool (tests/pack-windows-skills.test.ts checks both ends). */
export const TAUGHT: Array<[tool: string, skillId: string, names: string[]]> = [
  ["evtx_query", "logs/security", [
    "records_examined", "events_matched", "parse_errors", "chunks_declared", "chunks_read", "bytes_expected", "file_bytes",
    "record_offset", "chunk_offset", "record_filetime", "record_time_utc", "event_ids", "contains", "start_record", "end_record",
    "start_time", "end_time", "events_without_time_excluded", "result_file", "result_file_requested", "limit",
  ]],
  ["evtx_query", "logs/coverage", ["highest_record_id_read", "result_file", "parse_errors"]],
  ["evtx_query", "logs/powershell", ["result_file", "record_offset"]],
  ["evtx_query", "logs/hunting", ["start_record", "end_record", "records_examined"]],
  ["evtx_carve", "logs/carving", [
    "chunk_limit", "candidate_limit", "resume_start", "max_bytes", "start", "sweep_complete", "range_requested", "range_examined",
    "signatures_rejected", "candidates", "all_results", "all_problems", "with_xml", "chunk_verified", "chunks_checksum_ok",
    "chunks_found", "problem_count", "record_offset", "chunk_offset", "record_id", "time_created", "computer", "channel", "provider",
  ]],
  ["sigma_hunt", "logs/hunting", [
    "run_dir", "ruleset", "result_file", "all_detections", "exit_code", "command", "timeout_seconds", "malformed_lines",
    "below_min_level", "unknown_levels", "min_level", "engine_version", "out_dir", "rules", "engine",
  ]],
];
