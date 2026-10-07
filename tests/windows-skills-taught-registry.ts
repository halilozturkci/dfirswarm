/**
 * The fields and flags the registry, accounts and persistence leaves teach, each of which a tool of the pack must write or
 * read: [tool, skill id, names]. tests/pack-windows-skills.test.ts asserts the leaf names them and the tool's script or
 * manifest contains them, so a leaf cannot keep teaching a field a tool no longer has.
 */
export const TAUGHT: Array<[tool: string, skillId: string, names: string[]]> = [
  ["regkv", "registry/overview", ["hive_dirty", "hive_sequence_numbers", "transaction_logs_beside_hive", "transaction_logs_replayed"]],
  [
    "regkv",
    "registry/readers",
    [
      "deepest_found", "missing", "subkeys_there", "value_types", "value_lengths", "corrupted_values", "stopped_branches", "tree_complete",
      "all_subkeys", "all_nodes", "sensitive_values_withheld", "not_attempted",
    ],
  ],
];
