// Project-authored rules for ransomware_family_match (AGPL-3.0-or-later, like the rest of this pack).
// Each rule looks for a short phrase that a cited page quotes from a ransom note; a hit is a lead, never a family name by itself.
// Every rule carries a rule_version; entries.json names the rule and its version, and the tool refuses a set where they differ.

rule rm_phobos_note_phrase_1
{
    meta:
        rule_version = 1
        entry = "phobos"
        variant = "phobos-core"
        source = "S13"
    strings:
        $phrase = "All of your files are encrypted" ascii wide nocase
    condition:
        $phrase
}

rule rm_play_note_phrase_1
{
    meta:
        rule_version = 1
        entry = "play"
        variant = "play-play-extension"
        source = "S17"
    strings:
        $phrase = "Your network has been encrypted" ascii wide nocase
    condition:
        $phrase
}
