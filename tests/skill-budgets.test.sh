#!/usr/bin/env bash
# The size budgets of a pack's skills: scripts/skill-budgets.py, which `pack.sh
# seal` and this suite both run. The rules are docs/packs.md, "Writing a pack that
# holds up", "Skill size"; the program's header says how a token is estimated and
# how the golden list, tests/skill-budgets.golden, works.
#
#   - the shipped packs hold to the budgets, the known findings being the list's;
#   - each rule is proved on small packs built to break it: a leaf over 1,000
#     tokens (and the warning band from 800), a router over 400, a file over 300
#     lines, an index entry over 40, `needs` more than 2 deep (and a loop), a needs
#     chain over 1,900 tokens counted through `depends`, and the warning when a chain
#     is within 150 of that, which names the skill whose growth would push a
#     dependant over;
#   - the golden list: a listed finding passes, one past its ceiling fails, one that
#     no longer happens fails, and a missing, malformed, unsorted or repeating list
#     fails;
#   - `pack.sh seal` refuses a skill over 1,000 tokens before it writes anything,
#     says the rest as warnings, and seals a pack within the budgets.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null || fail "$PY is required"
command -v jq >/dev/null || fail "jq is required"
BUDGETS="$ROOT/scripts/skill-budgets.py"

# --- the shipped packs -------------------------------------------------------
"$PY" "$BUDGETS" check > "$WORK/shipped.out" 2>&1; rc=$?
cat "$WORK/shipped.out"
[[ $rc -eq 0 ]] || fail "a shipped pack is over a skill budget and the golden list does not say so (above)"
grep -q '^checked [0-9]* packs: [0-9]* skills' "$WORK/shipped.out" || fail "the check did not say what it checked"
pass "the shipped packs hold to the skill budgets, the known findings being tests/skill-budgets.golden's"

# The list is what `golden` writes for the packs as they are, or a pack was fixed and
# its line stayed (the check fails that too), or a ceiling was raised by hand.
"$PY" "$BUDGETS" golden > "$WORK/now.golden" || fail "golden failed"
"$PY" - "$ROOT/tests/skill-budgets.golden" "$WORK/now.golden" <<'EOF' || fail "tests/skill-budgets.golden lists a ceiling higher than the packs need, or a finding they no longer have: write it again with scripts/skill-budgets.py golden"
import sys
def lines(p):
    return [l.rstrip("\n") for l in open(p, encoding="utf-8") if l.strip() and not l.startswith("#")]
listed = {tuple(l.split(" ")[:3]): int(l.split(" ")[3]) for l in lines(sys.argv[1])}
now = {tuple(l.split(" ")[:3]): int(l.split(" ")[3]) for l in lines(sys.argv[2])}
bad = [k for k in listed if k not in now or listed[k] > now[k]]
if bad:
    print("\n".join("  " + " ".join(k) + " (listed %d, now %s)" % (listed[k], now.get(k, "gone")) for k in bad))
    sys.exit(1)
EOF
pass "no golden line holds a ceiling above what its skill needs"

# --- the rules, on packs built to break each ---------------------------------
cat > "$WORK/fx.py" <<'EOF'
import json, os, sys

dest, mutations = sys.argv[1], sys.argv[2:]
R = 4.245

def sk(tokens=300, needs=(), router=False, title="t", when="w", lines=None):
    return dict(tokens=tokens, needs=list(needs), router=router, title=title, when=when, lines=lines)

def render(sid, s):
    head = "---\nid: %s\ntitle: %s\nwhen: %s\nneeds: [%s]\ntools: []\nrequires_host: []\n%s---\n\nUse when it is a test. Not for anything else.\n" % (
        sid, s["title"], s["when"], ", ".join(s["needs"]), "router: true\n" if s["router"] else "")
    if s["lines"]:
        text = head
        while text.count("\n") + 1 < s["lines"]:
            text += "x\n"
        return text  # `lines` lines in all, the empty one after the last newline counted
    text = head
    n = 0
    while len(text.encode()) / R < s["tokens"]:
        text += ("w%d " % n) * 12 + "\n"
        n += 1
    # trim to just under the target so the size is the target, not past it
    while len(text.encode()) / R > s["tokens"] and len(text) > len(head):
        text = text[:-1]
    return text

packs = {
    "bp": dict(depends=[], skills={"b/one": sk(300), "b/two": sk(300, ["b/one"])}),
    "cp": dict(depends=["bp>=1.0.0"], skills={"c/one": sk(300, ["b/two"]), "c/lone": sk(200)}),
}
def put(pid, sid, **kw): packs[pid]["skills"][sid] = sk(**kw)

M = {
    "leaf-800": lambda: put("cp", "c/lone", tokens=799),
    "leaf-801": lambda: put("cp", "c/lone", tokens=801),
    "leaf-900": lambda: put("cp", "c/lone", tokens=900),
    "leaf-1000": lambda: put("cp", "c/lone", tokens=999),
    "leaf-1001": lambda: put("cp", "c/lone", tokens=1002),
    "leaf-1100": lambda: put("cp", "c/lone", tokens=1100),
    "leaf-1200": lambda: put("cp", "c/lone", tokens=1200),
    "leaf-1300": lambda: put("cp", "c/lone", tokens=1300),
    "router-390": lambda: put("cp", "c/lone", tokens=390, router=True),
    "router-450": lambda: put("cp", "c/lone", tokens=450, router=True),
    # a router is held to 400, not to the leaf's 1,000
    "router-900": lambda: put("cp", "c/lone", tokens=900, router=True),
    # windows-forensics, linux-forensics, memory-forensics and macos-forensics are held to 500 (scripts/skill-budgets.json)
    "win-router-450": lambda: packs.__setitem__("windows-forensics", dict(depends=[], skills={"w/router": sk(450, router=True)})),
    "win-router-495": lambda: packs.__setitem__("windows-forensics", dict(depends=[], skills={"w/router": sk(495, router=True)})),
    "win-router-520": lambda: packs.__setitem__("windows-forensics", dict(depends=[], skills={"w/router": sk(520, router=True)})),
    "lines-300": lambda: put("cp", "c/lone", lines=300),
    "lines-301": lambda: put("cp", "c/lone", lines=301),
    "entry-long": lambda: put("cp", "c/lone", title="a title that goes on and on and on and on and on", when="and a when that is nothing like short, so the index line of this skill is longer than forty tokens are, and then some more words follow it to be sure of that"),
    "depth-2": lambda: (put("cp", "c/a", needs=["c/b"]), put("cp", "c/b", needs=["c/lone"])),
    "depth-3": lambda: (put("cp", "c/a", needs=["c/b"]), put("cp", "c/b", needs=["c/d"]), put("cp", "c/d", needs=["c/lone"])),
    "loop": lambda: (put("cp", "c/a", needs=["c/b"]), put("cp", "c/b", needs=["c/a"])),
    # a chain is counted across depends: 650 + 650 + 650 = 1,950
    "chain-over": lambda: (put("bp", "b/one", tokens=650), put("bp", "b/two", tokens=650, needs=["b/one"]),
                           put("cp", "c/one", tokens=650, needs=["b/two"])),
    # 650 + 600 + 600 = 1,850: within 150 of 1,900, not over
    "chain-near": lambda: (put("bp", "b/one", tokens=600), put("bp", "b/two", tokens=600, needs=["b/one"]),
                           put("cp", "c/one", tokens=650, needs=["b/two"])),
    # 640 + 650 + 600 = 1,890: within the limit, and within the margin of it
    "chain-exact": lambda: (put("bp", "b/one", tokens=600), put("bp", "b/two", tokens=650, needs=["b/one"]),
                            put("cp", "c/one", tokens=640, needs=["b/two"])),
    # the base pack grew by 100: it is c's chain that goes over
    "chain-grown": lambda: (put("bp", "b/one", tokens=700), put("bp", "b/two", tokens=600, needs=["b/one"]),
                            put("cp", "c/one", tokens=650, needs=["b/two"])),
    # a skill counted once however many ways it is reached
    "chain-shared": lambda: (put("cp", "c/x", tokens=500, needs=["b/one"]), put("cp", "c/y", tokens=500, needs=["b/one"]),
                             put("cp", "c/z", tokens=500, needs=["c/x", "c/y"])),
    "chain-prefixed": lambda: (put("bp", "b/one", tokens=700), put("bp", "b/two", tokens=700, needs=["b/one"]),
                               put("cp", "c/one", tokens=600, needs=["bp:b/two"])),
}
for m in mutations:
    M[m]()

for pid, p in packs.items():
    d = os.path.join(dest, pid)
    os.makedirs(d)
    json.dump(dict(id=pid, name=pid, version="1.0.0", description="x", licence="AGPL-3.0-or-later", depends=p["depends"]),
              open(os.path.join(d, "pack.json"), "w"))
    open(os.path.join(d, "LICENCE"), "w").write("Test pack.\n")
    for sid, s in p["skills"].items():
        path = os.path.join(d, "skills", sid + ".md")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").write(render(sid, s))
EOF

case_n=0
# budget_case <label> <rc> <pattern the output has, or ''> <golden: '-' none, else lines joined by ';'> <mutations...>
budget_case() {
  local label="$1" want="$2" pattern="$3" golden="$4"; shift 4
  case_n=$((case_n + 1))
  local dir="$WORK/fx$case_n" got rc
  mkdir "$dir" && "$PY" "$WORK/fx.py" "$dir" "$@" || fail "could not build the packs for: $label"
  case "$golden" in
    @missing) ;;
    -) : > "$dir.golden" ;;
    *) printf '%s\n' "$golden" | tr ';' '\n' > "$dir.golden" ;;
  esac
  got="$("$PY" "$BUDGETS" check --packs-dir "$dir" --golden "$dir.golden" 2>&1)"; rc=$?
  [[ $rc -eq $want ]] || fail "$label: expected exit $want, got $rc:
$got"
  [[ -z "$pattern" ]] || grep -qE -- "$pattern" <<<"$got" || fail "$label: the output lacks /$pattern/:
$got"
  LAST="$got"; LAST_DIR="$dir"
}
absent() { # <label> <pattern>: the last output must not have it
  ! grep -qE -- "$2" <<<"$LAST" || fail "$1: the output has /$2/:
$LAST"
}

budget_case "a pack within every budget" 0 "checked 2 packs: 4 skills" -
absent "a clean set" "^warning"
budget_case "799 tokens is a leaf" 0 "" - leaf-800; absent "799 tokens" "^warning"
budget_case "over 800 tokens is a warning, not a finding" 0 "warning: cp: c/lone: 801 tokens, over the leaf budget of 800 .sealing refuses above 1000." - leaf-801
budget_case "900 tokens is a warning" 0 "warning: cp: c/lone: 900 tokens" - leaf-900
budget_case "999 tokens is no finding" 0 "warning: cp: c/lone: 999 tokens" - leaf-1000
budget_case "over 1,000 tokens is a finding" 1 "cp: c/lone: 1002 tokens, over the 1000 a skill may have .budget 800.: split it into leaves .it is not on the golden list" - leaf-1001
budget_case "a router is held to 400" 0 "" - router-390; absent "a router of 390" "router"
budget_case "a router over 400 is a finding" 1 "cp: c/lone: the router is 450 tokens, over its budget of 400" - router-450
budget_case "a 450-token router passes for windows-forensics (limit 500)" 0 "" - win-router-450; absent "a 450-token windows router" "router"
budget_case "the same 450-token router fails for another pack (limit 400)" 1 "cp: c/lone: the router is 450 tokens, over its budget of 400" - router-450
budget_case "a 520-token router fails for windows-forensics" 1 "windows-forensics: w/router: the router is 520 tokens, over its budget of 500" - win-router-520
budget_case "a router of 900 tokens is a router finding, not a leaf one" 1 "the router is 900 tokens" - router-900; absent "a router of 900" "a skill may have"
budget_case "300 lines is within the budget" 0 "" - lines-300
budget_case "301 lines is a finding" 1 "cp: c/lone: 301 lines, over the 300 a skill file may have" - lines-301
budget_case "an index entry over 40 tokens is a finding" 1 "cp: c/lone: its index entry is [0-9.]+ tokens, over 40: shorten .title. or .when." - entry-long
budget_case "needs two deep is within the budget" 0 "" - depth-2
budget_case "needs three deep is a finding" 1 "cp: c/a: .needs. reaches 3 deep, over 2" - depth-3
budget_case "a loop in needs is a finding" 1 "cp: c/a: .needs. loops: cp c/a > cp c/b > cp c/a" - loop
budget_case "a chain over 1,900 tokens, counted through depends, is a finding" 1 "cp: c/one: its needs chain is [0-9]+ tokens, over 1900 .3 skill.s.: c/one \(650\), bp:b/two \(650\), bp:b/one \(650\)" - chain-over
budget_case "a chain within 150 tokens of the limit is a warning" 0 "warning: cp: c/one: its needs chain is 18[0-9][0-9] tokens, [0-9]+ under the 1900 limit; it is made of c/one \(650\), bp:b/two \(600\), bp:b/one \(600\); growing any of them by more than [0-9]+ tokens pushes it over" - chain-near
grep -qE "warning: bp: b/two \([0-9]+ tokens\) is in the needs chain of 1 skill.s. of other packs within 150 tokens of the 1900 limit: growing it by more than [0-9]+ tokens pushes it over - cp c/one \([0-9]+ tokens of room\)" <<<"$LAST" || fail "the warning does not name the base skill whose growth pushes the dependant over:
$LAST"
grep -qE "warning: bp: b/one \(" <<<"$LAST" || fail "the warning does not name every base skill of the chain:
$LAST"
budget_case "a chain just under the limit is within it" 0 "" - chain-exact
budget_case "a base skill that grew puts its dependant over" 1 "cp: c/one: its needs chain is [0-9]+ tokens, over 1900 .3 skill.s.: c/one \(650\), bp:b/two \(600\), bp:b/one \(700\)" - chain-grown
budget_case "a skill reached two ways is counted once" 0 "" - chain-shared; absent "a shared skill" "over 1900"
budget_case "a pack:id in needs resolves" 1 "cp: c/one: its needs chain is [0-9]+ tokens, over 1900" - chain-prefixed
pass "each budget holds: a leaf (warning from 800, finding over 1,000), a router, lines, an index entry, needs depth and loops, and the chain counted through depends, with its margin warning"

# --- the golden list ----------------------------------------------------------
LEAF_LINE="cp leaf c/lone 1125"
budget_case "a listed finding does not fail" 0 "budgets: 1 finding.s. in all, 1 of them on the golden list .leaf 1." "$LEAF_LINE" leaf-1100
budget_case "a finding at its ceiling does not fail" 0 "1 of them on the golden list" "cp leaf c/lone 1100" leaf-1100
budget_case "a listed skill that grew past its ceiling fails" 1 "past the ceiling of 1050 on its golden line 1: it may only shrink" "cp leaf c/lone 1050" leaf-1100
budget_case "a listed skill that shrank and is still over keeps its line" 0 "1 of them on the golden list" "cp leaf c/lone 1200" leaf-1001
budget_case "a new finding next to a listed one fails" 1 "cp: c/a: .needs. reaches 3 deep, over 2 .it is not on the golden list" "$LEAF_LINE" leaf-1100 depth-3
budget_case "a listed finding that no longer happens fails" 1 "skill-budgets.golden line 1, .cp leaf c/lone 1125., no longer happens: remove the line" "$LEAF_LINE"
budget_case "a line that is not four fields fails" 1 "golden line 1 is not .pack kind skill-id ceiling." "cp leaf c/lone"
budget_case "a line with a kind that is none fails" 1 "golden line 1 is not .pack kind skill-id ceiling." "cp big c/lone 1125"
budget_case "a ceiling that is no number fails" 1 "golden line 1 is not .pack kind skill-id ceiling." "cp leaf c/lone many"
budget_case "a (pack, kind, skill) listed twice fails" 1 "golden line 2 repeats line 1" "$LEAF_LINE;cp leaf c/lone 1150" leaf-1100
budget_case "an unsorted list fails" 1 "golden line 2 is out of order" "$LEAF_LINE;bp leaf b/one 900" leaf-1100
budget_case "a missing list fails" 1 "skill-budgets.golden is missing|is missing: the known findings are held to it" @missing
budget_case "comments and blank lines are skipped" 0 "1 of them on the golden list" "# why;;$LEAF_LINE" leaf-1100
budget_case "a listed chain" 0 "1 of them on the golden list .chain 1." "cp chain c/one 1975" chain-over
absent "a listed chain" "^warning: cp: c/one: its needs chain"
budget_case "a listed chain that grew fails" 1 "past the ceiling of 1900 on its golden line 1" "cp chain c/one 1900" chain-over

# `golden` writes a list the check takes, ceilings a little above the values.
dir="$WORK/fxg"; mkdir "$dir" && "$PY" "$WORK/fx.py" "$dir" leaf-1100 depth-3 chain-over || fail "could not build the packs for the golden writer"
"$PY" "$BUDGETS" golden --packs-dir "$dir" > "$WORK/written.golden" || fail "golden failed"
LC_ALL=C sort -c "$WORK/written.golden" || fail "golden wrote an unsorted list"
grep -qx 'cp leaf c/lone 1125' "$WORK/written.golden" || fail "golden did not write the leaf ceiling (a multiple of 25, with room): $(cat "$WORK/written.golden")"
grep -qx 'cp depth c/a 3' "$WORK/written.golden" || fail "golden did not write the depth exactly: $(cat "$WORK/written.golden")"
grep -q '^cp chain c/one ' "$WORK/written.golden" || fail "golden did not write the chain: $(cat "$WORK/written.golden")"
"$PY" "$BUDGETS" check --packs-dir "$dir" --golden "$WORK/written.golden" > "$WORK/roundtrip.out" 2>&1 || fail "the check does not take the list golden wrote:
$(cat "$WORK/roundtrip.out")"
dir="$WORK/fxl"; mkdir "$dir" && "$PY" "$WORK/fx.py" "$dir" lines-301 || fail "could not build the packs for the golden writer"
"$PY" "$BUDGETS" golden --packs-dir "$dir" | grep -qx 'cp lines c/lone 310' || fail "golden did not write the lines ceiling (a multiple of 10)"
pass "the golden list: a listed finding passes at or under its ceiling; one past it, a new one, one that no longer happens and a bad, unsorted, repeating or missing list fail; golden writes a list the check takes"

# --- seal ---------------------------------------------------------------------
# The seal runs the same program before it writes anything.
seal_case() { # <label> <seal rc> <pattern> <mutations...>
  local label="$1" want="$2" pattern="$3"; shift 3
  case_n=$((case_n + 1))
  local dir="$WORK/sl$case_n" got rc
  mkdir "$dir" && "$PY" "$WORK/fx.py" "$dir" "$@" || fail "could not build the packs for: $label"
  got="$(DFIRSWARM_HOME="$WORK/home" bash "$ROOT/scripts/pack.sh" seal "$dir/cp" 2>&1)"; rc=$?
  [[ $rc -eq $want ]] || fail "$label: expected seal exit $want, got $rc:
$got"
  [[ -z "$pattern" ]] || grep -qE -- "$pattern" <<<"$got" || fail "$label: the output lacks /$pattern/:
$got"
  LAST="$got"; LAST_DIR="$dir"
}
seal_case "a pack within every budget seals" 0 "^sealed: cp 1.0.0, 2 skills"
absent "a clean seal" "budget:|warning"
jq -e '.checksums.sha256["skills/INDEX.md"]' "$LAST_DIR/cp/pack.json" >/dev/null || fail "the clean pack was not sealed"
seal_case "800 to 1,000 tokens seals, with a warning" 0 "budget: cp: c/lone: 900 tokens, over the leaf budget of 800" leaf-900
seal_case "over 1,000 tokens is refused" 1 "refused: cp: c/lone: 1100 tokens, over the 1000 a skill may have" leaf-1100
grep -q 'BLOCKER: a skill is over its size budget' <<<"$LAST" || fail "the refusal does not say why: $LAST"
[[ "$(jq 'has("checksums")' "$LAST_DIR/cp/pack.json")" == false ]] || fail "a refused seal wrote the checksums"
[[ ! -e "$LAST_DIR/cp/skills/INDEX.md" ]] || fail "a refused seal wrote the index"
seal_case "a router over 400 tokens is refused" 1 "refused: cp: c/lone: the router is 450 tokens" router-450
# The seal reads the same limits by pack id: windows-forensics seals a 495-token router and refuses a 520-token one.
for case in "win-router-495 0 sealed:" "win-router-520 1 the.router.is.520.tokens"; do
  set -- $case
  case_n=$((case_n + 1)); dir="$WORK/sl$case_n"
  mkdir "$dir" && "$PY" "$WORK/fx.py" "$dir" "$1" || fail "could not build the packs for the windows router case $1"
  got="$(DFIRSWARM_HOME="$WORK/home" bash "$ROOT/scripts/pack.sh" seal "$dir/windows-forensics" 2>&1)"; rc=$?
  [[ $rc -eq $2 ]] || fail "sealing windows-forensics with $1: expected exit $2, got $rc:
$got"
  grep -qE -- "$3" <<<"$got" || fail "sealing windows-forensics with $1: the output lacks /$3/:
$got"
done
seal_case "the other budgets are warnings at the seal" 0 "budget: cp: c/a: .needs. reaches 3 deep, over 2 .tests/skill-budgets.test.sh fails on it." depth-3
seal_case "a chain over the limit is a warning at the seal" 0 "budget: cp: c/one: its needs chain is [0-9]+ tokens, over 1900" chain-over
seal_case "a chain near the limit warns, naming the skills" 0 "budget: cp: c/one: its needs chain is .*made of c/one \(650\), bp:b/two \(600\), bp:b/one \(600\)" chain-near

# The base pack's seal says what its growth did to the packs that depend on it.
case_n=$((case_n + 1)); dir="$WORK/sl$case_n"; mkdir "$dir" && "$PY" "$WORK/fx.py" "$dir" chain-grown || fail "could not build the packs"
got="$(DFIRSWARM_HOME="$WORK/home" bash "$ROOT/scripts/pack.sh" seal "$dir/bp" 2>&1)" || fail "the base pack does not seal: $got"
grep -qE "budget: cp: c/one: its needs chain is [0-9]+ tokens, over 1900, and it reaches skills of this pack \(b/two, b/one\)" <<<"$got" || fail "sealing the base said nothing of the dependant its growth put over the limit:
$got"
case_n=$((case_n + 1)); dir="$WORK/sl$case_n"; mkdir "$dir" && "$PY" "$WORK/fx.py" "$dir" chain-near || fail "could not build the packs"
got="$(DFIRSWARM_HOME="$WORK/home" bash "$ROOT/scripts/pack.sh" seal "$dir/bp" 2>&1)" || fail "the base pack does not seal: $got"
grep -qE "budget: bp: b/two \([0-9]+ tokens\) is in the needs chain of 1 skill.s. of other packs within 150 tokens of the 1900 limit: growing it by more than [0-9]+ tokens pushes it over - cp c/one" <<<"$got" || fail "sealing the base did not name the skill whose growth would push the dependant over:
$got"
pass "sealing refuses a skill over 1,000 tokens (and a router over 400) before it writes anything, says every other budget as a warning, and tells the base pack what its growth does to a dependant"

# A pack seals under its golden list: one with a listed leaf over 1,000 tokens seals,
# and the same pack with no list is refused. The assertions run on a pack built here
# (a leaf of 1,100 tokens and a list that names it), so they never depend on what the
# shipped list still holds: the list is meant to shrink, and a seal case that took "the
# first shipped pack the list names for a leaf" passed without checking anything once
# no such line was left. When the shipped list does name a leaf, the same assertions
# also run on that pack.
golden_seal_case() { # <label> <pack dir> <golden file>
  local label="$1" pack="$2" golden="$3"
  "$PY" "$BUDGETS" seal "$pack" --golden "$golden" > "$WORK/gs.seal" || fail "$label: the seal check failed"
  [[ "$(jq '.errors | length' "$WORK/gs.seal")" == 0 ]] || fail "$label: its listed findings are refused at the seal: $(cat "$WORK/gs.seal")"
  jq -e '.warnings | map(select(test("known finding.s. are on tests/skill-budgets.golden"))) | length == 1' "$WORK/gs.seal" >/dev/null || fail "$label: the seal did not say that the pack has known findings: $(cat "$WORK/gs.seal")"
  "$PY" "$BUDGETS" seal "$pack" > "$WORK/gs.nogolden" || fail "$label: the seal check failed without the list"
  [[ "$(jq '.errors | length' "$WORK/gs.nogolden")" -gt 0 ]] || fail "$label: a listed leaf over 1,000 tokens is not refused without the list"
}
case_n=$((case_n + 1)); dir="$WORK/sl$case_n"; mkdir "$dir" && "$PY" "$WORK/fx.py" "$dir" leaf-1100 || fail "could not build the packs"
printf '%s\n' "cp leaf c/lone 1125" > "$dir.golden"
golden_seal_case "the built pack" "$dir/cp" "$dir.golden"
shipped="$(awk '$2 == "leaf" { print $1; exit }' "$ROOT/tests/skill-budgets.golden")"
if [[ -n "$shipped" ]]; then
  golden_seal_case "the shipped pack $shipped" "$ROOT/packs/$shipped" "$ROOT/tests/skill-budgets.golden"
else
  echo "note - tests/skill-budgets.golden names no leaf: the seal assertions ran on the built pack only"
fi
case_n=$((case_n + 1)); dir="$WORK/sl$case_n"; mkdir "$dir" && "$PY" "$WORK/fx.py" "$dir" leaf-1100 || fail "could not build the packs"
printf '%s\n' "cp leaf c/lone 1125" > "$dir.golden"
"$PY" "$BUDGETS" seal "$dir/cp" --golden "$dir.golden" > "$WORK/listed.seal" || fail "seal check failed"
[[ "$(jq '.errors | length' "$WORK/listed.seal")" == 0 ]] || fail "a leaf on the list is refused: $(cat "$WORK/listed.seal")"
printf '%s\n' "cp leaf c/lone 1050" > "$dir.golden"
"$PY" "$BUDGETS" seal "$dir/cp" --golden "$dir.golden" > "$WORK/grown.seal" || fail "seal check failed"
[[ "$(jq '.errors | length' "$WORK/grown.seal")" == 1 ]] || fail "a listed leaf past its ceiling is not refused: $(cat "$WORK/grown.seal")"
pass "the seal reads the golden list: a listed leaf seals, one past its ceiling is refused, and without the list a leaf over 1,000 tokens is refused"

# A pack written before the rule is resealed for unrelated changes: a leaf over 1,000
# tokens that the golden list covers seals with a note (the list's), the same leaf grown
# past its ceiling is refused, and a new leaf over 1,000 tokens is refused.
case_n=$((case_n + 1)); dir="$WORK/sl$case_n"; mkdir "$dir" && "$PY" "$WORK/fx.py" "$dir" leaf-1200 || fail "could not build the packs"
printf '%s\n' "cp leaf c/lone 1250" > "$dir.golden"
got="$(PACK_BUDGETS_GOLDEN="$dir.golden" DFIRSWARM_HOME="$WORK/home" bash "$ROOT/scripts/pack.sh" seal "$dir/cp" 2>&1)" || fail "a golden-covered leaf of 1,200 tokens is refused at the seal: $got"
grep -q 'budget: cp: 1 known finding.s. are on tests/skill-budgets.golden (leaf 1)' <<<"$got" || fail "the seal did not say the leaf is a known finding: $got"
grep -q 'budget: cp: c/lone: 1200 tokens, over the 1000 a skill may have; it is on tests/skill-budgets.golden with a ceiling of 1250' <<<"$got" || fail "the seal did not say the ceiling: $got"
grep -q '^sealed: cp' <<<"$got" || fail "the golden-covered leaf was not sealed: $got"
case_n=$((case_n + 1)); dir="$WORK/sl$case_n"; mkdir "$dir" && "$PY" "$WORK/fx.py" "$dir" leaf-1300 || fail "could not build the packs"
printf '%s\n' "cp leaf c/lone 1250" > "$dir.golden"
got="$(PACK_BUDGETS_GOLDEN="$dir.golden" DFIRSWARM_HOME="$WORK/home" bash "$ROOT/scripts/pack.sh" seal "$dir/cp" 2>&1)" && fail "the leaf grown to 1,300 tokens past its ceiling of 1,250 was sealed: $got"
grep -q 'refused: cp: c/lone: 1300 tokens.*past the ceiling of 1250 on its golden line 1' <<<"$got" || fail "the refusal does not name the ceiling: $got"
[[ "$(jq 'has("checksums")' "$dir/cp/pack.json")" == false ]] || fail "a refused seal wrote the checksums"
case_n=$((case_n + 1)); dir="$WORK/sl$case_n"; mkdir "$dir" && "$PY" "$WORK/fx.py" "$dir" leaf-1100 || fail "could not build the packs"
printf '%s\n' "bp leaf b/one 1250" > "$dir.golden"
got="$(PACK_BUDGETS_GOLDEN="$dir.golden" DFIRSWARM_HOME="$WORK/home" bash "$ROOT/scripts/pack.sh" seal "$dir/cp" 2>&1)" && fail "a new leaf of 1,100 tokens (not on the list) was sealed: $got"
grep -q 'refused: cp: c/lone: 1100 tokens.*not on the golden list' <<<"$got" || fail "the refusal of a new leaf does not say it is not listed: $got"
pass "a golden-covered leaf over 1,000 tokens seals with a note, the same leaf past its ceiling and a new leaf over 1,000 are refused"
