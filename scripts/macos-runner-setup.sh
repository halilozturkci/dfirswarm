#!/bin/bash
# Make this Mac a self-hosted GitHub Actions runner for the macOS CI jobs, in a
# way a public repository can live with (docs/macos-runners.md):
#
#   - jobs run as a dedicated, hidden, non-admin user (default `runner`), never
#     as the owner, and nothing is written into the owner's home;
#   - every job gets a fresh runner: a supervisor (a root LaunchDaemon) copies a
#     pristine, root-owned runner, registers it with --ephemeral, lets it take
#     one job, then ends every process the job left and starts again;
#   - before a step runs, a root-owned job-started hook reads the event GitHub
#     sent and fails any job that is not a push to main or a pull request the
#     owner opened from a branch of this repository. A fork can rewrite the
#     workflow's runs-on in its own pull request; it cannot rewrite the event;
#   - one runner per Mac, so one job at a time.
#
# Usage (from an admin account, on Apple silicon, macOS 13 or later):
#   sudo bash scripts/macos-runner-setup.sh install   [--name NAME] [--user USER]
#   sudo bash scripts/macos-runner-setup.sh status
#   sudo bash scripts/macos-runner-setup.sh uninstall [--delete-user]
#
# install asks for a fine-grained personal access token (this repository only,
# "Administration: Read and write"): the supervisor needs one to register a new
# runner for every job. It is stored root-only and the job user cannot read it.
# Before install: `brew install jq gh` and `gh auth login` in the owner's account
# (gh is used once, from the owner's account, to check access).
#
# bash 3.2 (macOS's own) is enough.

set -euo pipefail

REPO="halilozturkci/dfirswarm"
# shellcheck disable=SC2034 # written into the config by name
OWNER="${REPO%%/*}"
LABELS="self-hosted,macOS,ARM64,dfirswarm"
LABEL="com.dfirswarm.actions-runner"
BASE="/Library/Application Support/dfirswarm-runner"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
LOG="/Library/Logs/dfirswarm-runner.log"
# actions/setup-python's macOS builds are not relocatable: they work only here.
TOOLCACHE="/Users/runner/hostedtoolcache"

RUNNER_VERSION="2.338.2"
RUNNER_SHA256="25a065af409ffa317ab4d5a3b614dd15fc9c40f2172bc1b35a1b1258e919a388"
RUNNER_URL="https://github.com/actions/runner/releases/download/v$RUNNER_VERSION/actions-runner-osx-arm64-$RUNNER_VERSION.tar.gz"

die() { printf 'macos-runner-setup: %s\n' "$*" >&2; exit 1; }
say() { printf '==> %s\n' "$*"; }

# A path inside a folder a sync client uploads (the same list as swarm.sh's
# synced-folder check). A runner there would upload every job's checkout.
in_synced_folder() { # <path>
  case "$1" in
    */Library/CloudStorage/*|*/Library/Mobile\ Documents/*|*/Dropbox|*/Dropbox/*|*/Google\ Drive/*|*/OneDrive*) return 0 ;;
  esac
  return 1
}

usage() { sed -n '16,19p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

CMD="${1:-}"; [ -n "$CMD" ] || usage; shift
RUNNER_USER="runner"
RUNNER_NAME="dfirswarm-$(scutil --get LocalHostName 2>/dev/null || hostname -s)"
DELETE_USER=0
while [ $# -gt 0 ]; do
  case "$1" in
    --name) RUNNER_NAME="${2:?--name needs a value}"; shift 2 ;;
    --user) RUNNER_USER="${2:?--user needs a value}"; shift 2 ;;
    --delete-user) DELETE_USER=1; shift ;;
    *) usage ;;
  esac
done
case "$RUNNER_USER" in ''|*[!a-z0-9_]*) die "--user must be a short lowercase name" ;; esac
case "$RUNNER_NAME" in ''|*[!A-Za-z0-9._-]*) die "--name may hold letters, digits, '.', '_' and '-' only" ;; esac
# An installed runner keeps the name and user it was installed with.
if [ "$CMD" != install ] && [ -r "$BASE/config" ]; then
  RUNNER_NAME="$(sed -n 's/^RUNNER_NAME=//p' "$BASE/config")"
  RUNNER_USER="$(sed -n 's/^RUNNER_USER=//p' "$BASE/config")"
fi
RUNNER_HOME="/Users/$RUNNER_USER"

[ "$(uname -s)" = Darwin ] || die "this is for macOS"
[ "$(id -u)" -eq 0 ] || die "run it with sudo"
OWNER_USER="${SUDO_USER:-}"
case "$OWNER_USER" in ''|root) die "run it with sudo from the owner's own admin account, not as root" ;; esac
[ "$OWNER_USER" != "$RUNNER_USER" ] || die "the runner user must not be the account you are logged in as"
OWNER_HOME="$(dscl . -read "/Users/$OWNER_USER" NFSHomeDirectory | awk '{print $2}')"

case "$RUNNER_HOME/" in "$OWNER_HOME"/*) die "the runner's home would be inside yours ($OWNER_HOME)" ;; esac
for p in "$(cd "$(dirname "$0")" && pwd -P)" "$BASE" "$RUNNER_HOME" "$TOOLCACHE"; do
  in_synced_folder "$p" && die "$p is in a synced folder (Dropbox, iCloud, OneDrive, Google Drive): move the checkout out of it first"
done

as_owner() { sudo -u "$OWNER_USER" -H "$@"; }
user_exists() { dscl . -read "/Users/$1" UniqueID >/dev/null 2>&1; }
is_admin() { dseditgroup -o checkmember -m "$1" admin 2>/dev/null | grep -q '^yes'; }

stop_daemon() {
  if launchctl print "system/$LABEL" >/dev/null 2>&1; then
    say "stopping the supervisor"
    launchctl bootout "system/$LABEL" 2>/dev/null || true
  fi
  if user_exists "$RUNNER_USER"; then
    pkill -9 -u "$RUNNER_USER" 2>/dev/null || true
  fi
}

# Delete this Mac's runner registration (an idle ephemeral runner stays
# registered until it takes a job).
deregister() {
  [ -r "$BASE/token" ] || return 0
  local id
  id="$(GH_TOKEN="$(cat "$BASE/token")" "$GH" api "repos/$REPO/actions/runners?per_page=100" \
        --jq ".runners[] | select(.name == \"$RUNNER_NAME\") | .id" 2>/dev/null || true)"
  if [ -n "$id" ]; then
    say "removing runner $RUNNER_NAME (id $id) from $REPO"
    GH_TOKEN="$(cat "$BASE/token")" "$GH" api -X DELETE "repos/$REPO/actions/runners/$id" >/dev/null || true
  fi
}

GH="$(PATH="/opt/homebrew/bin:/usr/local/bin:$PATH" command -v gh || true)"

cmd_status() {
  if launchctl print "system/$LABEL" >/dev/null 2>&1; then
    launchctl print "system/$LABEL" | grep -E '^[[:space:]]*(state|pid|last exit code) =' | sed 's/^[[:space:]]*/supervisor: /'
  else
    echo "supervisor: not loaded"
  fi
  user_exists "$RUNNER_USER" && echo "user $RUNNER_USER: present (admin: $(is_admin "$RUNNER_USER" && echo YES || echo no))" || echo "user $RUNNER_USER: absent"
  [ -f "$LOG" ] && { echo "--- last lines of $LOG"; tail -n 15 "$LOG"; }
  return 0
}

cmd_uninstall() {
  stop_daemon
  [ -n "$GH" ] && deregister
  rm -f "$PLIST"
  rm -rf "$BASE"
  if [ "$DELETE_USER" = 1 ] && user_exists "$RUNNER_USER"; then
    say "deleting user $RUNNER_USER and its home"
    sysadminctl -deleteUser "$RUNNER_USER" 2>&1 | grep -v '^$' || true
    rm -rf "$TOOLCACHE"
  fi
  say "uninstalled; set the repository variable MACOS_RUNNER aside (gh variable delete MACOS_RUNNER -R $REPO) if no Mac runs jobs any more"
}

cmd_install() {
  [ "$(uname -m)" = arm64 ] || die "this script registers an ARM64 runner; this Mac is $(uname -m)"
  [ -n "$GH" ] || die "gh is not installed: brew install gh, then gh auth login"
  JQ="$(PATH="/opt/homebrew/bin:/usr/local/bin:$PATH" command -v jq || true)"
  [ -n "$JQ" ] || die "jq is not installed: brew install jq (the job user cannot brew install)"

  # gh, from the owner's own login, only to check that the repository is there
  # and that the owner may manage its runners.
  say "checking access to $REPO with the owner's gh login"
  as_owner "$GH" api "repos/$REPO" --jq '.permissions.admin' 2>/dev/null | grep -qx true \
    || say "warning: could not confirm admin access with the owner's gh login (gh auth status); the token below is checked either way"

  # The token the supervisor registers each new runner with.
  if [ -r "$BASE/token" ]; then
    say "keeping the stored token ($BASE/token)"
  else
    echo "Paste a fine-grained personal access token for $REPO only, permission"
    echo "\"Administration: Read and write\", with an expiry (it is not echoed):"
    local tok; IFS= read -r -s tok; echo
    [ -n "$tok" ] || die "no token given"
    GH_TOKEN="$tok" "$GH" api -X POST "repos/$REPO/actions/runners/registration-token" --jq .token >/dev/null 2>&1 \
      || die "that token cannot create a runner registration token for $REPO"
    mkdir -p "$BASE"; chown root:wheel "$BASE"; chmod 755 "$BASE"
    (umask 077; printf '%s\n' "$tok" > "$BASE/token")
    chown root:wheel "$BASE/token"; chmod 600 "$BASE/token"
  fi

  # The job user: standard (not admin), hidden from the login window, with a
  # random password nobody keeps. It never logs in.
  if user_exists "$RUNNER_USER"; then
    say "user $RUNNER_USER exists"
  else
    say "creating user $RUNNER_USER"
    sysadminctl -addUser "$RUNNER_USER" -fullName "dfirswarm CI runner" -shell /bin/bash \
      -home "$RUNNER_HOME" -password "$(openssl rand -base64 32)" 2>&1 | grep -v '^$' || true
    user_exists "$RUNNER_USER" || die "could not create user $RUNNER_USER"
    dscl . -create "/Users/$RUNNER_USER" IsHidden 1
  fi
  is_admin "$RUNNER_USER" && die "user $RUNNER_USER is an admin: a runner must not be (System Settings, Users & Groups)"
  [ -d "$RUNNER_HOME" ] || createhomedir -c -u "$RUNNER_USER" >/dev/null
  chown "$RUNNER_USER":staff "$RUNNER_HOME"; chmod 700 "$RUNNER_HOME"
  mkdir -p "$TOOLCACHE"; chown "$RUNNER_USER":staff "$TOOLCACHE"

  # The pristine runner: root-owned, so a job cannot change what the next job
  # starts from. Checked against the SHA-256 the release states.
  stop_daemon
  local tmp; tmp="$(mktemp -d)"
  say "downloading actions/runner $RUNNER_VERSION"
  curl -fsSL -o "$tmp/runner.tar.gz" "$RUNNER_URL"
  [ "$(shasum -a 256 "$tmp/runner.tar.gz" | awk '{print $1}')" = "$RUNNER_SHA256" ] || { rm -rf "$tmp"; die "the runner download does not match its SHA-256"; }
  rm -rf "$BASE/runner"; mkdir -p "$BASE/runner"
  tar -xzf "$tmp/runner.tar.gz" -C "$BASE/runner"
  rm -rf "$tmp"
  chown -R root:wheel "$BASE/runner"; chmod -R go-w "$BASE/runner"

  # Sourced by the hook and the supervisor, so every value is shell-quoted.
  local v
  for v in REPO OWNER LABELS RUNNER_NAME RUNNER_USER RUNNER_HOME TOOLCACHE GH JQ; do
    eval "printf '%s=%q\n' $v \"\$$v\""
  done > "$BASE/config"
  write_hook > "$BASE/job-started.sh"
  write_supervisor > "$BASE/supervise.sh"
  chown root:wheel "$BASE/config" "$BASE/job-started.sh" "$BASE/supervise.sh"
  chmod 644 "$BASE/config"; chmod 755 "$BASE/job-started.sh" "$BASE/supervise.sh"

  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>/bin/bash</string><string>$BASE/supervise.sh</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>
</dict>
</plist>
EOF
  chown root:wheel "$PLIST"; chmod 644 "$PLIST"
  plutil -lint "$PLIST" >/dev/null
  launchctl bootstrap system "$PLIST"
  say "installed: runner $RUNNER_NAME, labels $LABELS, jobs as $RUNNER_USER"
  say "log: $LOG    status: sudo bash $0 status"
  say "to send the owner's macOS jobs here: gh variable set MACOS_RUNNER -R $REPO --body '[\"self-hosted\",\"macOS\",\"ARM64\",\"dfirswarm\"]'"
}

# The job-started hook. It runs as the job user before any step, reads the
# event GitHub sent (not the workflow, which a fork's pull request can edit) and
# fails every job but a push to main and a pull request the owner opened from a
# branch of this repository. jq is the owner's Homebrew one, which the job user
# cannot write to.
write_hook() {
  cat <<'EOF'
#!/bin/bash
. "/Library/Application Support/dfirswarm-runner/config"
ev() { "$JQ" -r "$1 // empty" "$GITHUB_EVENT_PATH" 2>/dev/null; }
refuse() { echo "::error::this self-hosted runner refuses the job: $*"; exit 1; }
[ "${GITHUB_REPOSITORY:-}" = "$REPO" ] || refuse "repository ${GITHUB_REPOSITORY:-?} is not $REPO"
[ -r "${GITHUB_EVENT_PATH:-}" ] || refuse "no event payload"
case "${GITHUB_EVENT_NAME:-}" in
  push)
    [ "${GITHUB_REF:-}" = refs/heads/main ] || refuse "a push to ${GITHUB_REF:-?}, not to main" ;;
  pull_request)
    head="$(ev .pull_request.head.repo.full_name)"; author="$(ev .pull_request.user.login)"
    [ "$head" = "$REPO" ] || refuse "a pull request from ${head:-a deleted fork}, not from a branch of $REPO"
    [ "$author" = "$OWNER" ] || refuse "a pull request opened by ${author:-?}, not by $OWNER" ;;
  *) refuse "event ${GITHUB_EVENT_NAME:-?}" ;;
esac
echo "self-hosted runner: ${GITHUB_EVENT_NAME} accepted"
EOF
}

# The supervisor: one ephemeral runner after another, each from the pristine
# copy, each job's leftovers ended before the next registers.
write_supervisor() {
  cat <<'EOF'
#!/bin/bash
set -u
. "/Library/Application Support/dfirswarm-runner/config"
BASE="/Library/Application Support/dfirswarm-runner"
DIR="$RUNNER_HOME/actions-runner"
log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
clean() {
  pkill -9 -u "$RUNNER_USER" 2>/dev/null
  crontab -r -u "$RUNNER_USER" 2>/dev/null
  rm -rf "$DIR" "$RUNNER_HOME/Library/LaunchAgents"
}
as_runner() {
  /usr/bin/sudo -u "$RUNNER_USER" -H /usr/bin/env -i HOME="$RUNNER_HOME" USER="$RUNNER_USER" LOGNAME="$RUNNER_USER" \
    PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" LANG=en_US.UTF-8 "$@"
}
while :; do
  clean
  token="$(GH_TOKEN="$(cat "$BASE/token")" "$GH" api -X POST "repos/$REPO/actions/runners/registration-token" --jq .token 2>&1)" \
    || { log "no registration token: $token"; sleep 60; continue; }
  # APFS clone: instant, and the job user owns only its copy.
  /bin/cp -cR "$BASE/runner" "$DIR" && chown -R "$RUNNER_USER":staff "$DIR" || { log "could not copy the runner"; sleep 60; continue; }
  cat > "$DIR/.env" <<ENV
ACTIONS_RUNNER_HOOK_JOB_STARTED=$BASE/job-started.sh
RUNNER_TOOL_CACHE=$TOOLCACHE
AGENT_TOOLSDIRECTORY=$TOOLCACHE
LANG=en_US.UTF-8
ENV
  # The runner's env.sh adds to .env while it configures, so the job user owns
  # it; nothing in it outlives this job, and the hook it names is root-owned.
  chown "$RUNNER_USER":staff "$DIR/.env"
  if ! as_runner /bin/bash -c 'cd "$1" && ./config.sh --unattended --ephemeral --replace --disableupdate \
        --url "https://github.com/$2" --token "$3" --name "$4" --labels "$5" --work _work' _ \
        "$DIR" "$REPO" "$token" "$RUNNER_NAME" "$LABELS"; then
    log "config.sh failed"; sleep 60; continue
  fi
  log "registered $RUNNER_NAME; waiting for a job"
  as_runner /bin/bash -c 'cd "$1" && ./run.sh' _ "$DIR"
  log "runner exited ($?)"
done
EOF
}

case "$CMD" in
  install) cmd_install ;;
  status) cmd_status ;;
  uninstall) cmd_uninstall ;;
  *) usage ;;
esac
