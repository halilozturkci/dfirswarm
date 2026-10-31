#!/usr/bin/env bash
# Provision a Claude Code cloud environment (Anthropic-hosted VM: Ubuntu 24.04
# x86_64, setup scripts run as root before Claude Code launches) for this repo.
#
# The exact same text is pasted into the "Setup script" field of the
# "Add cloud environment" dialog at claude.ai/code. It is idempotent, so it can
# also be re-run inside a session (as root or as the session user), or from a
# SessionStart hook, to finish the user-scoped and repo-scoped steps.
#
# Rules from the docs (code.claude.com/docs/en/cloud-environments):
#   - a non-zero exit blocks the session, so non-critical steps end in `|| true`
#   - keep total runtime under ~5 minutes so the environment cache can snapshot
#   - installs need network: use Custom access with the default list included
#     plus herdr.dev, cdn.playwright.dev, playwright.download.prss.microsoft.com
#
# Phases:
#   provision  Node >= 22.19, apt tools, Herdr, Pi, Playwright Chromium + deps
#   project    herdr integration install pi (per user), npm ci, npm run ui:build
#   (both run by default; `provision` / `project` as $1 selects one)
set -uo pipefail

PHASE="${1:-all}"
log() { printf '[cloud-setup] %s\n' "$*"; }
warn() { printf '[cloud-setup] WARN %s\n' "$*" >&2; }

export DEBIAN_FRONTEND=noninteractive
export HERDR_INSTALL_DIR="${HERDR_INSTALL_DIR:-/usr/local/bin}"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/opt/ms-playwright}"
export PATH="/opt/node22/bin:/usr/local/bin:$HOME/.local/bin:$PATH"

SUDO=""
if [[ "$(id -u)" -ne 0 ]] && command -v sudo >/dev/null 2>&1; then SUDO="sudo -E"; fi

node_ok() {
  node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>22||(a===22&&b>=19)?0:1)' 2>/dev/null
}

install_node() {
  # Cloud VMs ship Node 20/21/22 under /opt/node<ver>; this path is only for
  # other images. nodejs.org is on the default Trusted allowlist.
  local tar
  tar="$(curl -fsSL https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt | grep -o 'node-v22[0-9.]*-linux-x64.tar.xz' | head -1)"
  [[ -n "$tar" ]] || { warn "could not resolve a Node 22 tarball"; return 1; }
  curl -fsSL "https://nodejs.org/dist/latest-v22.x/$tar" -o /tmp/node22.tar.xz || return 1
  $SUDO mkdir -p /opt/node22
  $SUDO tar -xJf /tmp/node22.tar.xz -C /opt/node22 --strip-components=1
  rm -f /tmp/node22.tar.xz
  export PATH="/opt/node22/bin:$PATH"
}

phase_provision() {
  log "phase: provision (uid $(id -u), $(uname -m), $(. /etc/os-release && echo "$PRETTY_NAME"))"

  if command -v node >/dev/null 2>&1 && node_ok; then
    log "node $(node --version) ok"
  else
    log "node >= 22.19 missing; installing from nodejs.org"
    install_node || warn "node install failed"
  fi

  # jq/python3/curl are pre-installed on the cloud image; tmux hosts `herdr server`.
  $SUDO apt-get update -qq >/dev/null 2>&1 || true
  $SUDO apt-get install -y -qq --no-install-recommends jq python3 curl tmux util-linux iproute2 >/dev/null 2>&1 \
    || warn "apt install of base tools failed"

  # Herdr: binary is a GitHub release asset (github.com/herdrdev/herdr). The
  # cloud GitHub proxy may 403 release assets of repositories not attached to
  # the session; if so, this step logs a warning and the session still starts.
  if command -v herdr >/dev/null 2>&1; then
    log "herdr $(herdr --version 2>/dev/null | head -1) ok"
  else
    log "installing herdr to $HERDR_INSTALL_DIR"
    $SUDO mkdir -p "$HERDR_INSTALL_DIR"
    (curl -fsSL --retry 3 https://herdr.dev/install.sh | HERDR_INSTALL_DIR="$HERDR_INSTALL_DIR" $SUDO sh) \
      || warn "herdr install failed (GitHub release asset blocked by the proxy?)"
  fi &
  local herdr_job=$!

  # Playwright Chromium + OS deps into a shared, world-readable browsers dir.
  # Downloads come from cdn.playwright.dev / playwright.download.prss.microsoft.com
  # (not on the Trusted list; add them under Custom). `--with-deps` uses apt.
  if [[ -d "$PLAYWRIGHT_BROWSERS_PATH" ]] && ls "$PLAYWRIGHT_BROWSERS_PATH" 2>/dev/null | grep -q '^chromium'; then
    log "playwright chromium present in $PLAYWRIGHT_BROWSERS_PATH"
  else
    log "installing playwright chromium + deps into $PLAYWRIGHT_BROWSERS_PATH"
    $SUDO mkdir -p "$PLAYWRIGHT_BROWSERS_PATH"
    (cd /tmp && PLAYWRIGHT_BROWSERS_PATH="$PLAYWRIGHT_BROWSERS_PATH" $SUDO npx --yes playwright@1.63 install --with-deps chromium) \
      || warn "playwright chromium install failed (network allowlist?)"
    $SUDO chmod -R a+rX "$PLAYWRIGHT_BROWSERS_PATH" 2>/dev/null || true
  fi &
  local pw_job=$!

  # Pi from the npm registry (Trusted list). No pi.dev needed. Global bin lands
  # next to node (/opt/node22/bin), so it is on PATH for every user.
  if command -v pi >/dev/null 2>&1; then
    log "pi $(pi --version 2>/dev/null | head -1) ok"
  else
    # The version the repository pins (package.json's devDependency), unless
    # PI_VERSION says another. This text is also pasted where no checkout is
    # beside it, so the fallback names the same version; tests/image-pins.test.ts
    # holds the two equal.
    if [[ -z "${PI_VERSION:-}" ]]; then
      PI_VERSION_FALLBACK="1.4.0"
      _pj="$(dirname "${BASH_SOURCE[0]:-$0}")/../package.json"
      [[ -f "$_pj" ]] || _pj="package.json"
      PI_VERSION="$(sed -n 's/.*"@earendil-works\/pi-coding-agent": *"\([^"]*\)".*/\1/p' "$_pj" 2>/dev/null | head -1)"
      PI_VERSION="${PI_VERSION:-$PI_VERSION_FALLBACK}"
    fi
    log "installing pi (@earendil-works/pi-coding-agent${PI_VERSION:+@$PI_VERSION})"
    $SUDO npm install -g --ignore-scripts "@earendil-works/pi-coding-agent${PI_VERSION:+@$PI_VERSION}" \
      || warn "pi install failed"
  fi

  wait "$herdr_job" "$pw_job" 2>/dev/null || true
}

phase_project() {
  log "phase: project (user $(id -un), HOME=$HOME)"

  # Herdr's Pi integration is per user (~/.pi/agent/extensions). Root's copy
  # from the setup script does not help a non-root session user; re-run here.
  if command -v herdr >/dev/null 2>&1; then
    mkdir -p "$HOME/.pi/agent/extensions"
    herdr integration install pi >/dev/null 2>&1 && log "herdr integration install pi ok" \
      || warn "herdr integration install pi failed"
  fi

  # Repo-scoped steps only when the cwd (or CLAUDE_PROJECT_DIR) is this repo.
  local repo="${CLAUDE_PROJECT_DIR:-$PWD}"
  if [[ ! -f "$repo/package.json" ]] || ! grep -q '"name": *"dfirswarm"' "$repo/package.json"; then
    log "no dfirswarm package.json in $repo; skipping npm ci / ui:build"
    return 0
  fi
  cd "$repo" || return 0
  if [[ ! -d node_modules/vite ]]; then
    log "npm ci"
    if [[ -f package-lock.json ]]; then npm ci --no-audit --no-fund || warn "npm ci failed"; else npm install --no-audit --no-fund || warn "npm install failed"; fi
  fi
  if [[ ! -f ui/dist/index.html ]]; then
    log "npm run ui:build"
    npm run ui:build >/dev/null 2>&1 && log "ui/dist built" || warn "ui:build failed"
  fi
}

summary() {
  log "summary:"
  printf '  node      %s\n' "$(node --version 2>/dev/null || echo missing)"
  printf '  npm       %s\n' "$(npm --version 2>/dev/null || echo missing)"
  printf '  herdr     %s\n' "$(herdr --version 2>/dev/null | head -1 || echo missing)"
  printf '  pi        %s\n' "$(pi --version 2>/dev/null | head -1 || echo missing)"
  printf '  jq        %s\n' "$(jq --version 2>/dev/null || echo missing)"
  printf '  tmux      %s\n' "$(tmux -V 2>/dev/null || echo missing)"
  printf '  chromium  %s\n' "$(ls -d "$PLAYWRIGHT_BROWSERS_PATH"/chromium* 2>/dev/null | head -1 || echo missing)"
  printf '  unshare   %s\n' "$(unshare -rn true 2>/dev/null && echo 'user+net namespace ok (netguard netns possible)' || echo 'blocked (netguard falls back to proxy-only; prefer --no-netguard here)')"
}

case "$PHASE" in
  provision) phase_provision ;;
  project) phase_project ;;
  all) phase_provision; phase_project ;;
  *) echo "usage: $0 [provision|project|all]" >&2; exit 2 ;;
esac
summary
exit 0
