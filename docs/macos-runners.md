# The macOS CI jobs on the owner's own Macs

GitHub's hosted macOS runners can queue for one to two hours, and a queued job
is sometimes cancelled with "job was not acquired by Runner". The four macOS
parts of `.github/workflows/ci.yml` can instead run on the owner's own Apple
silicon Macs, registered as self-hosted runners. This page is how to set one
up, what keeps someone else's code off it, and how to go back.

The repository is public. A self-hosted runner runs whatever a job tells it to,
so the whole design is about one rule: **only code the owner wrote runs on the
owner's Mac.** Everything else stays on GitHub's hosted runners.

## What runs where

| Run | Runs on |
| --- | --- |
| A push to `main` | the owner's Mac |
| A pull request the owner opened from a branch of this repository | the owner's Mac |
| A pull request from a fork | GitHub-hosted `macos-latest` |
| A Dependabot pull request, or one anyone else opened | GitHub-hosted `macos-latest` |
| Any run while the variable `MACOS_RUNNER` is not set | GitHub-hosted `macos-latest` |

The Linux jobs are not affected.

## Three guards, not one

1. **The workflow routes.** The macOS job's `runs-on` picks the labels in the
   repository variable `MACOS_RUNNER` only for the runs in the table above,
   and `macos-latest` for everything else.
2. **The Mac checks.** A fork can change `runs-on` in its own pull request,
   because a `pull_request` run uses the workflow from the pull request. So
   the Mac does not trust the workflow. Every job first runs a root-owned
   job-started hook (`ACTIONS_RUNNER_HOOK_JOB_STARTED`). It reads the event
   that GitHub sent, which a pull request cannot change, and fails the job
   before any step runs unless the job is a push to `main` or a pull request
   opened by the owner from a branch of this repository.
3. **The repository asks first.** In Settings → Actions → General, under
   "Approval for running fork pull request workflows from contributors",
   choose **Require approval for all external contributors** and click Save.
   A fork's run then waits for the owner. Read any change it makes under
   `.github/` before approving it. (The section "Fork pull request workflows"
   on the same page is for private repositories and does not apply here.)

The job itself is contained as well. This is what limits the harm if the
owner's own branch carries a bad dependency:

- Jobs run as a dedicated, hidden, standard (non-admin) user, `runner` by
  default. They never run as the owner. The job user cannot use `sudo`, cannot
  read the owner's home, and cannot write to Homebrew.
- Every job gets a fresh runner. A root LaunchDaemon copies a pristine,
  root-owned runner. It registers the copy with `--ephemeral`, so the copy
  takes one job and leaves. The daemon then ends every process the job left,
  clears the job user's crontab and LaunchAgents, deletes the copy, and starts
  again.
- There is one runner per Mac, so a Mac runs one CI job at a time.

What a job can still do: read what the job user can read, use the network,
and leave files in the job user's home (the npm cache, the Playwright browser,
`/Users/runner/hostedtoolcache`). The next job will see those files. Per-job
VMs (below) close that gap.

## Setting up a Mac

You need an admin account on an Apple silicon Mac with macOS 13 or later, and
a checkout of this repository outside Dropbox, iCloud Drive, OneDrive and
Google Drive. The script refuses to run from inside those folders.

1. Install the tools the jobs and the script use:

   ```bash
   brew install jq gh
   ```

   ```bash
   gh auth login
   ```

   The job user cannot install anything with Homebrew. The workflow's
   `brew install jq` fallback only works when jq is already there.

2. Create a fine-grained personal access token in GitHub → Settings →
   Developer settings:
   - Repository access: `halilozturkci/dfirswarm` only.
   - Permissions: Administration, Read and write.
   - Give it an expiry.

   The supervisor needs this token to register a new runner for every job,
   because a registration token lasts only one hour. The script stores the
   token in `/Library/dfirswarm-runner/token`, readable by
   root only. The job user cannot read it.

3. Install:

   ```bash
   sudo bash scripts/macos-runner-setup.sh install
   ```

   The script checks your `gh` login against the repository and asks for the
   token. It checks that the token can create a registration token
   (`gh api -X POST repos/halilozturkci/dfirswarm/actions/runners/registration-token`).
   Then it does the following:
   - Creates the hidden, standard user `runner`, with a random password that
     nobody keeps.
   - Creates `/Users/runner/hostedtoolcache`. actions/setup-python's macOS
     builds work only at that path.
   - Downloads the pinned actions/runner release and checks it against the
     SHA-256 that the release states.
   - Installs the hook, the supervisor, and the LaunchDaemon
     `com.dfirswarm.actions-runner`, all under `/Library/dfirswarm-runner`.
     The path holds no space on purpose: the runner calls the job-started
     hook by its path unquoted, and the first version of this script, under
     `/Library/Application Support`, failed every job at that call. Running
     `install` again on a Mac set up by that version moves its token to the
     new directory and removes the old one; there is nothing to paste again.

   Options: `--name NAME` sets the runner name (the default is
   `dfirswarm-<LocalHostName>`). `--user USER` sets the job user.

   The script writes nothing in your home. It only reads your `gh` login.

4. Check that the runner is idle and registered:

   ```bash
   sudo bash scripts/macos-runner-setup.sh status
   ```

   The runner should also appear in the repository under Settings → Actions →
   Runners, with the labels `self-hosted, macOS, ARM64, dfirswarm`.

5. Send the owner's macOS jobs to it:

   ```bash
   gh variable set MACOS_RUNNER -R halilozturkci/dfirswarm --body '["self-hosted","macOS","ARM64","dfirswarm"]'
   ```

Start with one Mac. On a few pull requests, compare its four macOS parts with
the hosted runner. To get a hosted run of the same commit, delete the variable
and re-run the job. Add the second Mac once the results agree: run the same
install on it. Jobs then go to whichever Mac is free.

The log is `/Library/Logs/dfirswarm-runner.log`. The runner is pinned to one
version and started with `--disableupdate`. When GitHub stops accepting that
version, raise `RUNNER_VERSION` and `RUNNER_SHA256` in the script, then run
`install` again.

## Going back to GitHub-hosted runners

Delete the variable. Every macOS job goes back to `macos-latest` on its next
run:

```bash
gh variable delete MACOS_RUNNER -R halilozturkci/dfirswarm
```

To take a Mac out of service, run the following. It stops the daemon, removes
the runner from the repository, and deletes the files. `--delete-user` also
deletes the `runner` user, its home, and the tool cache.

```bash
sudo bash scripts/macos-runner-setup.sh uninstall --delete-user
```

Then revoke the token in GitHub.

## Differences from the hosted runner

- **Python.** The job installs Python 3.14 with actions/setup-python on both
  kinds of runner, so the two are comparable. The Linux jobs run Ubuntu
  24.04's Python 3.12.
- **Docker and Herdr.** They are not on the hosted runner, and the suites
  skip what needs them. If a Mac has Docker Desktop, its socket belongs to the
  owner. The job user cannot reach it.
- **Speed.** One runner per Mac means the four parts run one after another on
  one Mac. With two Macs, two parts run at a time.

## Later: a VM per job (Tart)

The next step is to run each job in a throwaway macOS VM rather than as a user
on the host. [Tart](https://tart.run) clones an Apple Virtualization framework
VM in seconds. The supervisor loop stays the same, with three changes:

1. It clones a prepared image (`tart clone`).
2. It boots the clone and starts the ephemeral runner inside it.
3. After the job it deletes the clone.

Nothing a job writes then outlives the job, including the caches. Apple's
licence allows two macOS VMs per Mac at a time, which matches the limit of
about three heavy jobs per Mac.
