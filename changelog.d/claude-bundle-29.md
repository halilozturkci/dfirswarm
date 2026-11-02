### Added: linux-forensics `audit_events` reads the audit log with the standard library

- Read an explicit, ordered set of acquired `audit.log` files (rotations named by the caller, gzip allowed) and
  group the records into events by their `audit(<seconds>.<fraction>:<serial>)` stamp, across rotation boundaries.
  A group carries its locators, record types, the grammar's numeric fields, the lengths of command lines, `cwd`
  and PATH names, and the parts that are missing (a PATH short of `items=`, EXECVE arguments short of `argc`, an
  execve with no EXECVE). Command lines, `exe`, `cwd`, PATH names and typed names are never printed; the whole of
  every line goes to a 0600 file on `write_text` in a secret-output job.
- Report the rotation inventory, gaps between files and in rotation numbers, serial restarts, `lost=` counters and
  DAEMON records, and runs of time that go backwards. Uids and gids are named only from identity files of the evidence.

### Added: linux-forensics `audit_events` can compare itself with `ausearch` on a sample

- `compare_ausearch` runs the installed `ausearch` (`-if <sample> -r`, never `-i`) on the first 2000 lines of the first
  file and says `agree`, `disagree` or `not_run`, with the installed version and the differences counted and never shown.
  A one-record probe must come back through `-if <file> -r` first. The program runs in the tool's own process group:
  a deadline, an output past 32 MiB or a stop signal ends it and what it started. It is declared secret output.

### Added: linux-forensics `linux_persistence` lists where a root starts programs from

- List cron tables, system and user systemd units (the homes of the passwd and every directory under `home/`, so a deleted
  account's home is read), drop-ins in file-name order with the assignments that reset a list, enablement links, masks and aliases
  (listed, never followed), `.path` and `.socket` units, `rc.local`, `init.d` and XDG autostart, each with file, line and byte
  offset and every place tried named. Configuration and execution are separate fields (execution only from journal rows the
  caller declares), the effective state is always unresolved with the reasons, and a copy without links says enablement cannot
  be read. Command lines and environments, and key names systemd does not define, are lengths; the text goes to a 0600 file on
  `write_text` in a secret-output job. `persistence/mechanisms` names the tool.

### Added: linux-forensics `container_inventory` reads container runtime files of an extracted root

- Read the Docker data root (and roots named by `storage_roots`), rootless Podman stores and a Kubernetes node's CRI log
  directories: containers with locators into `config.v2.json` and `hostconfig.json`, lifecycle times, mounts, capabilities and
  log files, images, and layers by chain id with the ones missing from the store named. containerd's bolt database is
  listed as unsupported. Commands, arguments, environments, labels, binds and log text are lengths; the stored text goes to a
  0600 file on `write_text` in a secret-output job. Large JSON logs are streamed, lists are paged, and hostile JSON gives a
  refusal. `containers/docker` names the tool and the `target-fs` route.

### Added: linux-forensics `container_layers` builds the effective view of an image's layers

- Take an explicit chain of layer directories (base first, with an optional writable layer) or overlay2's own `lower`
  files, and give for each path the layer that supplies it and what each layer did to it (added, replaced, merged, deleted,
  made opaque, present but hidden). OCI `.wh.<name>` and `.wh..wh..opq` are told apart from overlayfs native whiteouts
  (a character device 0/0, `trusted.overlay.opaque`), and the answer says when the attribute could not be read. A missing
  lower layer, a link out of the store, a loop and a layer past the entry bounds are named and make the status partial.
  Nothing is mounted or run; with `copy: true` in a secret-output job named files are copied to `$OUT/layers-view` and never
  over a file that is there. `containers/layers-times` names the tool.

### Added: linux-forensics `package_verify` wraps debsums and rpm -V with their limits stated

- Run the installed `debsums` (`-r <root> -a`) or `rpm -V --root --dbpath --noscripts --nodeps --nodigest --nosignature` in
  the tool's own process group (no stdin, a fixed environment, a deadline, a 256 MiB output cap; a stop signal ends the program and
  what it started). The answer gives the scope (packages asked for, the database found and its backend, Debian packages with no
  md5sums file), every difference as a row with rpm's flags decoded, the first stderr lines by kind, and the lines it could not
  parse. The expected values are the acquired database's, so it never claims distribution authenticity. It states that it has
  NOT confirmed that the installed `rpm` suppresses `%verifyscript` with those options (no rpm was available to its tests).
  `packages/integrity` names the tool in place of its direct commands, `packages/baseline` agrees, and the `debsums` and `rpm`
  texts in `requires/host.json` say what is and is not confirmed.
