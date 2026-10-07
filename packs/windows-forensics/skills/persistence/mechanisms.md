---
id: persistence/mechanisms
title: Services, run keys, startup: configured versus fired
when: You sweep for ways something runs again, or must tell configuration from execution.
needs: []
tools: [regkv, icat_extract, file_type]
requires_host: [fls]
---

Use when you sweep services, drivers, Run keys and startup folders. Not for tasks, COM, WMI or replaced binaries (`persistence/tasks-com-wmi`: read it only if those families are in scope).

Sweep by family and record what you examined; a configured mechanism and one that fired are separate findings. Read hives by `registry/overview`.

- Services and drivers: `SYSTEM\ControlSet00n\Services\<name>`: control set, name, `Type`, `Start` (0 boot, 1 system, 2 automatic, 3 on demand, 4 disabled), the account in `ObjectName`, `ImagePath` with its arguments, `Parameters\ServiceDll` for a hosted service, failure-action and trigger configuration, and the identity of the file named (`icat_extract` returns its sha256, `file_type` what it is). Many legitimate components live under the Windows directory, so a directory alone is no finding: look for configuration that does not fit the component it claims to be, an imitating name, a file that is not what its name says, an account or start mode out of line with its peers. Correlate with install and change events (7045, 4697, 7040: `logs/events`) and execution evidence; a missing install event may be retention or collection.
- Run and startup, in `SOFTWARE` (and its 32-bit view under `Wow6432Node`) and each `NTUSER.DAT`: `...\CurrentVersion\Run`, `RunOnce`, `Policies\Explorer\Run`, and `Explorer\User Shell Folders` and `Shell Folders` (Startup, Common Startup). List the resolved Startup folders with `fls` and extract what is there. `RunServices` and `RunServicesOnce` are legacy and build-specific: record them where present, do not assume the build reads them.
- Logon-time settings (Winlogon `Shell` and `Userinit`, image file execution options `Debugger`, `AppInit_DLLs` with `LoadAppInit_DLLs`) work only under conditions of the build and policy: establish the referenced component and the condition before calling one active.
- Activation: find an execution record that fits the trigger and times (Prefetch, Amcache, SRUM, process creation with its parent, service state events: `execution/overview`) and say what the record would look like had it not fired. A second reader gives an independent sweep (`registry/readers`).
- A negative lists the families, hives and profiles examined and what was unavailable or unsupported (the WMI repository, a user whose hive was not collected, a dirty hive not replayed); it infers no operator intent.

Sensitive output: a Run value, an `ImagePath` or an argument can hold a typed secret that `regkv` does not recognise (it withholds by name and place only): describe the command's shape, and run in a job with `secret_output: true` when the hive may hold one.
Shows: that an entry is configured. Does not show: that it ran, who set it, when (a key's last write is key-level), or why; no entry does not show that none existed. Record: control set, key path, value, file identity, the execution record sought.
