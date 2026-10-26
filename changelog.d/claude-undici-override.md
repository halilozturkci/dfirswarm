### Security: undici is held at 8.12.2 or later

- The pinned Pi coding agent depends on undici 8.10.2 exactly, and no Pi release (1.4.0 included)
  moves it, so Dependabot could not raise it. Without the fix, `fetch()` in undici 8 can crash the
  process when a server answers with more than five content codings and closes the connection
  early (GHSA-xjj6-f33q-929c). An npm override takes it to 8.12.3, the patched line; the lockfile
  has it once, at the top level. This covers the repository's own install (development and CI); the
  VM images install Pi on their own and still carry what Pi pins.
