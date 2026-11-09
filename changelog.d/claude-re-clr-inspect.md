### Added: reverse-engineering `clr_inspect` reads a .NET assembly's metadata and, in a secret job, writes a labelled C# reconstruction with ilspycmd

`clr_inspect` reads a .NET assembly's CLR header and metadata root as structure
and prints metadata only: the runtime version, the flags, the entry point as a
token, whether a strong-name signature, resources or a native header are
declared, the metadata version string, the streams, and the row counts the table
stream's header declares for ten tables. Nothing from the tables, heaps, IL or
resources is read (`pe_directories` reads the tables). A PE with no CLR header is
`unsupported`; a damaged header or root is `partial` with the problem named.

With `decompile` the tool runs `ilspycmd --disable-updatecheck` on the file and
writes the decompiled C# to a file under `$OUT/tool-output`, mode 0600, never
inline. The file begins with comment lines that say it is a reconstruction by a
decompiler, an interpretation of the IL and not the author's source, then the
program's output unchanged. `decompile` is declared `secret_output` in the
manifest and is refused as JSON, before anything is read or created, outside a
job run as secret output. The program gets a fixed environment (no caller
variable, no proxy, an empty home), a time limit and an output budget
(`max_output_bytes`); past either, it and what it started are ended and the
partial file is removed. A nonzero exit status with output is `partial`; the
program's error text goes to a log file and is never printed; a file that
changed while the program read it is `failed`. The program's words are never
parsed: only its exit status, its `--version` line and the files it wrote are
used. A stop signal ends the program and removes the files of the call.

`ilspycmd` was never run for real by this change: the machine that wrote it has
no .NET runtime, so every case that starts the program uses a stand-in, and the
options used are those of the package's own README (11.2.0.10050). A case that
runs the real program is skipped unless `ilspycmd` and an assembly
(`DFIRSWARM_CLR_SAMPLE`) are present. The tool makes no network request itself;
whether the program makes any other request was not measured.

The pack declares `ilspycmd` 11.2.0.10050, optional, from nuget.org: the amd64
image takes the Native AOT platform package `ilspycmd.linux-x64` (no runtime), the
arm64 image the framework-dependent `ilspycmd.any`, run by the .NET runtime the
pack already declares. Each package is pinned by sha256 and has no NuGet
dependency.

### Added: images `install.py` unpacks a pinned NuGet package and a download can name its interpreter per architecture

A pinned download whose file is a `.nupkg` (a zip file) is checked against its
sha256 and then unpacked whole by rules of its own: regular files and
directories only, every name under the program's directory (an absolute name, a
drive letter, a backslash, a control character or a `..`, `.` or empty component
is refused), nothing existing replaced or followed (`O_EXCL`, `O_NOFOLLOW`, no
link on the way), a link, a device, an encrypted member or a method other than
stored or deflate refused, at most 2,000 members, 256 MiB for a member and 512 MiB
in all, and every file 0644 and every directory 0755 whatever the archive says.
A refused package leaves only its own archive behind and the program is recorded
as not installed. A download's architecture entry may also carry its own `run`,
which wins over the download's, so one program can be a native build on one
architecture and a .NET assembly on the other.
