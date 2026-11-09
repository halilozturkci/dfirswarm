# Why eleven of the eighteen were not answered

The run answered six questions at high confidence, one at medium, offered
eight as low-confidence hypotheses and left three open. This is the account of
what stopped it — written out in full, because it is the most useful thing
this run produced.

Nothing here is about the swarm reasoning badly. It found the container, it
found the key, it identified the format, and it wrote its own tool when the
host had none. It was stopped by three layers of file format and one missing
library, and by the moment it found out.

## The wall: one file, three layers

```
Users/phorger/Documents/desktop.ini            an ordinary NTFS file
   └── :vault.vhdx                             an alternate data stream       ← layer 1
          └── VHDX container                   Microsoft virtual disk         ← layer 2
                 └── BitLocker volume          -FVE-FS- , recovery protector  ← layer 3
                        └── NTFS filesystem    Spending.xlsx, the PSD
                                               template, the ATM PDF, baker/
```

Five to seven of the eighteen questions live in that last box: the amount of
the April take (Q6), the luxury purchase (Q9), the designer's full name
(Q11), the print-batch timestamps (Q13), the printer (Q14), and the material
behind the ATM and bank-statement questions (Q15, Q18).

**The swarm got through layer 1 in twenty minutes.** `s821c08` read the
alternate data stream off the file system with `icat` at inode `102124-128-4`
and wrote it out as `work/extracted/s821c08/vault.vhdx`, sha256
`877fff02e22383cccd511e9e94a77c83f7acbcc789e0ed9d2343e1c89234da3f`. It
recognised the VHDX header and the `-FVE-FS-` BitLocker signature inside it,
and found the Recent LNK showing the container had been mounted as `Y:`.

**It then did something the question did not ask for.** `s821c01` went
looking for the key and found it on the *other* image: an iPhone note, inside
an iTunes backup, inside the laptop image —
`Users/phorger/AppData/Roaming/Apple Computer/MobileSync/Backup/…/NoteStore.sqlite`,
the note titled *BitLocker recovery*, gzip-compressed inside a Core Data
blob. Identifier `929983CA-5012-49E9-A194-4550C08C6127`, recovery key
`590238-514580-…-636911`. `s821c00` then confirmed that identifier matches a
protector GUID in the VHDX's own FVE metadata at offset `0x8400000`, after
normalising the little-endian GUID — exhibit E-55.

So: the right file, the right format, the right key, all proved on the record.
And then nothing.

## What it tried, minute by minute

| Time | Agent | Command | What happened |
| --- | --- | --- | --- |
| 18:11:27 | s821c02 | `which dislocker bdemount bdeinfo qemu-img guestmount` | none of them on the host |
| 18:15:10 | s821c08 | `command -v bdemount bdestat bitlocker…` | nothing |
| 18:15:46 | s821c04 | `which dislocker bdemount mkfs.vfat…` | nothing |
| 18:16:07 | s821c04 | `brew install dislocker` | netguard denied `formulae.brew.sh` |
| 18:19:18 | s821c04 | `hdiutil attach` on the VHDX | macOS does not attach VHDX |
| 18:20:09 | s821c04 | `which qemu-img` | not installed |
| 18:23:38 | s821c04 | `pip3 install dislocker` | netguard denied `pypi.org` — **17 denials in the proxy log** |
| 18:34:07 | s821c02 | forged `bde_unlock` (python3) | its own BitLocker reader, 12 calls |
| 18:44:48 | s821c00 | forged `bde_unlock2` v3 | a third attempt, 15 calls, `InvalidTag` on every AES-CCM variant |

The last two rows are the part worth keeping: with no tool and no way to
install one, two agents wrote a BitLocker implementation in Python from the
format documentation, got as far as locating the FVEK-encrypted VMK and
running AES-CCM against it, and failed on the authentication tag. Writing a
correct BitLocker reader inside a 60-minute case is not a reasonable thing to
ask of anyone; that they tried is the tool-forging feature working, and that
it failed is not a defect of the swarm.

## The question this raises: is a package enough, or do we need privileges?

It is the right question, and the answer turns on a distinction that is easy
to miss.

**Mounting is privileged. Reading is not.**

The tools the agents reached for first — `dislocker`, `bdemount` (libbde),
`vhdimount` (libvhdi) — are FUSE tools. They do not read a volume so much as
*present* one: they create a mount point and serve a virtual filesystem from
it. That needs a FUSE implementation in the kernel, which on macOS means
macFUSE (a kernel extension: an administrator install, a reboot, and on
Apple Silicon a reduced-security boot), and on Linux means the `fusermount`
setuid helper and a mount point. `hdiutil attach` is the same class of
operation one layer down. **If the answer had been "install dislocker", the
instinct would have been right: we would have installed it and still been
stuck**, because the sandbox has no root and the panes are ordinary processes
owned by the examiner.

But there is a second way to read every one of these formats, and it is the
one the DFIR tooling settled on years ago: **open the container as a file and
decrypt in user space**. The libyal libraries all ship Python bindings that
do exactly this:

| Layer | Mount-based (privileged) | In-process (no root) |
| --- | --- | --- |
| VHDX | `vhdimount`, `hdiutil attach` | `pyvhdi` — opens the file, exposes the volume as a byte stream |
| BitLocker | `dislocker … -- /mnt`, `bdemount` | `pybde` — `set_recovery_password()`, then `read_buffer()` returns plaintext |
| NTFS inside it | `mount -o loop` | `pytsk3` — takes a byte-stream handler instead of a device |
| all three at once | — | `dfvfs` — composes EWF / VHDX / BitLocker / LUKS / NTFS handlers in one process; it is what Plaso uses |

That stack answers the user's question directly: **no, privileges would not
have been needed** — but only because those libraries exist and expose the
format without a mount. Had we opened the package index and installed only
`dislocker`, the case would still have been closed. The lesson is not "let
them install things", it is "install the libraries that read, not the tools
that mount".

Two honest caveats:

1. `libbde-python` and `libvhdi-python` build from source on install. On a
   machine with a C toolchain that is a minute; on one without, the install
   fails and the run is no better off. So an index is not a guarantee, which
   is why the toolbox check exists and why `--toolbox-required` should be the
   default for a case: better to refuse to start than to find out at minute
   forty.
2. There is a class of work that genuinely does need privilege — mounting a
   filesystem to run a tool that only speaks to mount points, attaching a
   loop device, reading a raw device. For that the answer is a disposable
   container with the evidence bind-mounted read-only, not `sudo` on the
   examiner's machine. That is B17 in the improvement plan, and it is not
   what this case needed.

## The other six that were not the vault

| Q | Why it was not answered |
| --- | --- |
| Q4 · where William lives | Answered at medium confidence with coordinates that turned out to be the *lab* geofence in East St. Louis, not his home. The iPhone `consolidated.db` geofence was the first location artefact found and nothing challenged it; the Uber "home" label that would have corrected it was never opened. A single-source answer, and the report says so. |
| Q7 · the March celebration venue | Reached "a downtown St. Louis bar" from the Telegram thread and stopped. The Splitwise database that names the restaurant was found by filename but never queried — the swarm was 40 minutes in and had moved to the vault. |
| Q10 · the May concert | Recovered a string (`Magic Mandrake`) from a Telegram blob and offered it as a hypothesis. The poster image in the browser cache — the actual artefact — was not reached. |
| Q12 · the lab address | Had the geofence coordinates and the words "uncle's garage" from chat, but never resolved the coordinates to a street address. `nominatim.openstreetmap.org` *was* on the allowlist; nobody called it. |
| Q13 · the largest print batch | Needed the Telegram bot conversation parsed for batch sizes and completion times. The postbox was extracted and dumped; the batch arithmetic was never done. |
| Q14 · the printer model | The USB device history in the registry hives was extracted (`SYSTEM`, `SOFTWARE`) but the `USBSTOR`/`VID_`/`PID_` lookup was not run. The swarm recorded that "printer details were sent separately" from a chat message and treated the question as blocked. |

Five of those six are not missing tools. They are a 60-minute clock spent on
the vault, and a team that — correctly, by its own dependency map — judged the
vault to be worth more. `work/dependencies.md` shows it: Q6, Q9, Q11, Q15,
Q16 and Q18 were all marked as gated behind Q8, which made the vault look
like the highest-value target on the board. It was, and it was also the one
thing the host could not open.

## What was changed because of this

- The `crypto` toolbox set now names the in-process readers — `pybde`,
  `pyvhdi`, `pytsk3`, `dfvfs` — beside the FUSE tools, with a comment saying
  which is which and why it matters.
- `--toolbox auto` reads the goal document: a goal that says "encrypted
  container" adds the crypto set by itself.
- The evidence catalog warns when it has just seen a BitLocker or
  virtual-disk signature on a run with no crypto set.
- `--allow-install` opens `pypi.org` into a prefix inside the sandbox, so the
  seventeen denials become an install — of libraries that read, not tools
  that mount.
- Root on the examiner's host stays refused, and the reason is written down
  in [safety](../../../safety.md).

The next run on this case starts with `--toolbox dfir,crypto
--toolbox-required`, and either the libraries are there or it does not start.
