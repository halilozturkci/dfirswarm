#!/usr/bin/env python3
"""A stand-in for `memprocfs` whose FUSE mount stops answering, for tests/pack-memory-fuse-bound.test.ts.

It is a minimal FUSE server over /dev/fuse (the kernel's own wire format, linux/fuse.h, protocol 7.31): it mounts through
fusermount3 (or fusermount), answers INIT, and then, depending on the mode, never answers GETATTR or LOOKUP again.

    stall-getattr     the process that mem_fs started is the server; INIT is answered and nothing else, so the first stat of the
                      mount (the readiness check) blocks in the kernel for as long as the server lives
    stall-after-term  the server is a detached process (double fork, own session, no pipe of the engine); it serves the root and
                      a `sys` directory with an empty listing until the process that mem_fs started is terminated, which leaves
                      the file named by STALL_FLAG behind, and from then on it answers nothing: the engine is gone, the mount is not

Environment: STALL_MODE, STALL_FLAG (stall-after-term), STALL_PIDFILE (the server's pid), STALL_READY (a file written once the mount
is up). Arguments, as mem_fs passes them to MemProcFS: -device <path> -mount <dir>.
"""
import errno
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

FUSE_LOOKUP, FUSE_FORGET, FUSE_GETATTR, FUSE_RELEASE, FUSE_FLUSH, FUSE_INIT = 1, 2, 3, 18, 25, 26
FUSE_OPENDIR, FUSE_READDIR, FUSE_RELEASEDIR, FUSE_INTERRUPT, FUSE_DESTROY, FUSE_BATCH_FORGET = 27, 28, 29, 36, 38, 42
S_IFDIR = 0o040000


def attr(ino: int) -> bytes:
    # fuse_attr: ino size blocks atime mtime ctime atimensec mtimensec ctimensec mode nlink uid gid rdev blksize padding
    return struct.pack("<QQQQQQIIIIIIIIII", ino, 0, 0, 0, 0, 0, 0, 0, 0, S_IFDIR | 0o755, 2, os.getuid(), os.getgid(), 0, 4096, 0)


def mount(directory: str) -> int:
    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    helper = shutil.which("fusermount3") or shutil.which("fusermount")
    if not helper:
        sys.exit("no fusermount")
    env = dict(os.environ, _FUSE_COMMFD=str(theirs.fileno()))
    subprocess.run([helper, "-o", "fsname=stall", "--", directory], env=env, pass_fds=[theirs.fileno()], check=True)
    theirs.close()
    _msg, fds, _flags, _addr = socket.recv_fds(ours, 16, 1)
    ours.close()
    return fds[0]


def serve(fd: int, stalled) -> None:
    while True:
        try:
            buf = os.read(fd, 1 << 21)
        except OSError as exc:
            if exc.errno in (errno.ENOENT, errno.EINTR, errno.EAGAIN):
                continue
            return
        if len(buf) < 40:
            return
        length, opcode, unique, nodeid, _uid, _gid, _pid, _pad = struct.unpack_from("<IIQQIIII", buf)
        body = buf[40:length]

        def reply(error: int = 0, data: bytes = b"") -> None:
            os.write(fd, struct.pack("<IiQ", 16 + len(data), error, unique) + data)

        if opcode == FUSE_INIT:
            # major minor max_readahead flags max_background congestion_threshold max_write time_gran max_pages map_alignment flags2 unused[7]
            reply(0, struct.pack("<IIIIHHIIHHI28x", 7, 31, 65536, 0, 16, 12, 65536, 1, 0, 0, 0))
        elif opcode in (FUSE_FORGET, FUSE_BATCH_FORGET, FUSE_INTERRUPT):
            continue
        elif stalled():
            continue                              # the request is never answered
        elif opcode == FUSE_GETATTR:
            reply(0, struct.pack("<QII", 0, 0, 0) + attr(nodeid or 1))
        elif opcode == FUSE_LOOKUP:
            if nodeid == 1 and body.rstrip(b"\0") == b"sys":
                reply(0, struct.pack("<QQQQII", 2, 0, 0, 0, 0, 0) + attr(2))
            else:
                reply(-errno.ENOENT)
        elif opcode == FUSE_OPENDIR:
            reply(0, struct.pack("<QII", 1, 0, 0))
        elif opcode == FUSE_READDIR:
            reply(0, b"")
        elif opcode in (FUSE_RELEASEDIR, FUSE_RELEASE, FUSE_FLUSH):
            reply(0)
        elif opcode == FUSE_DESTROY:
            reply(0)
            return
        else:
            reply(-errno.ENOSYS)


def main() -> None:
    args = sys.argv[1:]
    directory = args[args.index("-mount") + 1]
    mode = os.environ["STALL_MODE"]
    flag = os.environ.get("STALL_FLAG", "")
    fd = mount(directory)
    if mode == "stall-getattr":
        with open(os.environ["STALL_PIDFILE"], "w") as fh:
            fh.write(str(os.getpid()))
        with open(os.environ["STALL_READY"], "w") as fh:
            fh.write("ready")
        serve(fd, lambda: True)
        return
    # stall-after-term: the engine is this process; the server is a detached one that does not hold the engine's pipes
    if os.fork() == 0:
        os.setsid()
        if os.fork() != 0:
            os._exit(0)
        devnull = os.open(os.devnull, os.O_RDWR)
        for std in (0, 1, 2):
            os.dup2(devnull, std)
        with open(os.environ["STALL_PIDFILE"], "w") as fh:
            fh.write(str(os.getpid()))
        serve(fd, lambda: bool(flag) and os.path.exists(flag))
        os._exit(0)
    os.wait()
    os.close(fd)

    def bye(*_unused):
        with open(flag, "w") as fh:
            fh.write("stalled")
        os._exit(0)

    signal.signal(signal.SIGTERM, bye)
    with open(os.environ["STALL_READY"], "w") as fh:
        fh.write("ready")
    while True:
        time.sleep(0.05)


main()
