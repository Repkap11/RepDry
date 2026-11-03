# RepDry — dry-run sandbox

`repdry` runs a command inside a throwaway filesystem and reports what it did,
without letting it modify the real system. Think "run `curl | sh` or
`make install` and see the diff afterwards".

## Usage

```
repdry [--allow-net] [-v]
       [--ignore REGEX]... [--ro DIR]... [--hide DIR]...
       -- COMMAND [ARGS...]
```

| Option | Effect |
|---|---|
| `--allow-net` | share the host network (default: unshared — DNS/connects fail but are still reported) |
| `--ignore REGEX` | drop matching paths from the report (repeatable, `std::regex_match`) |
| `--ro DIR` | real contents stay visible, but writes are silently discarded — the payload sees a normal writable fs, the host never changes |
| `--hide DIR` | contents hidden from the payload entirely (empty tmpfs at DIR); writes discarded. Traced read/write attempts still appear in the report |
| `-v`, `--verbose` | dump the generated bwrap argv before running |
| `--` | separator; everything after it is the command |

After the command exits, repdry prints the report and — only if the
filesystem actually changed — prompts `apply these changes? [y/N]`. `y`
applies the diff to the real fs; anything else (including non-interactive
stdin/EOF) discards it. The scratch dir is always removed — even on
crash: a forked babysitter process holds a pipe whose write end dies with
repdry, and wipes the scratch dir on EOF. The command's exit status is
repdry's exit status.

## Architecture

Two mechanisms, each doing what it's good at:

**Containment — bubblewrap + overlayfs (kernel-enforced).** repdry execs
`bwrap --unshare-all` with the host fs bound read-only at `/`, plus a
`bwrap --overlay` (persistent upperdir under the scratch dir) over every
directory that can legally be an overlay lower. Writes land in
`SCRATCH/upper/<path>`; the host is never touched. `/tmp` is replaced by an
empty writable dir (the scratch dir itself lives under `/tmp`), the scratch
dir is hidden from the payload with an empty bind, and `--proc`/`--dev`
pseudo-mounts are added.

Direct `unshare` doesn't work on this machine — Ubuntu's
`apparmor_restrict_unprivileged_userns` strips `CAP_SYS_ADMIN` from
unconfined binaries — but `/usr/bin/bwrap` has an AppArmor exception, which
is why bwrap is the backend.

**Reporting — ptrace + seccomp cBPF (best-effort attribution).** The existing
tracer core (`tracer.cpp`, inherited from RepShell) follows the bwrap process
tree, tracks per-pid cwd and fd→path tables, and classifies syscalls into
reads / writes / deletes / probes / execs / connects. The report merges this
with a walk of the overlay uppers (authoritative for created/modified/deleted
via whiteouts). Evasion or ptrace failure only degrades the report — it can
never let a write escape, because the kernel owns the boundary.

## Overlay planning

Empirical constraints on this kernel/bwrap combo (kernel 7.0, Ubuntu 24.04+):

- a lowerdir may **not contain sub-mounts** (clone of the lower path fails) —
  planDir() descends into such dirs instead (`/`, `/boot`, `/snap`)
- the lower fs must support **user xattrs** (`userxattr` overlays) — vfat,
  ntfs, squashfs, fuse, etc. are skipped and stay read-only
- mount roots are fine as lowerdirs *if* the above hold (`/tmp`, `/run/lock`)
- unreadable dirs (`/root`, `lost+found`) stay read-only
- the scratch dir must never sit inside its own lower — its ancestors are
  descended and the dir itself is hidden by an empty bind
- cwd under an emptied bound dir gets its own late overlay so `--chdir` works

Everything that can't be covered stays read-only; attempted writes there fail
with EROFS and show up in the trace.

## Report

```
== Created (sandbox only) ==      upper-layer diff (authoritative)
== Modified (sandbox only) ==
== Deleted (sandbox only) ==
== Wrote (traced) ==              syscall-level view, per-process;
== Deleted (traced) ==            "(discarded)" = under --ro/--hide, won't apply
== Read ==
== Probed / statted only ==       includes "(missing)" for ENOENT probes
== Executed ==
== Network connects ==            sockaddr rendered per family
== io_uring detected ==           ring users + registered files;
                                  per-SQE I/O isn't attributable
```

The diff comes from the upper layer; the traced sections attribute each path
to `exe(pid)`. Setup noise is suppressed structurally, not by name: bwrap only
ever execs once (in the root pid), so the first successful `execve` in any
other pid is treated as the payload boundary — everything before it is
infrastructure and dropped, everything after it is payload, including a
nested `bwrap` the payload itself might run.

## Limitations

- **Dry-run covers local fs effects only.** The network is unshared by
  default; `--allow-net` opts back in, and then traffic really happens.
  Writes by external daemons (DBus, sockets) escape the process tree and
  the overlay.
- **Tracing is not a security boundary** — TOCTOU on path strings, detectable
  via `TracerPid`, incomplete syscall coverage. io_uring is the main hole:
  submission-queue I/O happens through shared memory with no per-op syscall,
  so repdry can only *detect* ring use (`io_uring detected` report section,
  including files registered via `IORING_REGISTER_FILES`) — reads/writes
  issued through the ring are not attributed. `sendmsg`-passed fds resolve
  lazily via `/proc` on first use. The overlay is the wall; the trace is the
  narrative — an unattributed write still cannot escape the diff.
- **Applying is `cp`/`symlink`/`rm` per upper entry** — not atomic, no
  metadata beyond mode preserved, and deletions via whiteouts are applied
  with `rm -rf`.
- Files at the top level of `/` and in non-overlayable dirs are read-only.
