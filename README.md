# RepDry

A dry-run sandbox for arbitrary commands. `repdry` runs a command inside a
throwaway filesystem — the host fs is mounted read-only with overlayfs
uppers in a scratch dir — then reports everything it created, modified,
deleted, read, probed, and executed, and asks whether to apply the diff to
the real filesystem (default: discard).

Think "run `curl | sh` or `make install` and see the diff afterwards".

```sh
./out/RepDry --allow-net -- sh -c 'curl -fsSL https://example.com/install.sh | sh'
```

(The pipe has to be inside the sandboxed command — left outside, the host
shell would run `sh` on repdry's report. `--allow-net` is needed since the
network is unshared by default.)

## Usage

```
repdry [--allow-net] [-v] [--full]
       [--ignore REGEX]... [--ro DIR]... [--hide DIR]...
       -- COMMAND [ARGS...]
```

| Option          | Effect                                                                                          |
| --------------- | ----------------------------------------------------------------------------------------------- |
| `--allow-net`   | share the host network (default: unshared — connects fail but are still reported)                |
| `--ignore REGEX` | drop matching paths from the report (repeatable)                                                |
| `--ro DIR`      | contents stay visible, but writes there are silently discarded — the host never changes          |
| `--hide DIR`    | contents hidden from the payload entirely (empty tmpfs); writes discarded                        |
| `--full`        | show every traced row — common low-risk noise (shared libs, locale, `/dev`, ...) is hidden by default |
| `-v`, `--verbose` | dump the generated bwrap argv before running                                                  |
| `--`            | separator; everything after it is the command                                                    |

If the command changed the filesystem, repdry prompts
`apply these changes? [y/N]` — `y` applies the diff to the real fs;
anything else discards it. The scratch dir is always cleaned up, even on
SIGKILL, and the command's exit status becomes repdry's.

## Building

Prereqs: `g++`, `ccache`, and `/usr/bin/bwrap` at runtime (direct `unshare`
is blocked on some systems by `apparmor_restrict_unprivileged_userns`;
bwrap carries an AppArmor exception).

```sh
make            # builds out/RepDry
make test       # end-to-end suite (test/run_tests.sh, ~110 checks)
./out/RepDry -- <cmd>
```

## How it works

Two mechanisms, each doing what it's good at:

- **Containment — bubblewrap + overlayfs (kernel-enforced).** The command
  runs under `bwrap --unshare-all` with `/` bound read-only and an
  overlayfs upper over every directory that can legally be one, so writes
  land in a scratch dir under `/tmp` and the host is never touched.
- **Reporting — ptrace + seccomp cBPF.** A tracer follows the process tree
  and attributes file accesses to `exe(pid)`, then merges that with a walk
  of the overlay uppers (authoritative for the diff). Evasion or ptrace
  failure only degrades the report — it can never let a write escape,
  because the kernel owns the boundary.

## Limitations

- Dry-run covers local fs effects only. `--allow-net` opts back into real
  networking; writes by external daemons (DBus, sockets) escape the
  process tree and the overlay.
- Tracing is not a security boundary — io_uring submission-queue I/O, in
  particular, is only *detected*, not attributed.
- Applying the diff is per-entry `cp`/`symlink`/`rm` — not atomic, and no
  metadata beyond mode is preserved.

## Documentation

- [docs/overview.md](docs/overview.md) — concept, repo layout, terminology
- [docs/repdry.md](docs/repdry.md) — full usage, overlay planning rules,
  report format, limitations
- [docs/history.md](docs/history.md) — why the repo is named RepMake: it
  began as an experimental make replacement that learned dependencies by
  tracing builds, pivoted through a `SHELL = ...` make instrumentation
  phase, and shed everything but the tracer when RepDry arrived.

## Status

Experimental / WIP — expect rough edges.
