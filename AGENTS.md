# AGENTS.md — RepMake / RepDry

## What this is

RepDry (`repdry` branch): a dry-run sandbox. Runs a command inside
bubblewrap with the host fs read-only + overlayfs uppers in a scratch dir,
then reports what it read/wrote/deleted/probed/executed and can apply the
diff on confirmation. Built on a ptrace+seccomp tracer inherited from the
project's earlier incarnation (RepShell — see `docs/history.md`).

Docs live in `docs/`:

* `docs/overview.md` — concept, layout, terminology.
* `docs/repdry.md` — usage, bwrap+overlay containment, overlay planning
  rules, report format, limitations.
* `docs/history.md` — evolution from the old standalone "RepMake" build
  tool through RepShell to the current RepDry-only state.

## Build & test

Prereqs: `g++`, `ccache`; runtime needs `/usr/bin/bwrap` — direct `unshare`
is blocked on this machine by `apparmor_restrict_unprivileged_userns`.

```sh
make            # builds out/RepDry
make clean      # rm -rf out
make test       # runs test/run_tests.sh (~110 checks)
./out/RepDry -- <cmd>   # smoke test
```

`test/run_tests.sh` is the end-to-end suite: it exercises the CLI flags,
the apply/discard prompt, scratch cleanup (incl. SIGKILL), and per-syscall
attribution. `test/harness.c` is a small C helper compiled on the fly —
one subcommand per syscall coreutils can't reach (io_uring, sendfile,
vmsplice, openat2, execveat, xattr, *at variants, sockets…). Test fixtures
must live under the repo (NOT /tmp — the sandbox binds /tmp to an empty
dir, hiding host files there).

## Code map

* `src/cpp/RepDry.cpp` — everything: arg parsing (`--allow-net`, `--ignore`,
  `--ro`, `--hide`, `--full`, `-v`, `--`), mount-aware overlay planning, bwrap argv
  construction, per-pid ptrace event loop, upper-layer diff walk, report
  printer, apply-on-confirm.
* `include/tracer.hpp`, `src/cpp/tracer.cpp` — shared tracer core:
  `runTracedExec` (seccomp cBPF + `PTRACE_TRACEME` + exec, with
  fd-arg and arg1 BPF filters), `read_file` (`PTRACE_PEEKTEXT` path reads),
  `waitForSyscallRet`, `matchsAnyIgnore`.
* `include/logging.hpp` — `pr_debug`/`pr_debug_raw` (stderr; can be
  compiled to no-ops by swapping the commented macros).

## Conventions & gotchas

* C++11, `.clang-format` (LLVM base, 240 col limit) — run clang-format after
  edits. Compiler flags: `-Wall -Werror -Wextra`.
* `out/` is the only build-artifact dir and is git-ignored.
* Debug tracing: uncomment the no-op `pr_debug` defines in `logging.hpp`.
* The project is experimental/WIP — expect TODOs. Read `docs/repdry.md`
  before changing overlay planning or the report, and `docs/history.md` for
  why the repo is named RepMake.
