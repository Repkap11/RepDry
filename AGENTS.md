# AGENTS.md — RepMake / RepShell / RepDry

## What this is

RepShell: a Linux/x86-64 tool that discovers build dependencies automatically
by tracing file-access syscalls. It is used as the `SHELL` in a GNU Makefile;
each recipe runs under seccomp+ptrace, and the learned dependencies are merged
into `RepDep.d` (Makefile syntax) which the Makefile `-include`s. Recipes need
no hand-written prerequisites.

RepDry (`repdry` branch): a dry-run sandbox built on the same tracer. Runs a
command inside bubblewrap with the host fs read-only + overlayfs uppers in a
scratch dir, then reports what it read/wrote/deleted/probed/executed and can
`--commit` the diff. See `docs/repdry.md`.

Full docs live in `docs/`:

* `docs/overview.md` — concept, layout, terminology (real deps vs sus deps,
  `REP_SPACE`).
* `docs/usage.md` — CLI flags, Makefile integration, `RepDep.d` sample,
  limitations.
* `docs/internals.md` — tracing machinery, syscall→dep classification,
  `RepDep.d` write path, build pipeline.
* `docs/history.md` — evolution from the old standalone "RepMake" build tool
  (deleted code, `repshell` branch) to the current shell-wrapper design.
* `docs/repdry.md` — the dry-run sandbox: bwrap+overlay containment, overlay
  planning rules, report format, limitations.

## Build & test

Prereqs: `antlr4`, `cmake`, `g++`, `ccache`; `libs/antlr4-cpp-runtime` is a
git submodule built via cmake into `out/antlr_runtime`.

```sh
make            # builds out/RepShell + out/RepDry (also generates
                # out/antlr_src from src/antlr/RepShell.g4)
make dev        # additionally builds example/
make clean      # rm -rf out
make valgrind   # run the example under valgrind
cd example && ./full_test.sh   # iterative-build smoke test
```

There is no unit test suite; the `example/` directory (toy C project with a
RepShell-wired Makefile) is the de-facto test harness.

## Code map

* `src/cpp/RepShell.cpp` — arg parsing (`--task`, `--shell`, `--ignore`,
  `--`), `traceBash` ptrace event loop, `RepDep.d` parse/merge/rewrite under
  `flock`.
* `src/cpp/RepDry.cpp` — repdry: arg parsing, mount-aware overlay planning,
  bwrap argv construction, per-pid ptrace event loop, upper-layer diff walk,
  report printer, `--commit` applier.
* `include/tracer.hpp`, `src/cpp/tracer.cpp` — shared tracer core:
  `runTracedExec` (seccomp cBPF + `PTRACE_TRACEME` + exec), `read_file`
  (PTRACE_PEEKTEXT path reads), `waitForSyscallRet`, `matchsAnyIgnore`.
* `src/cpp/utils.cpp`, `include/utils.hpp` — string helpers (`str_startsWith`,
  `str_equalsAny`), `flagsToString`.
* `include/rules.hpp` — `Rule { name, real_deps, sus_deps }`.
* `include/sys_map.hpp` — syscall-number→name table for debug prints.
* `include/logging.hpp` — `pr_debug`/`pr_debug_raw` (stderr; can be compiled
  to no-ops by swapping the commented macros).
* `src/antlr/RepShell.g4` — grammar used to re-parse `RepDep.d` (supports the
  `REP_SPACE` sus-dep marker). `src/antlr/RepMake.g4` is legacy — not compiled.
* `example/` — `Makefile` showing the `SHELL = ../out/RepShell ... --task $@ --`
  integration, `full_test.sh` iterative-build test, toy C sources.

## Conventions & gotchas

* C++11, `.clang-format` (LLVM base, 240 col limit) — run clang-format after
  edits. Compiler flags: `-Wall -Werror -Wextra`.
* Generated/temporary files: `out/` (all build artifacts, incl. ANTLR
  codegen), `RepDep.d`, `example/*.o`, `example/example` — all git-ignored;
  don't commit them.
* `REP_DEP_FILE_NAME` is hardcoded to `RepDep.d` in `RepShell.cpp` (and again
  as a literal in `parseExistingRules`).
* Traced children are filtered to relative paths only — absolute paths, `.`,
  `/tmp`, directories, and `--ignore` matches are excluded from the graph.
* repdry needs `/usr/bin/bwrap` — direct `unshare` is blocked on this machine
  by `apparmor_restrict_unprivileged_userns`. ANTLR headers are included via
  `-isystem` so their warnings don't hit `-Werror`.
* Debug tracing: uncomment the no-op `pr_debug` defines in `logging.hpp`.
* `example/fish` is an empty leftover file.
* Working tree note: the project is experimental/WIP — expect TODOs and dead
  code (e.g. `removeFileAsDep` is never set). Read `docs/internals.md` before
  changing syscall classification.
