# Project history

The repository went through two distinct architectures (standalone build
tool, then make-shell wrapper) before landing on the current dry-run
sandbox, RepDry. This document is historical — everything described in
phases 1–4 has since been deleted.

## Phase 1 — RepMake the build tool (Oct 2023, `master` through ~`dbdbc87`)

RepMake started as a **standalone replacement for make**. Layout at commit
`b46dc28` ("Correctly run tasks with dep files"):

```
src/cpp/repmake.cpp      # main: parse build files, build rule graph, schedule
src/cpp/rules.cpp        # Rule::runTasksInOrder — topo sort + timestamps + run
src/cpp/trace_tasks.cpp  # ptrace/seccomp tracer for a single rule's tasks
include/rules.hpp        # rich Rule class (triggers, timestamps, task queue)
src/antlr/RepMake.g4     # grammar for the RepMake build-file format
example/RepMake          # the build file itself (Make-like syntax)
```

How it worked:

* You wrote a `RepMake` file — Make-like `target: deps` rules with indented
  task lines — *without* necessarily declaring all deps.
* `repmake` parsed `RepMake` **and** the previously-generated `RepDep.d` with
  ANTLR4, building a graph of `Rule`s (`deps_str`, `dep_rules`, `triggers`,
  `tasks`).
* `Rule::runTasksInOrder` did a topological traversal of only the requested
  targets, comparing per-file millisecond timestamps
  (`self_modified_timestamp` vs. `deps_modified_timestamp`) to skip
  up-to-date work — its own incremental-build engine.
* Each rule's task list ran via `bash -x -c` under `trace_tasks()` — a
  ptrace+seccomp tracer — and the files it opened were written back into
  `RepDep.d`, so the declared graph improved itself every run.

## Phase 2 — ptrace experiments (late 2023)

The middle of `master`'s history (`25aab28` "Log syscalls with ptrace" →
`b46dc28`) is incremental work on the tracer: seccomp cBPF filters to avoid
stopping on every syscall, following `fork`/`vfork`/`clone` into child
processes, reading path arguments out of tracee memory, tracking fd→path
mappings, and learning deps into a `.RepDep`/`RepDep.d` file.

## Phase 3 — the `repshell` branch (mid 2024)

Branch point: `dbdbc87`. The insight: **don't replace make — instrument its
shell**. On `repshell` (`a97eeef` "Change repo to initial hello world for
RepShell" onward) the code shrank to `src/repshell.cpp` plus
`src/trace_tasks.cpp`, and the integration became:

```make
SHELL = ../out/repshell $@
```

i.e. make's recipe-invocation mechanism itself supplies the target name and
the command. RepShell traces the recipe and appends to `RepDep.d`, which the
Makefile `-include`s. All the scheduler/parser machinery of phase 1 became
unnecessary — GNU make does the ordering; RepShell only does the tracing and
dep bookkeeping.

## Phase 4 — merged back to master (Sep 2024)

* `8dfbac1` "Merge in repshell code" — brought the RepShell design onto
  master, initially alongside the old RepMake sources.
* `a374828` "Delete repmake files, all in on repshell" — removed
  `src/RepMake.cpp`; the binary became `RepShell` only. The `RepShell.g4`
  grammar gained the `REP_SPACE`/sus-dep list so `RepDep.d` could round-trip
  through the ANTLR parser.
* Subsequent commits hardened the dep classification (`--ignore` regexes,
  `newfstatat`/`read`/`unlinkat` handling, ccache support, `flock`ed
  `RepDep.d` for `-j` builds, `--shell` to stop hardcoding bash, `--task` to
  stop relying on argv position).

The `repshell` remote branch still exists at `5424db9` as a frozen snapshot of
the simpler pre-merge experiment; development has since moved to the
`repdry` branch (Phase 5).

## Phase 5 — the `repdry` branch (2026)

RepDry reused the tracer core for a different problem: instead of learning
build dependencies, run an arbitrary command in a bubblewrap+overlayfs
sandbox and report what it would have changed. With RepDry working, the
last reason to keep ANTLR disappeared — it was only there so RepShell could
re-parse `RepDep.d` — so `repdry` deleted:

* `src/cpp/RepShell.cpp` and the whole `example/` harness,
* `src/antlr/` (`RepShell.g4` and the legacy `RepMake.g4`) and the
  `libs/antlr4-cpp-runtime` submodule,
* `utils.*`, `rules.hpp`, `sys_map.hpp` (RepShell-only helpers),
* the `docs/usage.md`/`docs/internals.md` RepShell walkthroughs.

What survived: `src/cpp/tracer.cpp`/`include/tracer.hpp` (the
seccomp+ptrace core, now refactored into a shared `runTracedExec`) and
`include/logging.hpp`. The repository is RepDry-only.
