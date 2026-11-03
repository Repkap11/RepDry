# Project history

The repository went through two distinct architectures. Understanding both
explains some leftovers in the tree (two grammar files, `include/rules.hpp`'s
simple shape, `src/antlr/RepMake.g4`).

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
the simpler pre-merge experiment; `master` is the live code.

## What survived from each phase

| From Phase 1 (RepMake) | From Phase 3 (RepShell) |
|---|---|
| ANTLR4 + the `libs/antlr4-cpp-runtime` submodule | The `SHELL = RepShell ...` trick |
| `RepDep.d` as the learned-dep store | sus deps / `REP_SPACE` |
| The Makefile-style grammar (evolved into `RepShell.g4`) | `--task`/`--ignore`/`--shell` CLI |
| `trace_tasks.cpp`'s seccomp+ptrace core (now inlined in `RepShell.cpp`) | |

Things deleted along the way: the rule scheduler and timestamp logic
(`rules.cpp`, the old `runTasksInOrder`), the `RepMake` build file format, and
`include/trace_tasks.hpp`.
