# RepMake / RepShell Overview

RepMake is an experiment in **automatic dependency discovery for build systems**.
Instead of declaring dependencies by hand (or generating them with compiler
flags like `gcc -MMD`), RepMake learns what each build step actually reads and
writes by *tracing its execution*, then emits the result as a Makefile-compatible
dependency file (`RepDep.d`) that an ordinary GNU Makefile can `-include`.

## The idea

Build systems need an accurate dependency graph to do incremental and parallel
builds correctly. Maintaining that graph by hand is tedious and error-prone:

* C/C++ compilers can emit `.d` files, but only for source-level `#include`
  edges, and only for tools that support it.
* Generated code, scripts, asset pipelines, and tools that read configuration
  or search-path files all create dependencies that compilers never report.
* Missing dependencies cause stale builds; extra dependencies cause spurious
  rebuilds.

RepMake's answer: **run the build under a tracer and record the truth**. Every
file a recipe opens, reads, executes, or stats is a candidate dependency; every
file it writes is a candidate target. Do this for each recipe in a Makefile and
the union of observations *is* the dependency graph — no declaration needed.

## Current state: RepShell

The project is currently a single program, **RepShell**
(`out/RepShell`, source in `src/cpp/RepShell.cpp`):

* RepShell is used as the `SHELL` in a GNU Makefile, so make runs every recipe
  line through it.
* For each invocation, RepShell forks, installs a seccomp filter and `ptrace`s
  the child shell (and all of its descendants) to observe file-access syscalls.
* When the recipe finishes, RepShell merges what it learned into `RepDep.d`, a
  Make-compatible dependency file. The Makefile `-include`s it, so each run of
  make refines the graph discovered by previous runs.

Recipes can therefore be written **with no prerequisites at all** — the first
build discovers them. Failed recipes still record what they probed for, so
creating a previously-missing input file retriggers the target. See
[usage.md](usage.md) for how to wire it into a Makefile and
[internals.md](internals.md) for how the tracer works.

## History in one paragraph

The repository began life as a standalone build tool also called RepMake: it
parsed a `RepMake` build file with ANTLR4, topologically scheduled rules with
timestamp-based rebuild detection, ran each rule's tasks under ptrace, and
wrote learned deps back to `RepDep.d`. That design was later pivoted — on the
`repshell` branch — into the much smaller "shell wrapper for real make" design
that exists on `master` today. The old build-tool code was deleted in commit
`a374828` ("Delete repmake files, all in on repshell"). See
[history.md](history.md) for the full story.

## Repository layout

```
Makefile               # Builds out/RepShell (g++ + ANTLR4-generated parser)
src/cpp/RepShell.cpp   # The whole program: arg parsing, tracing, RepDep.d I/O
src/cpp/utils.cpp      # Small string/flag helpers
src/antlr/RepShell.g4  # ANTLR grammar for parsing RepDep.d back in
src/antlr/RepMake.g4   # Grammar from the old build tool (kept for reference)
include/rules.hpp      # Rule { name, real_deps, sus_deps }
include/sys_map.hpp    # syscall number -> name table for debug logging
include/logging.hpp    # pr_debug macros
include/utils.hpp
libs/antlr4-cpp-runtime/  # ANTLR4 C++ runtime (git submodule, cmake-built)
example/               # Toy C project + Makefile wired to RepShell
out/                   # Build output (git-ignored)
docs/                  # This documentation
```

## Key terms

| Term          | Meaning |
|---------------|---------|
| **RepShell**  | The binary. A ptrace-based shell wrapper that learns deps. |
| **RepDep.d**  | The generated dependency file, written in Makefile syntax. |
| **real deps** | Files a recipe definitely used (read, accessed, or exec'd). |
| **sus deps**  | "Suspect" deps: files a recipe only *opened* or *statted*. Recorded after a `REP_SPACE` marker in `RepDep.d`. |
| **REP_SPACE** | A phony separator target emitted into `RepDep.d` dividing real deps from sus deps. |
| **`--ignore`** | Regex(es) filtering paths out of the learned graph. |
