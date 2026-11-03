# RepDry overview

This repository began as **RepMake**, an experiment in automatic dependency
discovery for build systems: run each build step under a ptrace+seccomp
tracer, record what it actually reads and writes, and feed the result back
into the build as a generated `RepDep.d` file. That lineage produced the
tracer core that still lives here.

## Current state: RepDry

The project is now a single program, **RepDry** (`out/RepDry`, source in
`src/cpp/RepDry.cpp`) — a dry-run sandbox for arbitrary commands:

```sh
repdry -- curl -fsSL https://example.com/install.sh | sh
```

* The command runs inside **bubblewrap** with the host filesystem bound
  read-only and **overlayfs** uppers in a scratch dir, so every write lands
  in the sandbox instead of the real fs.
* The inherited **ptrace+seccomp tracer** follows the process tree and
  attributes file accesses to processes.
* Afterwards repdry prints a report — what the command created, modified,
  deleted, read, probed, and executed — and asks whether to apply the diff
  to the real filesystem (default: discard).

See [repdry.md](repdry.md) for usage, the overlay planning rules, report
format, and limitations.

## History in one paragraph

The repository began life as a standalone build tool also called RepMake: it
parsed a `RepMake` build file with ANTLR4, topologically scheduled rules with
timestamp-based rebuild detection, ran each rule's tasks under ptrace, and
wrote learned deps back to `RepDep.d`. That design pivoted — on the
`repshell` branch — into a small "shell wrapper for real make" (`SHELL =
../out/RepShell --task $@ --`), which instrumented every recipe of an
ordinary Makefile instead of replacing make. Both are gone now: RepShell and
all the ANTLR machinery it still needed to re-parse `RepDep.d` were deleted
on the `repdry` branch, leaving only the shared tracer and RepDry. See
[history.md](history.md) for the full story.

## Repository layout

```
Makefile               # Builds out/RepDry
src/cpp/RepDry.cpp     # The whole program: arg parsing, overlay planning,
                       # bwrap argv, ptrace event loop, diff walk, report
src/cpp/tracer.cpp     # Shared tracer core: seccomp cBPF + PTRACE_TRACEME +
                       # exec, tracee-memory path reads, syscall-ret waits
include/tracer.hpp
include/logging.hpp    # pr_debug macros
docs/                  # This documentation
out/                   # Build output (git-ignored)
```

## Key terms

| Term | Meaning |
|------|---------|
| **RepDry** | The binary. A dry-run sandbox that reports a command's fs effects. |
| **scratch dir** | Throwaway directory under `/tmp` holding the overlay uppers. |
| **upper / lower** | overlayfs layers: lower = real fs (read-only), upper = scratch (receives writes). |
| **whiteout** | Upper-layer marker file meaning "this lower file was deleted". |
| **the report** | Merged view of the upper-layer diff (authoritative) and the ptrace trace (per-process attribution). |
