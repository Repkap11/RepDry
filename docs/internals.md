# RepShell Internals

Everything lives in `src/cpp/RepShell.cpp` (~640 lines). This document walks
through the execution flow, the tracing machinery, how syscalls map to
dependency decisions, and how `RepDep.d` is produced.

## High-level flow (`main`)

```
parse args (--task/--shell/--ignore/--)
fork()
 ├─ child:  runBash()   → install seccomp filter, PTRACE_TRACEME, SIGSTOP, execvp(shell)
 └─ parent: waitpid()   → PTRACE_SETOPTIONS(TRACESECCOMP|TRACECLONE|TRACEFORK|TRACEVFORK)
            traceBash() → ptrace event loop; fills a Rule{real_deps, sus_deps}
            flock(RepDep.d) → parse existing rules → merge → rewrite file
```

The traced child's exit status becomes RepShell's exit status, so make sees the
real result of each recipe.

## The child: `runBash()`

Before `execvp`, the child:

1. Calls `ptrace(PTRACE_TRACEME)` so the parent traces it.
2. `prctl(PR_SET_NO_NEW_PRIVS)` — required so an unprivileged process may
   install a seccomp filter.
3. `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)` — installs a cBPF
   program that returns `SECCOMP_RET_TRACE` for exactly the syscalls we care
   about and `SECCOMP_RET_ALLOW` for everything else.
4. `kill(getpid(), SIGSTOP)` — hands control back to the parent so it can set
   ptrace options before the tracee runs anything interesting.
5. `execvp(argv[0], argv)` — becomes the requested shell.

This is the classic "poor man's strace" pattern — seccomp decides *which*
syscalls stop, ptrace observes them — and is dramatically cheaper than
tracing every syscall (references are in comments above `read_file`).

### Syscalls trapped by the filter

`SYS_read`, `SYS_openat`, `SYS_access`, `SYS_execve`, `SYS_newfstatat`,
`SYS_unlinkat`. Everything else runs untraced.

## The parent: `traceBash()`

A `waitpid(0, ...)` loop over the whole traced process tree (thanks to
`PTRACE_O_TRACECLONE|TRACEFORK|TRACEVFORK`). For each stop:

* `WIFEXITED` on the original child pid → return its exit code.
* Stops that aren't `SIGTRAP | PTRACE_EVENT_SECCOMP<<8` → `PTRACE_CONT` and
  keep waiting.
* Seccomp stops → `PTRACE_GETREGS`, dispatch on `regs.orig_rax`.

### Per-syscall classification

Each syscall sets a few boolean "verbs" which are applied at the bottom of the
loop (`addFileAsDep` → real dep, `trackFile` → sus dep + fd bookkeeping,
`mayBeTarget` → candidate rule name, `removeFileAsDep` → currently unused):

| Syscall | Path source | Action |
|---------|-------------|--------|
| `execve` | `rdi` | real dep (executed files are definitely inputs) |
| `access` | `rdi` | real dep (existence/permission probes count — e.g. shell PATH lookup decides which binary runs) |
| `read` | fd in `rdi`, resolved through `fd_path_map` | real dep — *only* if the fd was previously opened for read (see below) |
| `newfstatat` | `rsi` (only when `rdi == AT_FDCWD`) | sus dep + register path |
| `openat` | `rsi` (only when `rdi == AT_FDCWD`) | `O_RDONLY` → sus dep + record fd→path; `O_WRONLY`/`O_RDWR` → maybe-target (`O_RDWR` also tracked) |
| `unlinkat` | `rsi` | path is read, but no verb is currently set (vestigial) |

### Why two dep classes

A file **opened read-only or statted** is only a *suspect* dependency — tools
routinely probe paths that don't affect output (compiler include search paths,
ccache lookups, shell hash tables). A file that was then actually **`read`**,
`access`ed, or `exec`d is a *real* dependency. `fd_path_map` (fd → path, keyed
by the `openat` return value obtained via `waitForSyscallRet` →
`PTRACE_SINGLESTEP` → `regs.rax`) is what lets `read` attribute data back to
the file that was opened.

### Path filtering

Before any verb is applied, `orig_file` is dropped if it:

* starts with `/` (absolute — outside the build dir),
* equals `.` or `/tmp`,
* matches any `--ignore` regex (`std::regex_match`),
* is a directory (`stat()` + `S_ISDIR`).

### Rule naming

`--task NAME` wins. Otherwise the first `O_WRONLY`/`O_RDWR` open becomes the
rule name — the heuristic "the thing being built is the first file the recipe
writes."

### Reading the child's memory

`read_file(pid, reg, buf)` copies the NUL-terminated path out of the tracee's
address space one machine word at a time with `PTRACE_PEEKTEXT`.

## Writing RepDep.d

After the child exits, `main`:

1. `open("RepDep.d", O_RDWR|O_CREAT)` + `flock(LOCK_EX)` — safe under
   parallel make.
2. `parseExistingRules()` — re-reads the file through the **ANTLR4-generated
   parser** (`RepShell.g4`) into `std::set<Rule>`. Ignored regexes filter both
   rule names and dep names here too, so `--ignore` also *removes* previously
   recorded entries.
3. Merges the freshly traced `new_rule` into the set (union of `real_deps` and
   `sus_deps`), after deleting self-dependencies.
4. Rewrites the whole file:
   * `.PHONY: REP_SPACE` header.
   * Per rule: `name: real_dep ...` — and **only if the traced task failed**
     (`childRet != 0`), ` REP_SPACE sus_dep ...` appended.
   * Finally a `dep:` stub rule for every dep seen, so make never reports
     "no rule to make target 'dep'".
   * Rules with an empty name (no `--task`, nothing written) or zero deps are
     skipped.

### The semantics of sus deps and REP_SPACE

`REP_SPACE` is a phony target used purely as a visual separator between real
and sus deps in the dep list — but because it's just a normal prerequisite
name, sus deps after it are *still ordinary make prerequisites*. Two
consequences:

* Since `REP_SPACE` is `.PHONY` (always out of date), **any rule that has sus
  deps is always rebuilt** by make. That is intentional-ish: sus deps only
  appear when a recipe failed, and the target will be re-run anyway; once it
  succeeds RepShell rewrites the rule without them.
* Sus deps exist chiefly for the *failed task* case: when e.g. `gcc` fails on a
  missing header, all the include-path probes it made (`newfstatat` on
  `inc1/foo.h`, `inc2/foo.h`, ...) are recorded so that **creating** that file
  later retriggers the rule — the same job `gcc -MG`/`-MP` does for
  not-yet-existing headers.

There's an explicit TODO in the source (`traceBash`) refining this: on success,
only sus files that *exist* should be kept; on failure, everything becomes sus.
Current behavior is cruder, per above.

### The grammar quirk

`readEntireFile` prepends a `\r` before feeding the buffer to ANTLR — the
grammar's `IDENT`/`rule_name` tokens are anchored on a preceding `NEW_LINE`,
so a synthetic leading newline keeps the first rule parseable without shifting
reported line numbers.

## `src/antlr/RepShell.g4`

Parses `RepDep.d` back in. A `rep_shell_rule` is:

```
NEW_LINE rule_name ':' real_dependency_list? ('REP_SPACE' sus_dependency_list?)? IDENT? tasks? NEW_LINE?
```

i.e. exactly Make's `target: deps` syntax plus the `REP_SPACE` split, and it
tolerates indented recipe lines (`IDENT task`) — they parse but are ignored;
only dep lists are read.

`src/antlr/RepMake.g4` is the older grammar from the standalone-build-tool era
(no sus deps). It's still in the tree but **isn't compiled** — the Makefile
only generates a parser for `$(TARGET)`, which is `RepShell`.

## Build system (top-level `Makefile`)

* `make` → `out/RepShell`.
* ANTLR: `out/antlr_src` is generated from `src/antlr/$(TARGET).g4` by `antlr4
  -Dlanguage=Cpp`; generated sources compile under `CFLAGS_ANTLR`
  (`-O3 -Wno-attributes`, the warning suppression works around an ANTLR codegen
  bug).
* Runtime: `libs/antlr4-cpp-runtime` (a git submodule) is built once with
  `cmake` into `out/antlr_runtime` and linked as a static lib.
* Project sources compile with `-std=c++11 -Wall -Werror -Wextra -g` and
  `ccache`, each emitting `-MMD` depfiles that are `-include`d.
* `make dev` also builds the example; `make valgrind` runs it under valgrind;
  `make clean-example` removes example artifacts and `RepDep.d`.
* Prerequisites: `antlr4`, `cmake`, `g++`, `ccache` (`make install` apt-gets
  the first two).
