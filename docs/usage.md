# Using RepShell

RepShell wraps a shell command, traces every file it touches, and records the
learned dependencies in `RepDep.d`. Its primary intended use is as the `SHELL`
in a GNU Makefile, but it can wrap any command.

## Command line

```
RepShell [--task NAME] [--shell PATH] [--ignore REGEX]... -- SHELL_ARGS...
```

| Flag | Meaning |
|------|---------|
| `--task NAME` | Name of the rule the learned deps belong to. If omitted, the name is inferred from the **first file the child opens for writing** (i.e. the output being produced). |
| `--shell PATH` | Program to `exec` in place of RepShell. Defaults to `bash`. |
| `--ignore REGEX` | Exclude matching paths from the learned graph. Repeatable. The regex must match the whole path (`std::regex_match`). Useful for compiler-runtime files like `libgcc_s.so.1`. |
| `--` | Required separator. Everything after it becomes the argv of the traced program, with `argv[0]` replaced by the `--shell` value. |

Example — trace a compile by hand:

```sh
out/RepShell --task lib.o --ignore 'libgcc.*' -- \
    -c 'ccache gcc -c lib.c -o lib.o -I inc1 -I inc2'
```

(That is exactly the invocation the VS Code debugger config in
`.vscode/launch.json` runs.)

The exit status of the traced command propagates to RepShell's exit code, so
make sees normal success/failure semantics.

## Wiring it into a Makefile

`example/Makefile` shows the full pattern:

```make
OLD_SHELL := $(SHELL)
SHELL = ../out/RepShell \
        --ignore libgcc_s.so.1 \
        --shell $(OLD_SHELL) \
        --task $@ --

MAKEFLAGS += -k              # keep going so partial progress is made
MAKEFLAGS += --jobs=12       # tracing is per-recipe, so parallelism is fine

-include RepDep.d            # pull in everything learned so far

all:
	./example

build: example

example:
	ccache gcc example.o lib.o -o example

example.o:
	ccache gcc -c example.c -o example.o

lib.o:
	ccache gcc -c lib.c -o lib.o -I inc1 -I inc2
```

How it works:

1. Make expands `$(SHELL)` per recipe, so `--task $@` names the rule after the
   current target and `--shell $(OLD_SHELL)` runs the recipe under the
   original shell (`/bin/sh` by default).
2. Make invokes the new SHELL as `RepShell --ignore ... --task example.o -- -c 'ccache gcc ...'`.
3. RepShell traces the recipe, then appends/merges `example.o: example.c ...`
   into `RepDep.d` (with an `flock`, so parallel `-j` builds are safe).
4. On the next make run, `-include RepDep.d` turns those learned edges into
   real make prerequisites.

Note that **none of the recipes declare prerequisites**. `example` doesn't know
it needs `example.o` and `lib.o` until the first build proves it by observing
the linker open them.

## The iterative bootstrap problem

Because the graph doesn't exist before the first run, a cold build can fail
partway through — e.g. the link rule runs before the object files exist.
`MAKEFLAGS += -k` lets make schedule as much as it can anyway, and each run
learns one more "layer" of the graph. `example/full_test.sh` automates this:

```sh
while ! make; do :; done   # keep building until the fixpoint
make                        # one more run: should be a clean no-op
```

After the first successful build, `RepDep.d` contains enough edges that
subsequent incremental builds are correctly ordered and minimal.

## What lands in RepDep.d

A generated file for the example project looks like:

```make
.PHONY: REP_SPACE
all: ./example
example: example.o lib.o
example.o: example.c
lib.o: lib.c

./example:
example.c:
example.o:
lib.c:
lib.o:
```

* `all: ./example` — the `all` recipe ran `./example`, so the `execve` was
  recorded as a real dep.
* `lib.o: lib.c` — the headers `lib.c` includes don't appear here because this
  run was a ccache hit (cache probes are sus deps, dropped on success). On a
  real compile, `gcc` `open`+`read`s `inc1/header1.h` and `inc2/header2.h`,
  making them real deps.

* Each rule records `target: real_dep ... [ REP_SPACE sus_dep ... ]`.
* `REP_SPACE` is a phony separator: everything after it is a "sus" dep — a file
  the recipe opened or statted but never provably read.
* The trailing `name:` stub rules stop make from erroring with "no rule to make
  target" for dep-only files (the same trick as `gcc -MP`).
* Sus deps are only written back into `RepDep.d` when the traced recipe
  **fails**; on success the file is rewritten with real deps only. See
  [internals.md](internals.md) for why.

## Filtering noise

Every traced program reads some files you don't want in the graph (libc, locale
data, compiler internals). Three built-in filters apply before deps are
recorded:

* **Absolute paths are dropped** — only relative paths under the build
  directory are tracked. (`/` prefix filter in `traceBash`.)
* **`.` and `/tmp` are dropped.**
* **`--ignore` regexes** drop anything else — system headers aren't caught by
  the absolute-path filter if a tool copies them locally, ccache's own files,
  `libgcc_s.so.1`, etc.
* **Directories are dropped** — `stat()`ing the path and finding `S_ISDIR`
  skips it.

## Limitations / sharp edges

* Linux-only, x86-64 syscall/register conventions (`orig_rax`, `AT_FDCWD`
  relative-path handling).
* Only `openat`-with-`AT_FDCWD` paths are followed; file accesses via other
  dirfds are skipped.
* Recipes run under seccomp+ptrace, so they're slower than a bare shell.
* `RepDep.d` is a shared mutable file — keep it out of version control (it's
  in `.gitignore` for `example/`).
