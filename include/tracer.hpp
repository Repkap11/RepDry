#pragma once

#include <stddef.h>
#include <sys/types.h>
#include <map>
#include <regex>
#include <string>
#include <vector>

namespace tracer {

// Installs a seccomp filter that stops (SECCOMP_RET_TRACE) on the given
// syscalls, calls PTRACE_TRACEME, stops itself, then execvp's argv.
// Syscalls in fd_arg_syscalls only stop when their 5th argument (args[4],
// an fd for mmap-style calls) is not -1 — anonymous calls are skipped in
// BPF, keeping high-volume syscalls cheap. arg1_filters maps a syscall to
// a set of args[1] values worth tracing (e.g. ioctl request codes) — all
// other invocations of that syscall are allowed.
// Only call in a freshly-forked child. Returns only on error.
void runTracedExec( char *argv[], const std::vector<int> &trace_syscalls, const std::vector<int> &fd_arg_syscalls = std::vector<int>( ), const std::map<int, std::vector<unsigned int>> &arg1_filters = std::map<int, std::vector<unsigned int>>( ) );

// Reads a NUL-terminated string out of a tracee's address space.
void read_file( pid_t pid, long reg, char *file );

// Single-steps the tracee once and returns regs.rax (the syscall return value).
long waitForSyscallRet( pid_t current_pid );

bool matchsAnyIgnore( const std::string str, const std::vector<std::regex> &ignore );

} // namespace tracer
