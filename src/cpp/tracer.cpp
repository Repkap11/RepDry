#include "tracer.hpp"

#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include "logging.hpp"

// https://www.alfonsobeato.net/tag/seccomp/
// https://github.com/alfonsosanchezbeato/ptrace-redirect/blob/master/redir_filter.c
//  https://github.com/skeeto/ptrace-examples/blob/master/minimal_strace.c
// register order https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-and-user-space-f

namespace tracer {

void runTracedExec( char *argv[], const std::vector<int> &trace_syscalls, const std::vector<int> &fd_arg_syscalls, const std::map<int, std::vector<unsigned int>> &arg1_filters ) {
    /* Trace only the syscalls we care about, allow everything else */
    std::vector<sock_filter> filter;
    filter.push_back( BPF_STMT( BPF_LD + BPF_W + BPF_ABS, offsetof( struct seccomp_data, nr ) ) );
    for ( int syscall : trace_syscalls ) {
        filter.push_back( BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, ( unsigned int )syscall, 0, 1 ) );
        filter.push_back( BPF_STMT( BPF_RET + BPF_K, SECCOMP_RET_TRACE ) );
    }
    // arg4-of-fd filtered calls: trace only when args[4] != -1 (e.g. mmap —
    // anonymous maps would otherwise flood the tracer)
    static const unsigned int arg4lo = offsetof( struct seccomp_data, args ) + 4 * 8;
    static const unsigned int arg4hi = arg4lo + 4;
    for ( int syscall : fd_arg_syscalls ) {
        filter.push_back( BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, ( unsigned int )syscall, 0, 6 ) ); // not ours -> next block
        filter.push_back( BPF_STMT( BPF_LD + BPF_W + BPF_ABS, arg4lo ) );
        filter.push_back( BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, 0xffffffff, 0, 3 ) ); // lo != ff -> trace
        filter.push_back( BPF_STMT( BPF_LD + BPF_W + BPF_ABS, arg4hi ) );
        filter.push_back( BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, 0xffffffff, 0, 1 ) ); // hi != ff -> trace
        filter.push_back( BPF_STMT( BPF_RET + BPF_K, SECCOMP_RET_ALLOW ) );          // fd == -1 -> allow
        filter.push_back( BPF_STMT( BPF_RET + BPF_K, SECCOMP_RET_TRACE ) );
    }
    // arg1-set filters: trace only when args[1] is in the given set
    // (e.g. specific ioctl request codes out of a very hot syscall)
    static const unsigned int arg1lo = offsetof( struct seccomp_data, args ) + 8;
    for ( const auto &kv : arg1_filters ) {
        unsigned int n = ( unsigned int )kv.second.size( );
        filter.push_back( BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, ( unsigned int )kv.first, 0, ( __u8 )( 2 * n + 2 ) ) );
        filter.push_back( BPF_STMT( BPF_LD + BPF_W + BPF_ABS, arg1lo ) );
        for ( unsigned int req : kv.second ) {
            filter.push_back( BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, req, 0, 1 ) );
            filter.push_back( BPF_STMT( BPF_RET + BPF_K, SECCOMP_RET_TRACE ) );
        }
        filter.push_back( BPF_STMT( BPF_RET + BPF_K, SECCOMP_RET_ALLOW ) );
    }
    filter.push_back( BPF_STMT( BPF_RET + BPF_K, SECCOMP_RET_ALLOW ) );

    struct sock_fprog prog = {
        .len = ( unsigned short )filter.size( ),
        .filter = filter.data( ),
    };
    ptrace( PTRACE_TRACEME, 0, 0, 0 );
    /* To avoid the need for CAP_SYS_ADMIN */
    if ( prctl( PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0 ) < 0 ) {
        perror( "prctl(PR_SET_NO_NEW_PRIVS)" );
        return;
    }
    if ( prctl( PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog ) < 0 ) {
        perror( "when setting seccomp filter" );
        return;
    }
    kill( getpid( ), SIGSTOP );
    execvp( argv[ 0 ], argv );
    perror( "execvp" );
}

void read_file( pid_t pid, long reg, char *file ) {
    char *child_addr;
    unsigned long i;

    child_addr = ( char * )reg;

    do {
        long val;
        char *p;

        val = ptrace( PTRACE_PEEKTEXT, pid, child_addr, NULL );
        if ( val == -1 ) {
            pr_debug( "PTRACE_PEEKTEXT error: %s", strerror( errno ) );
            exit( 1 );
        }
        child_addr += sizeof( long );

        p = ( char * )&val;
        for ( i = 0; i < sizeof( long ); ++i, ++file ) {
            *file = *p++;
            if ( *file == '\0' )
                break;
        }
    } while ( i == sizeof( long ) );
}

long waitForSyscallRet( pid_t current_pid ) {
    int status;
    long syscall_ret = 42;
    {
        if ( ptrace( PTRACE_SINGLESTEP, current_pid, 0, 0 ) < 0 ) {
            pr_debug( "ptrace" );
            exit( 1 );
            return 1;
        }
        waitpid( current_pid, &status, 0 );
        struct user_regs_struct regs;
        if ( ptrace( PTRACE_GETREGS, current_pid, 0, &regs ) == -1 ) {
            if ( errno == ESRCH ) {
                pr_debug( "Child is exiting:%d: %s", errno, strerror( errno ) );
            } else {
                pr_debug( "Get Regs Error %d: %s", errno, strerror( errno ) );
            }
        }
        syscall_ret = regs.rax;
    }
    return syscall_ret;
}

bool matchsAnyIgnore( const std::string str, const std::vector<std::regex> &ignore ) {
    std::smatch match;
    for ( auto &regex : ignore ) {
        if ( std::regex_match( str, match, regex ) ) {
            return true;
        }
    }
    return false;
}

} // namespace tracer
