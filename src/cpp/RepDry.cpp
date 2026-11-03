#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/unistd.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include <algorithm>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "logging.hpp"
#include "tracer.hpp"

#ifndef IORING_REGISTER_FILES
#define IORING_REGISTER_FILES 2
#endif

// ---------------------------------------------------------------------------
// What we collect
// ---------------------------------------------------------------------------

struct Proc {
    std::string cwd = "/";
    std::string exe = "?";
    // true while the process is bubblewrap infrastructure: the traced root
    // (bwrap itself) and its children until they exec the payload. Clones
    // inherit it; a successful execve in any non-root pid clears it.
    bool infra = false;
    std::map<long, std::string> fd_path;
};

struct PathInfo {
    std::set<std::string> readers;
    std::set<std::string> writers;
    std::set<std::string> probers; // stat/access/never-read opens
    std::set<std::string> deleters;
    bool probed_missing = false;
};

struct Report {
    std::map<std::string, PathInfo> paths;
    std::map<std::string, std::set<std::string>> execs;    // exe path -> pids
    std::map<std::string, std::set<std::string>> connects; // dest -> procs
    std::set<std::string> iouring; // procs that created/used an io_uring ring
    std::map<std::string, std::set<std::string>> iouring_files; // files registered into a ring
    int child_exit = 0;
};

static std::map<pid_t, Proc> procs;

static std::string basenameOf( const std::string &p ) {
    size_t pos = p.find_last_of( '/' );
    return pos == std::string::npos ? p : p.substr( pos + 1 );
}

static std::string label( pid_t pid ) {
    return basenameOf( procs[ pid ].exe ) + "(" + std::to_string( pid ) + ")";
}

// Lexically normalize an absolute path: collapse //, /./, /../
static std::string normalize( const std::string &in ) {
    std::vector<std::string> parts;
    std::stringstream ss( in );
    std::string part;
    while ( std::getline( ss, part, '/' ) ) {
        if ( part.empty( ) || part == "." )
            continue;
        if ( part == ".." ) {
            if ( !parts.empty( ) )
                parts.pop_back( );
        } else {
            parts.push_back( part );
        }
    }
    std::string out = "/";
    for ( size_t i = 0; i < parts.size( ); i++ ) {
        out += parts[ i ];
        if ( i + 1 < parts.size( ) )
            out += "/";
    }
    return out;
}

// Resolve an fd to its path. The per-proc fd_path table is a cache fed by
// traced open/dup calls; on a miss (inherited fds, F_DUPFD variants, fds
// passed over sockets, ...) ask the kernel via /proc/<pid>/fd — the
// authoritative answer. Non-path targets (pipes, sockets, anon inodes)
// resolve to "".
static std::string fdPath( pid_t pid, long fd ) {
    // fd args can arrive sign- or zero-extended; compare as int
    if ( ( int )fd < 0 )
        return "";
    Proc &proc = procs[ pid ];
    auto it = proc.fd_path.find( fd );
    if ( it != proc.fd_path.end( ) )
        return it->second;
    char link[ PATH_MAX + 1 ];
    std::string p = "/proc/" + std::to_string( pid ) + "/fd/" + std::to_string( fd );
    std::string res;
    ssize_t n = readlink( p.c_str( ), link, sizeof link - 1 );
    if ( n > 0 ) {
        link[ n ] = 0;
        if ( link[ 0 ] == '/' )
            res = link;
    }
    proc.fd_path[ fd ] = res; // cache the answer, even if it's ""
    return res;
}

static std::string resolvePath( pid_t pid, long dirfd, const std::string &raw ) {
    if ( raw.empty( ) )
        return "";
    if ( raw[ 0 ] == '/' )
        return normalize( raw );
    std::string base;
    if ( ( int )dirfd == AT_FDCWD ) {
        base = procs[ pid ].cwd;
    } else {
        base = fdPath( pid, dirfd );
        if ( base.empty( ) )
            return "";
    }
    return normalize( base + "/" + raw );
}

static void readPathArg( pid_t pid, long reg, std::string &out ) {
    out.clear( );
    if ( !reg )
        return; // NULL path arg (futimens, execveat AT_EMPTY_PATH)
    char buf[ PATH_MAX ];
    tracer::read_file( pid, reg, buf );
    buf[ PATH_MAX - 1 ] = '\0';
    out = buf;
}

// ---------------------------------------------------------------------------
// Syscall set we trace
// ---------------------------------------------------------------------------

static const std::vector<int> trace_syscalls = {
    SYS_open,  SYS_openat,  SYS_openat2, SYS_access,   SYS_faccessat, SYS_faccessat2, SYS_stat,   SYS_lstat,    SYS_newfstatat, SYS_statx,  SYS_execve,    SYS_execveat, SYS_unlink,  SYS_unlinkat, SYS_rmdir,
    SYS_mkdir, SYS_mkdirat, SYS_rename,  SYS_renameat, SYS_renameat2, SYS_link,       SYS_linkat, SYS_symlink,  SYS_symlinkat,  SYS_read,   SYS_readv,     SYS_pread64,  SYS_write,   SYS_writev,   SYS_pwrite64,
    SYS_chdir, SYS_fchdir,  SYS_connect, SYS_chmod,    SYS_fchmodat,  SYS_chown,      SYS_lchown, SYS_fchownat, SYS_utime,      SYS_utimes, SYS_utimensat, SYS_mknod,    SYS_mknodat, SYS_truncate, SYS_ftruncate,
    // fd-table maintenance + copy paths that bypass read/write
    SYS_close, SYS_close_range, SYS_dup, SYS_dup2,    SYS_dup3,      SYS_fcntl,     SYS_preadv,    SYS_pwritev,
    SYS_copy_file_range, SYS_splice, SYS_sendfile,
    // metadata writes + link probes
    SYS_fchmod, SYS_fchown, SYS_fallocate,
    SYS_setxattr, SYS_lsetxattr, SYS_removexattr, SYS_lremovexattr,
    SYS_fsetxattr, SYS_fremovexattr, SYS_readlink, SYS_readlinkat,
    // remaining data/probe paths
    SYS_getdents, SYS_getdents64, SYS_fstat, SYS_statfs, SYS_fstatfs,
    SYS_futimesat, SYS_creat, SYS_vmsplice, SYS_finit_module,
    SYS_getxattr, SYS_lgetxattr, SYS_fgetxattr, SYS_listxattr, SYS_llistxattr, SYS_flistxattr,
    // namespace ops — reported as probes so they're at least visible
    SYS_mount, SYS_umount2, SYS_pivot_root, SYS_chroot,
#ifdef SYS_io_uring_setup
    // can't see inside rings, but their creation/use is visible
    SYS_io_uring_setup, SYS_io_uring_enter, SYS_io_uring_register,
#endif
#ifdef SYS_preadv2
    SYS_preadv2, SYS_pwritev2,
#endif
#ifdef SYS_fchmodat2
    SYS_fchmodat2,
#endif
#ifdef SYS_setxattrat
    SYS_setxattrat, SYS_removexattrat, SYS_getxattrat, SYS_listxattrat, SYS_file_getattr, SYS_file_setattr,
#endif
};

// Traced only when arg4 (the fd) is a real fd — anonymous maps are
// filtered out in BPF, since programs mmap() constantly.
static const std::vector<int> fd_arg_syscalls = { SYS_mmap };

// ioctl is far too hot to trace wholesale — only these request codes are
// interesting: reflink copies (cp --reflink) and inode-flag changes.
static const std::map<int, std::vector<unsigned int>> arg1_filters = {
    { SYS_ioctl, { FICLONE, FICLONERANGE, FS_IOC_SETFLAGS, FS_IOC_GETFLAGS } },
};

// ---------------------------------------------------------------------------
// The ptrace loop
// ---------------------------------------------------------------------------

static int traceRun( pid_t child, Report &rep, const std::vector<std::regex> &ignore ) {
    int status = 0;
    pid_t last = child;
    int inject = 0;
    while ( 1 ) {
        if ( last > 0 )
            ptrace( PTRACE_CONT, last, 0, inject );
        inject = 0;
        pid_t pid = waitpid( -1, &status, __WALL );
        if ( pid < 0 ) {
            if ( errno == ECHILD )
                return rep.child_exit;
            continue;
        }
        last = pid;

        if ( WIFEXITED( status ) ) {
            int child_status = WEXITSTATUS( status );
            procs.erase( pid );
            if ( pid == child ) {
                rep.child_exit = child_status;
                return child_status;
            }
            continue;
        }
        if ( WIFSIGNALED( status ) ) {
            procs.erase( pid );
            if ( pid == child ) {
                rep.child_exit = 128 + WTERMSIG( status );
                return rep.child_exit;
            }
            continue;
        }
        if ( !WIFSTOPPED( status ) ) {
            continue;
        }

        int event = ( status >> 16 ) & 0xffff;
        if ( event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ) {
            unsigned long new_pid = 0;
            ptrace( PTRACE_GETEVENTMSG, pid, 0, &new_pid );
            // Child inherits cwd, exe and fd table.
            procs[ ( pid_t )new_pid ] = procs[ pid ];
            continue;
        }

        int sig = WSTOPSIG( status );
        bool isSECTrap = status >> 8 == ( SIGTRAP | ( PTRACE_EVENT_SECCOMP << 8 ) );
        if ( !isSECTrap ) {
            // Reinject real signals, swallow SIGTRAP/event stops.
            inject = ( event == 0 && sig != SIGTRAP ) ? sig : 0;
            continue;
        }

        struct user_regs_struct regs;
        if ( ptrace( PTRACE_GETREGS, pid, 0, &regs ) == -1 ) {
            continue;
        }
        long syscall = regs.orig_rax;
        Proc &proc = procs[ pid ];
        std::string who = label( pid );
        // bwrap's own setup syscalls are noise — only processes that have
        // exec'd the payload (non-root after execve) count as real activity
        const bool isInfra = proc.infra;

        std::string path, path2;
        long dirfd = AT_FDCWD, dirfd2 = AT_FDCWD;
        long flags = 0;
        long fdarg = -1, fdarg2 = -1, extra = 0;
        bool wantRet = false;

        enum Act { NONE, PROBE, PROBEFD, READF, WRITEF, DEL, MKD, EXECF, CHDIRF, CONN, TRUNC, COPYRW, CLOSEF, DUPF, MMAPF, CLOSERANGE, IOURING } act = NONE;

        switch ( syscall ) {
            case SYS_execve:
            case SYS_execveat:
                dirfd = ( syscall == SYS_execveat ) ? regs.rdi : AT_FDCWD;
                readPathArg( pid, ( syscall == SYS_execveat ) ? regs.rsi : regs.rdi, path );
                act = EXECF;
                wantRet = true; // failed exec attempts (PATH scans) are noise
                break;
            case SYS_open:
                readPathArg( pid, regs.rdi, path );
                flags = regs.rsi;
                act = NONE;
                wantRet = true;
                break;
            case SYS_openat:
            case SYS_openat2:
                dirfd = regs.rdi;
                readPathArg( pid, regs.rsi, path );
                if ( syscall == SYS_openat ) {
                    flags = regs.rdx;
                } else {
                    // struct open_how { flags, mode, resolve } at rdx
                    long how[ 3 ] = { 0 };
                    for ( int i = 0; i < 3; i++ )
                        how[ i ] = ptrace( PTRACE_PEEKTEXT, pid, ( char * )regs.rdx + i * sizeof( long ), NULL );
                    flags = how[ 0 ];
                }
                wantRet = true;
                break;
            case SYS_access:
                readPathArg( pid, regs.rdi, path );
                act = PROBE;
                break;
            case SYS_faccessat:
            case SYS_faccessat2:
                dirfd = regs.rdi;
                readPathArg( pid, regs.rsi, path );
                act = PROBE;
                break;
            case SYS_stat:
            case SYS_lstat:
                readPathArg( pid, regs.rdi, path );
                act = PROBE;
                wantRet = true;
                break;
            case SYS_newfstatat:
            case SYS_statx:
                dirfd = regs.rdi;
                readPathArg( pid, regs.rsi, path );
                act = PROBE;
                wantRet = true;
                break;
            case SYS_unlink:
                readPathArg( pid, regs.rdi, path );
                act = DEL;
                break;
            case SYS_unlinkat:
                dirfd = regs.rdi;
                readPathArg( pid, regs.rsi, path );
                act = DEL;
                break;
            case SYS_rmdir:
                readPathArg( pid, regs.rdi, path );
                act = DEL;
                break;
            case SYS_mkdir:
                readPathArg( pid, regs.rdi, path );
                act = MKD;
                break;
            case SYS_mkdirat:
                dirfd = regs.rdi;
                readPathArg( pid, regs.rsi, path );
                act = MKD;
                break;
            case SYS_mknod:
                readPathArg( pid, regs.rdi, path );
                act = WRITEF;
                break;
            case SYS_mknodat:
                dirfd = regs.rdi;
                readPathArg( pid, regs.rsi, path );
                act = WRITEF;
                break;
            case SYS_rename:
            case SYS_link:
                readPathArg( pid, regs.rdi, path );
                readPathArg( pid, regs.rsi, path2 );
                act = DEL;
                break;
            case SYS_symlink:
                readPathArg( pid, regs.rdi, path );  // target (not fs path)
                readPathArg( pid, regs.rsi, path2 ); // linkpath
                path.clear( );
                act = WRITEF;
                break;
            case SYS_renameat:
            case SYS_renameat2:
            case SYS_linkat:
                dirfd = regs.rdi;
                dirfd2 = regs.rdx;
                readPathArg( pid, regs.rsi, path );
                readPathArg( pid, regs.r10, path2 );
                act = ( syscall == SYS_linkat ) ? WRITEF : DEL;
                break;
            case SYS_symlinkat:
                dirfd2 = regs.rsi;
                readPathArg( pid, regs.rdx, path2 );
                act = WRITEF;
                break;
            case SYS_chdir:
                readPathArg( pid, regs.rdi, path );
                act = CHDIRF;
                break;
            case SYS_fchdir:
                fdarg = regs.rdi;
                act = CHDIRF;
                break;
            case SYS_read:
            case SYS_readv:
            case SYS_pread64:
            case SYS_preadv:
#ifdef SYS_preadv2
            case SYS_preadv2:
#endif
                fdarg = regs.rdi;
                act = READF;
                break;
            case SYS_write:
            case SYS_writev:
            case SYS_pwrite64:
            case SYS_pwritev:
#ifdef SYS_pwritev2
            case SYS_pwritev2:
#endif
                fdarg = regs.rdi;
                act = WRITEF;
                break;
            case SYS_copy_file_range:
            case SYS_splice:
                fdarg = regs.rdi;  // fd_in
                fdarg2 = regs.rdx; // fd_out
                act = COPYRW;
                break;
            case SYS_sendfile:
                fdarg = regs.rsi;  // fd_in (arg order differs)
                fdarg2 = regs.rdi; // fd_out
                act = COPYRW;
                break;
            case SYS_close:
                fdarg = regs.rdi;
                act = CLOSEF;
                break;
            case SYS_close_range:
                fdarg = regs.rdi;
                fdarg2 = regs.rsi;
                act = CLOSERANGE;
                break;
            case SYS_mmap:
                fdarg = regs.r8;   // fd
                flags = regs.r10;  // MAP_* flags
                extra = regs.rdx;  // prot
                act = MMAPF;
                break;
            case SYS_fchmod:
            case SYS_fchown:
            case SYS_fallocate:
            case SYS_fsetxattr:
            case SYS_fremovexattr:
                fdarg = regs.rdi;
                act = TRUNC;
                break;
            case SYS_getdents:
            case SYS_getdents64:
            case SYS_finit_module:
                fdarg = regs.rdi;
                act = READF;
                break;
            case SYS_vmsplice:
                fdarg = regs.rdi;
                act = WRITEF;
                break;
            case SYS_fstat:
            case SYS_fstatfs:
            case SYS_fgetxattr:
            case SYS_flistxattr:
                fdarg = regs.rdi;
                act = PROBEFD;
                break;
            case SYS_statfs:
            case SYS_getxattr:
            case SYS_lgetxattr:
            case SYS_listxattr:
            case SYS_llistxattr:
                readPathArg( pid, regs.rdi, path );
                act = PROBE;
                break;
            case SYS_creat:
                readPathArg( pid, regs.rdi, path );
                flags = O_WRONLY | O_CREAT | O_TRUNC;
                wantRet = true; // shared open() handling below
                break;
            case SYS_mount:
                readPathArg( pid, regs.rsi, path ); // mountpoint target
                act = PROBE;
                break;
            case SYS_umount2:
            case SYS_pivot_root:
            case SYS_chroot:
                readPathArg( pid, regs.rdi, path );
                act = PROBE;
                break;
            case SYS_ioctl:
                if ( regs.rsi == FICLONE ) {
                    fdarg = regs.rdx;  // src fd
                    fdarg2 = regs.rdi; // dest fd
                    act = COPYRW;
                } else if ( regs.rsi == FICLONERANGE ) {
                    // struct file_clone_range — src_fd is the first member
                    fdarg = ptrace( PTRACE_PEEKTEXT, pid, ( char * )regs.rdx, NULL );
                    fdarg2 = regs.rdi;
                    act = COPYRW;
                } else if ( regs.rsi == FS_IOC_SETFLAGS ) {
                    fdarg = regs.rdi;
                    act = TRUNC;
                } else { // FS_IOC_GETFLAGS
                    fdarg = regs.rdi;
                    act = PROBEFD;
                }
                break;
#ifdef SYS_setxattrat
            case SYS_getxattrat:
            case SYS_listxattrat:
            case SYS_file_getattr:
                dirfd = regs.rdi;
                readPathArg( pid, regs.rsi, path );
                act = PROBE;
                break;
            case SYS_setxattrat:
            case SYS_removexattrat:
            case SYS_file_setattr:
                dirfd = regs.rdi;
                readPathArg( pid, regs.rsi, path );
                act = WRITEF;
                break;
#endif
            case SYS_setxattr:
            case SYS_lsetxattr:
            case SYS_removexattr:
            case SYS_lremovexattr:
                readPathArg( pid, regs.rdi, path );
                act = WRITEF;
                break;
            case SYS_readlink:
                readPathArg( pid, regs.rdi, path );
                act = PROBE;
                break;
            case SYS_readlinkat:
                dirfd = regs.rdi;
                readPathArg( pid, regs.rsi, path );
                act = PROBE;
                break;
#ifdef SYS_fchmodat2
            case SYS_fchmodat2:
                dirfd = regs.rdi;
                readPathArg( pid, regs.rsi, path );
                act = WRITEF;
                break;
#endif
            case SYS_dup:
            case SYS_dup2:
            case SYS_dup3:
                fdarg = regs.rdi;
                fdarg2 = ( syscall == SYS_dup ) ? -1 : regs.rsi;
                act = DUPF;
                wantRet = true; // need the new fd
                break;
            case SYS_fcntl:
                if ( regs.rsi == F_DUPFD || regs.rsi == F_DUPFD_CLOEXEC ) {
                    fdarg = regs.rdi;
                    fdarg2 = -1;
                    act = DUPF;
                    wantRet = true;
                }
                break;
            case SYS_chmod:
            case SYS_chown:
            case SYS_lchown:
            case SYS_utime:
            case SYS_utimes:
                readPathArg( pid, regs.rdi, path );
                act = WRITEF;
                break;
            case SYS_fchmodat:
            case SYS_fchownat:
                dirfd = regs.rdi;
                readPathArg( pid, regs.rsi, path );
                act = WRITEF;
                break;
            case SYS_utimensat:
            case SYS_futimesat:
                if ( regs.rsi ) {
                    dirfd = regs.rdi;
                    readPathArg( pid, regs.rsi, path );
                    act = WRITEF;
                } else {
                    fdarg = regs.rdi; // NULL path: futimens, fd is the file
                    act = TRUNC;
                }
                break;
            case SYS_truncate:
                readPathArg( pid, regs.rdi, path );
                act = TRUNC;
                break;
            case SYS_ftruncate:
                fdarg = regs.rdi;
                act = TRUNC;
                break;
            case SYS_connect:
                act = CONN;
                break;
#ifdef SYS_io_uring_setup
            case SYS_io_uring_setup:
            case SYS_io_uring_enter:
                act = IOURING;
                wantRet = true; // only successful ops mean a live ring
                break;
            case SYS_io_uring_register:
                act = IOURING;
                extra = regs.rsi;  // opcode (IORING_REGISTER_*)
                fdarg2 = regs.rdx; // arg ptr — fd array for REGISTER_FILES
                flags = regs.r10;  // nr_args
                wantRet = true;
                break;
#endif
            default:
                continue;
        }

        // Resolve the primary path
        std::string rpath, rpath2;
        if ( !path.empty( ) )
            rpath = resolvePath( pid, dirfd, path );
        if ( !path2.empty( ) )
            rpath2 = resolvePath( pid, dirfd2, path2 );

        // Fetch syscall return value where we need it (fd, existence)
        long ret = 0;
        if ( wantRet ) {
            ret = tracer::waitForSyscallRet( pid );
        }

        switch ( act ) {
            case EXECF: {
                if ( ret < 0 )
                    break; // failed execve (PATH search)
                // execveat(fd, "", AT_EMPTY_PATH) — resolve via the fd
                if ( rpath.empty( ) )
                    rpath = fdPath( pid, dirfd );
                if ( !rpath.empty( ) ) {
                    proc.exe = rpath;
                    // bwrap only ever execs once (in the root pid); the first
                    // exec in any other pid is the payload boundary
                    if ( pid != child )
                        proc.infra = false;
                    if ( !proc.infra )
                        rep.execs[ rpath ].insert( std::to_string( pid ) );
                }
                break;
            }
            case PROBE:
                if ( !isInfra && !rpath.empty( ) ) {
                    rep.paths[ rpath ].probers.insert( who );
                    if ( wantRet && ret != 0 )
                        rep.paths[ rpath ].probed_missing = true;
                }
                break;
            case PROBEFD: {
                if ( isInfra )
                    break;
                std::string fp = fdPath( pid, fdarg );
                if ( !fp.empty( ) )
                    rep.paths[ fp ].probers.insert( who );
                break;
            }
            case READF: {
                if ( !isInfra ) {
                    std::string fp = fdPath( pid, fdarg );
                    if ( !fp.empty( ) )
                        rep.paths[ fp ].readers.insert( who );
                }
                break;
            }
            case COPYRW: {
                if ( isInfra )
                    break;
                std::string fin = fdPath( pid, fdarg );
                if ( !fin.empty( ) )
                    rep.paths[ fin ].readers.insert( who );
                std::string fout = fdPath( pid, fdarg2 );
                if ( !fout.empty( ) )
                    rep.paths[ fout ].writers.insert( who );
                break;
            }
            case CLOSEF:
                proc.fd_path.erase( fdarg );
                break;
            case DUPF: {
                if ( ret < 0 )
                    break;
                // target now aliases the source — resolve it if we can,
                // otherwise clear any stale mapping
                long nfd = ( fdarg2 >= 0 ) ? fdarg2 : ret;
                std::string fp = fdPath( pid, fdarg );
                if ( fp.empty( ) )
                    proc.fd_path.erase( nfd );
                else
                    proc.fd_path[ nfd ] = fp;
                break;
            }
            case CLOSERANGE:
                for ( auto it = proc.fd_path.begin( ); it != proc.fd_path.end( ); ) {
                    if ( it->first >= fdarg && it->first <= fdarg2 )
                        it = proc.fd_path.erase( it );
                    else
                        ++it;
                }
                break;
            case MMAPF: {
                // PROT_WRITE|MAP_SHARED can modify the file invisibly (page
                // writeback makes no syscall) — count it as a writer; any
                // other file map is effectively a read channel.
                if ( isInfra )
                    break;
                std::string fp = fdPath( pid, fdarg );
                if ( fp.empty( ) )
                    break;
                if ( ( extra & PROT_WRITE ) && ( flags & MAP_SHARED ) )
                    rep.paths[ fp ].writers.insert( who );
                else
                    rep.paths[ fp ].readers.insert( who );
                break;
            }
            case WRITEF: {
                if ( isInfra )
                    break;
                if ( !rpath.empty( ) )
                    rep.paths[ rpath ].writers.insert( who );
                if ( !rpath2.empty( ) )
                    rep.paths[ rpath2 ].writers.insert( who );
                std::string fp = fdPath( pid, fdarg );
                if ( !fp.empty( ) )
                    rep.paths[ fp ].writers.insert( who );
                break;
            }
            case DEL: {
                if ( isInfra )
                    break;
                if ( !rpath.empty( ) )
                    rep.paths[ rpath ].deleters.insert( who );
                if ( !rpath2.empty( ) )
                    rep.paths[ rpath2 ].writers.insert( who ); // rename/link dst
                break;
            }
            case MKD:
            case TRUNC: {
                if ( isInfra )
                    break;
                if ( !rpath.empty( ) )
                    rep.paths[ rpath ].writers.insert( who );
                std::string fp = fdPath( pid, fdarg );
                if ( !fp.empty( ) )
                    rep.paths[ fp ].writers.insert( who );
                break;
            }
            case CHDIRF:
                if ( !rpath.empty( ) ) {
                    proc.cwd = rpath;
                } else if ( fdarg >= 0 ) {
                    std::string fp = fdPath( pid, fdarg );
                    if ( !fp.empty( ) )
                        proc.cwd = fp;
                }
                break;
            case CONN: {
                if ( isInfra )
                    break;
                int addrlen = ( int )regs.rdx;
                if ( addrlen > 0 && addrlen <= 512 ) {
                    std::vector<char> buf( addrlen, 0 );
                    for ( int i = 0; i < addrlen; i += sizeof( long ) ) {
                        long w = ptrace( PTRACE_PEEKTEXT, pid, ( char * )regs.rsi + i, NULL );
                        memcpy( &buf[ i ], &w, std::min( ( int )sizeof( long ), addrlen - i ) );
                    }
                    sockaddr *sa = ( sockaddr * )buf.data( );
                    std::string dest;
                    if ( sa->sa_family == AF_INET && addrlen >= ( int )sizeof( sockaddr_in ) ) {
                        sockaddr_in *in = ( sockaddr_in * )sa;
                        char ip[ INET_ADDRSTRLEN ];
                        unsigned char *b = ( unsigned char * )&in->sin_addr;
                        snprintf( ip, sizeof ip, "%d.%d.%d.%d", b[ 0 ], b[ 1 ], b[ 2 ], b[ 3 ] );
                        char tmp[ 64 ];
                        snprintf( tmp, sizeof tmp, "%s:%d", ip, ntohs( in->sin_port ) );
                        dest = tmp;
                    } else if ( sa->sa_family == AF_INET6 && addrlen >= ( int )sizeof( sockaddr_in6 ) ) {
                        sockaddr_in6 *in6 = ( sockaddr_in6 * )sa;
                        char ip[ INET6_ADDRSTRLEN ];
                        inet_ntop( AF_INET6, &in6->sin6_addr, ip, sizeof ip );
                        char tmp[ 128 ];
                        snprintf( tmp, sizeof tmp, "[%s]:%d", ip, ntohs( in6->sin6_port ) );
                        dest = tmp;
                    } else if ( sa->sa_family == AF_UNIX ) {
                        sockaddr_un *un = ( sockaddr_un * )sa;
                        if ( un->sun_path[ 0 ] == '\0' )
                            dest = std::string( "@abstract:" ) + std::string( un->sun_path + 1, strnlen( un->sun_path + 1, sizeof( un->sun_path ) - 1 ) );
                        else
                            dest = un->sun_path;
                    } else {
                        dest = "family=" + std::to_string( sa->sa_family );
                    }
                    rep.connects[ dest ].insert( who );
                }
                break;
            }
            case IOURING: {
                if ( isInfra || ret < 0 )
                    break;
                rep.iouring.insert( who );
                // A registered-files array names exactly which files the ring
                // may read/write invisibly — resolve each fd now.
                if ( syscall == SYS_io_uring_register && extra == IORING_REGISTER_FILES && fdarg2 && flags > 0 ) {
                    long n = std::min<long>( flags, 1024 );
                    for ( long i = 0; i < n; i++ ) {
                        long w = ptrace( PTRACE_PEEKTEXT, pid, ( char * )fdarg2 + i * ( long )sizeof( int ), NULL );
                        if ( w == -1 && errno )
                            break;
                        std::string fp = fdPath( pid, ( int )( w & 0xffffffff ) );
                        if ( !fp.empty( ) )
                            rep.iouring_files[ fp ].insert( who );
                    }
                }
                break;
            }
            case NONE:
                break;
        }

        // openat/open handled here since it isn't an Act
        if ( syscall == SYS_open || syscall == SYS_openat || syscall == SYS_openat2 || syscall == SYS_creat ) {
            if ( rpath.empty( ) )
                continue;
            long accmode = flags & O_ACCMODE;
            if ( ret >= 0 ) {
                proc.fd_path[ ret ] = rpath;
            }
            if ( accmode == O_RDONLY ) {
                if ( !isInfra )
                    rep.paths[ rpath ].probers.insert( who );
            } else {
                if ( !isInfra )
                    rep.paths[ rpath ].writers.insert( who );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Filesystem enumeration for bwrap args
// ---------------------------------------------------------------------------

static bool startsWith( const std::string &s, const std::string &pref ) {
    return s.size( ) >= pref.size( ) && s.compare( 0, pref.size( ), pref ) == 0;
}

static bool isDir( const std::string &p ) {
    struct stat st;
    return stat( p.c_str( ), &st ) == 0 && S_ISDIR( st.st_mode );
}

// Dirs whose sandbox writes are discarded rather than captured: --ro and
// --hide targets. The payload still sees a normal writable fs (overlay /
// tmpfs), but nothing under these paths enters the diff or gets applied.
static std::vector<std::string> g_discard_dirs;

static bool underAnyDir( const std::vector<std::string> &dirs, const std::string &p ) {
    for ( const auto &d : dirs )
        if ( p == d || startsWith( p, d + "/" ) )
            return true;
    return false;
}

// realpath, falling back to the input on failure
static std::string canon( const std::string &p ) {
    char buf[ PATH_MAX ];
    if ( realpath( p.c_str( ), buf ) )
        return buf;
    return p;
}

static void mkdirs( const std::string &p ) {
    std::string cur;
    for ( char c : p ) {
        cur += c;
        if ( c == '/' && cur.size( ) > 1 )
            mkdir( cur.c_str( ), 0755 );
    }
    mkdir( p.c_str( ), 0755 );
}

// ---------------------------------------------------------------------------
// Upper layer diff
// ---------------------------------------------------------------------------

struct UpperDiff {
    std::vector<std::string> created;
    std::vector<std::string> modified;
    std::vector<std::string> deleted;
};

static bool isWhiteout( const std::string &p, mode_t mode, dev_t rdev ) {
    if ( S_ISCHR( mode ) && rdev == 0 )
        return true;
    // userxattr overlays (unprivileged) mark whiteouts with an xattr instead
    char buf[ 8 ];
    return lgetxattr( p.c_str( ), "user.overlay.whiteout", buf, sizeof buf ) >= 0;
}

static void walkUpper( const std::string &upper_root, const std::string &fs_root, const std::string &rel, UpperDiff &d ) {
    DIR *dir = opendir( upper_root.c_str( ) );
    if ( !dir )
        return;
    struct dirent *ent;
    while ( ( ent = readdir( dir ) ) != NULL ) {
        if ( !strcmp( ent->d_name, "." ) || !strcmp( ent->d_name, ".." ) )
            continue;
        std::string upath = upper_root + "/" + ent->d_name;
        std::string rrel = rel.empty( ) ? ent->d_name : rel + "/" + ent->d_name;
        std::string real = fs_root + "/" + rrel;
        if ( underAnyDir( g_discard_dirs, real ) )
            continue;
        struct stat st;
        if ( lstat( upath.c_str( ), &st ) < 0 )
            continue;
        if ( isWhiteout( upath, st.st_mode, st.st_rdev ) ) {
            d.deleted.push_back( real );
            continue;
        }
        if ( S_ISDIR( st.st_mode ) ) {
            struct stat rst;
            if ( stat( real.c_str( ), &rst ) < 0 )
                d.created.push_back( real + "/" );
            walkUpper( upath, fs_root, rrel, d );
            continue;
        }
        struct stat rst;
        if ( stat( real.c_str( ), &rst ) < 0 )
            d.created.push_back( real );
        else
            d.modified.push_back( real );
    }
    closedir( dir );
}

// Walk a bound dir that started empty: everything in it is created.
// Walk a bound dir that started as a copy of dest: created/modified vs dest,
// plus a reverse walk for deletions.
static void walkBound( const std::string &src, const std::string &dest, const std::string &rel, bool copied, UpperDiff &d ) {
    DIR *dir = opendir( src.c_str( ) );
    if ( !dir )
        return;
    struct dirent *ent;
    while ( ( ent = readdir( dir ) ) != NULL ) {
        if ( !strcmp( ent->d_name, "." ) || !strcmp( ent->d_name, ".." ) )
            continue;
        std::string spath = src + "/" + ent->d_name;
        std::string rrel = rel.empty( ) ? ent->d_name : rel + "/" + ent->d_name;
        std::string real = dest + "/" + rrel;
        if ( underAnyDir( g_discard_dirs, real ) )
            continue;
        struct stat st, rst;
        if ( lstat( spath.c_str( ), &st ) < 0 )
            continue;
        if ( S_ISDIR( st.st_mode ) ) {
            if ( stat( real.c_str( ), &rst ) < 0 )
                d.created.push_back( real + "/" );
            walkBound( spath, dest, rrel, copied, d );
            continue;
        }
        if ( !copied ) {
            d.created.push_back( real );
            continue;
        }
        if ( stat( real.c_str( ), &rst ) < 0 ) {
            d.created.push_back( real );
        } else if ( st.st_mtime != rst.st_mtime || st.st_size != rst.st_size ) {
            d.modified.push_back( real );
        }
    }
    closedir( dir );
}

// Reverse walk: entries present on the real fs but missing from a copied bind
// were deleted inside the sandbox.
static void walkBoundDeleted( const std::string &src, const std::string &dest, const std::string &rel, UpperDiff &d ) {
    DIR *dir = opendir( dest.c_str( ) );
    if ( !dir )
        return;
    struct dirent *ent;
    while ( ( ent = readdir( dir ) ) != NULL ) {
        if ( !strcmp( ent->d_name, "." ) || !strcmp( ent->d_name, ".." ) )
            continue;
        std::string rrel = rel.empty( ) ? ent->d_name : rel + "/" + ent->d_name;
        std::string spath = src + "/" + rrel;
        std::string real = dest + "/" + rrel;
        if ( underAnyDir( g_discard_dirs, real ) )
            continue;
        struct stat st;
        if ( lstat( spath.c_str( ), &st ) < 0 ) {
            d.deleted.push_back( real );
            continue;
        }
        if ( S_ISDIR( st.st_mode ) )
            walkBoundDeleted( spath, real, rrel, d );
    }
    closedir( dir );
}

static int copyFile( const std::string &src, const std::string &dst, mode_t mode );

static int applyBound( const std::string &src, const std::string &dest, const std::string &rel, bool copied ) {
    DIR *dir = opendir( src.c_str( ) );
    int errs = 0;
    if ( dir ) {
        struct dirent *ent;
        while ( ( ent = readdir( dir ) ) != NULL ) {
            if ( !strcmp( ent->d_name, "." ) || !strcmp( ent->d_name, ".." ) )
                continue;
            std::string spath = src + "/" + ent->d_name;
            std::string rrel = rel.empty( ) ? ent->d_name : rel + "/" + ent->d_name;
            std::string dpath = dest + "/" + rrel;
            if ( underAnyDir( g_discard_dirs, dpath ) )
                continue;
            struct stat st;
            if ( lstat( spath.c_str( ), &st ) < 0 )
                continue;
            if ( S_ISDIR( st.st_mode ) ) {
                mkdirs( dpath );
                errs += applyBound( spath, dest, rrel, copied );
            } else if ( S_ISLNK( st.st_mode ) ) {
                char target[ PATH_MAX ];
                ssize_t n = readlink( spath.c_str( ), target, sizeof target - 1 );
                if ( n >= 0 ) {
                    target[ n ] = 0;
                    unlink( dpath.c_str( ) );
                    if ( symlink( target, dpath.c_str( ) ) < 0 )
                        errs++;
                }
            } else {
                if ( copyFile( spath, dpath, st.st_mode ) < 0 ) {
                    perror( dpath.c_str( ) );
                    errs++;
                }
            }
        }
        closedir( dir );
    }
    if ( copied ) {
        // delete dest entries missing from src
        DIR *dd = opendir( dest.c_str( ) );
        if ( dd ) {
            struct dirent *ent;
            while ( ( ent = readdir( dd ) ) != NULL ) {
                if ( !strcmp( ent->d_name, "." ) || !strcmp( ent->d_name, ".." ) )
                    continue;
                std::string rrel = rel.empty( ) ? ent->d_name : rel + "/" + ent->d_name;
                std::string spath = src + "/" + rrel;
                struct stat st;
                if ( lstat( spath.c_str( ), &st ) < 0 ) {
                    std::string cmd = "rm -rf -- '" + dest + "/" + rrel + "'";
                    if ( system( cmd.c_str( ) ) != 0 )
                        errs++;
                }
            }
            closedir( dd );
        }
    }
    return errs;
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

static void printSection( const char *title, const std::vector<std::string> &lines ) {
    if ( lines.empty( ) )
        return;
    printf( "\n== %s (%zu) ==\n", title, lines.size( ) );
    for ( const auto &l : lines )
        printf( "  %s\n", l.c_str( ) );
}

static bool skipPath( const std::string &p, const std::vector<std::regex> &ignore ) {
    // sandbox internals — always noise
    static const char *builtin[] = { "/proc", "/sys", "/oldroot", "/newroot", "/tmp/oldroot", "/tmp/newroot" };
    for ( const char *pref : builtin ) {
        if ( p == pref || startsWith( p, std::string( pref ) + "/" ) )
            return true;
    }
    return tracer::matchsAnyIgnore( p, ignore );
}

static void printReport( const Report &rep, const UpperDiff &diff, const std::vector<std::regex> &ignore ) {
    std::vector<std::string> wrote, read, probed, deleted;
    for ( const auto &kv : rep.paths ) {
        const std::string &p = kv.first;
        if ( skipPath( p, ignore ) )
            continue;
        const PathInfo &pi = kv.second;
        auto fmt = []( const std::set<std::string> &who ) {
            std::string s;
            for ( const auto &w : who )
                s += " " + w;
            return s;
        };
        // A path that was written OR read counts as "written/read", not probed
        bool isWrite = !pi.writers.empty( );
        bool isRead = !pi.readers.empty( );
        // writes under --ro/--hide dirs are discarded — say so, since no
        // amount of accepting the prompt will make them appear
        const char *discarded = underAnyDir( g_discard_dirs, p ) ? "   (discarded)" : "";
        if ( isWrite )
            wrote.push_back( p + "   by" + fmt( pi.writers ) + discarded );
        if ( isRead )
            read.push_back( p + "   by" + fmt( pi.readers ) );
        if ( !pi.deleters.empty( ) )
            deleted.push_back( p + "   by" + fmt( pi.deleters ) + discarded );
        // probed = opened-ro/statted but never read, or probed missing
        if ( !pi.probers.empty( ) && ( pi.probed_missing || ( !isRead && !isWrite ) ) ) {
            probed.push_back( p + ( pi.probed_missing ? "   (missing) by" : "   by" ) + fmt( pi.probers ) );
        }
    }
    std::vector<std::string> execs, conns, created, modified, deletedfs;
    for ( const auto &kv : rep.execs ) {
        if ( skipPath( kv.first, ignore ) )
            continue;
        execs.push_back( kv.first );
    }
    for ( const auto &kv : rep.connects ) {
        std::string s = kv.first + "   by";
        for ( const auto &w : kv.second )
            s += " " + w;
        conns.push_back( s );
    }
    std::vector<std::string> iouring;
    for ( const auto &w : rep.iouring )
        iouring.push_back( w + "   (ring I/O invisible to trace)" );
    for ( const auto &kv : rep.iouring_files ) {
        std::string s = kv.first + "   registered into ring by";
        for ( const auto &w : kv.second )
            s += " " + w;
        iouring.push_back( s );
    }
    for ( const auto &p : diff.created )
        created.push_back( p );
    for ( const auto &p : diff.modified )
        modified.push_back( p );
    for ( const auto &p : diff.deleted )
        deletedfs.push_back( p );

    printf( "\n repdry report" );
    printf( "\n==============" );
    printSection( "Created (sandbox only)", created );
    printSection( "Modified (sandbox only)", modified );
    printSection( "Deleted (sandbox only)", deletedfs );
    printSection( "Wrote (traced)", wrote );
    printSection( "Deleted (traced)", deleted );
    printSection( "Read", read );
    printSection( "Probed / statted only", probed );
    printSection( "Executed", execs );
    printSection( "Network connects", conns );
    printSection( "io_uring detected", iouring );
    printf( "\n" );
}

// ---------------------------------------------------------------------------
// Commit: apply upper onto the real fs
// ---------------------------------------------------------------------------

static int copyFile( const std::string &src, const std::string &dst, mode_t mode ) {
    int in = open( src.c_str( ), O_RDONLY );
    if ( in < 0 )
        return -1;
    mkdirs( dst.substr( 0, dst.find_last_of( '/' ) ) );
    int out = open( dst.c_str( ), O_WRONLY | O_CREAT | O_TRUNC, mode );
    if ( out < 0 ) {
        close( in );
        return -1;
    }
    char buf[ 64 * 1024 ];
    ssize_t n;
    while ( ( n = read( in, buf, sizeof buf ) ) > 0 ) {
        if ( write( out, buf, n ) != n ) {
            close( in );
            close( out );
            return -1;
        }
    }
    close( in );
    close( out );
    return 0;
}

static int applyUpper( const std::string &upper, const std::string &dest_root ) {
    DIR *dir = opendir( upper.c_str( ) );
    if ( !dir )
        return 0;
    int errs = 0;
    struct dirent *ent;
    while ( ( ent = readdir( dir ) ) != NULL ) {
        if ( !strcmp( ent->d_name, "." ) || !strcmp( ent->d_name, ".." ) )
            continue;
        std::string upath = upper + "/" + ent->d_name;
        std::string dpath = dest_root + "/" + ent->d_name;
        if ( underAnyDir( g_discard_dirs, dpath ) )
            continue;
        struct stat st;
        if ( lstat( upath.c_str( ), &st ) < 0 )
            continue;
        if ( isWhiteout( upath, st.st_mode, st.st_rdev ) ) {
            char cmd[ PATH_MAX + 16 ];
            snprintf( cmd, sizeof cmd, "rm -rf -- '%s'", dpath.c_str( ) );
            if ( system( cmd ) != 0 )
                errs++;
            continue;
        }
        if ( S_ISDIR( st.st_mode ) ) {
            mkdirs( dpath );
            errs += applyUpper( upath, dpath );
        } else if ( S_ISLNK( st.st_mode ) ) {
            char target[ PATH_MAX ];
            ssize_t n = readlink( upath.c_str( ), target, sizeof target - 1 );
            if ( n >= 0 ) {
                target[ n ] = 0;
                unlink( dpath.c_str( ) );
                if ( symlink( target, dpath.c_str( ) ) < 0 )
                    errs++;
            }
        } else {
            if ( copyFile( upath, dpath, st.st_mode ) < 0 ) {
                perror( dpath.c_str( ) );
                errs++;
            }
        }
    }
    closedir( dir );
    return errs;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

static void usage( ) {
    fprintf( stderr, "usage: repdry [--allow-net] [-v]\n"
                     "              [--ignore REGEX]... [--ro DIR]... [--hide DIR]...\n"
                     "              -- COMMAND [ARGS...]\n"
                     "\n"
                     "Run COMMAND inside a bubblewrap sandbox: the host filesystem is\n"
                     "visible read-only via an overlay, so writes land in a scratch dir\n"
                     "instead of touching the real system. Afterwards prints a report of\n"
                     "everything the command read, wrote, deleted, probed and executed.\n" );
}

int main( int argc, char *argv[] ) {
    std::vector<std::regex> ignore;
    std::vector<std::string> ro_dirs, hide_dirs;
    bool share_net = false, verbose = false;
    int i;
    bool foundSep = false;
    for ( i = 1; i < argc; i++ ) {
        const char *arg = argv[ i ];
        if ( !strcmp( "--", arg ) ) {
            foundSep = true;
            break;
        } else if ( !strcmp( "--ignore", arg ) && i + 1 < argc ) {
            ignore.emplace_back( argv[ ++i ] );
        } else if ( !strcmp( "--ro", arg ) && i + 1 < argc ) {
            ro_dirs.emplace_back( canon( argv[ ++i ] ) );
        } else if ( !strcmp( "--hide", arg ) && i + 1 < argc ) {
            hide_dirs.emplace_back( canon( argv[ ++i ] ) );
        } else if ( !strcmp( "--verbose", arg ) || !strcmp( "-v", arg ) ) {
            verbose = true;
        } else if ( !strcmp( "--allow-net", arg ) ) {
            share_net = true;
        } else if ( !strcmp( "--help", arg ) || !strcmp( "-h", arg ) ) {
            usage( );
            return 0;
        } else {
            fprintf( stderr, "repdry: unexpected arg: %s\n", arg );
            usage( );
            return 1;
        }
    }
    if ( !foundSep || i == argc - 1 ) {
        usage( );
        return 1;
    }
    int cmdStart = i + 1;

    // --- scratch dir ---
    char tmpl[] = "/tmp/repdry.XXXXXX";
    if ( !mkdtemp( tmpl ) ) {
        perror( "mkdtemp" );
        return 1;
    }
    std::string scratch_canon = canon( tmpl );
    mkdirs( scratch_canon + "/upper" );
    mkdirs( scratch_canon + "/work" );
    mkdirs( scratch_canon + "/hide" );

    // Fork a babysitter whose only job is to wipe the scratch dir if repdry
    // dies before cleaning up. It blocks all blockable signals (ctrl-c's
    // SIGINT hits the whole foreground group, including us) and waits on a
    // pipe; the write end is held by repdry and inherited by the traced
    // payload, so EOF means every process that could touch the scratch is
    // gone. Normal exits kill it before it ever wakes up.
    int bpipe[ 2 ] = { -1, -1 };
    pid_t babysitter = -1;
    if ( pipe( bpipe ) == 0 ) {
        babysitter = fork( );
        if ( babysitter == 0 ) {
            sigset_t mask;
            sigfillset( &mask );
            sigprocmask( SIG_SETMASK, &mask, NULL );
            close( bpipe[ 1 ] );
            char c;
            while ( read( bpipe[ 0 ], &c, 1 ) > 0 ) {
            }
            execl( "/bin/sh", "sh", "-c",
                   "chmod -R u+rwX -- \"$1\" 2>/dev/null; exec rm -rf -- \"$1\"",
                   "sh", scratch_canon.c_str( ), (char *)NULL );
            _exit( 1 );
        }
        close( bpipe[ 0 ] );
        if ( babysitter < 0 )
            close( bpipe[ 1 ] );
    }

    // --- mount-aware overlay planning ---------------------------------------
    // Constraints found empirically with bwrap+overlayfs on this kernel:
    //   * the lowerdir may not contain sub-mounts (clone of the lower path fails)
    //   * the lower fs must support user xattrs (vfat/ntfs/squashfs/... fail)
    //   * a mount root itself can't be a lowerdir
    // planDir() therefore overlays only leaf dirs on xattr-capable filesystems
    // and descends into everything else; what it can't cover stays read-only
    // and shows up as failed writes in the trace.

    // canonical mountpoint -> fstype
    std::map<std::string, std::string> mount_fs;
    {
        std::ifstream mounts( "/proc/self/mounts" );
        std::string dev, mp, fs, rest;
        while ( mounts >> dev >> mp >> fs ) {
            std::getline( mounts, rest );
            mount_fs[ canon( mp ) ] = fs;
        }
    }

    // fstype of the deepest mount containing d
    auto fsAt = [ & ]( const std::string &d ) {
        std::string best = "rootfs";
        size_t bestlen = 0;
        for ( const auto &kv : mount_fs ) {
            const std::string &mp = kv.first;
            if ( ( d == mp || mp == "/" || startsWith( d, mp + "/" ) ) && mp.size( ) > bestlen ) {
                best = kv.second;
                bestlen = mp.size( );
            }
        }
        return best;
    };
    // filesystems whose dirs can't serve as an overlay lowerdir in a userns
    static const std::set<std::string> unsafe_lower_fs = { "vfat", "msdos",   "fat",         "exfat",  "ntfs",     "ntfs3",   "fuseblk", "iso9660", "udf",        "squashfs",  "erofs",      "cifs",    "smb3",      "nfs",
                                                           "nfs4", "overlay", "ramfs",       "9p",     "autofs",   "debugfs", "tracefs", "pstore",  "securityfs", "selinuxfs", "configfs",   "fusectl", "hugetlbfs", "mqueue",
                                                           "bpf",  "nsfs",    "binfmt_misc", "devpts", "devtmpfs", "cgroup",  "cgroup2", "sysfs",   "proc",       "efivarfs",  "rpc_pipefs", "sunrpc",  "ecryptfs" };
    auto fsUnsafe = [ & ]( const std::string &fs ) { return unsafe_lower_fs.count( fs ) || startsWith( fs, "fuse" ); };
    // does d contain any mountpoints strictly beneath it?
    auto hasSubmounts = [ & ]( const std::string &d ) {
        for ( const auto &kv : mount_fs )
            if ( kv.first != d && startsWith( kv.first, d + "/" ) )
                return true;
        return false;
    };
    auto underAny = []( const std::vector<std::string> &dirs, const std::string &d ) {
        for ( const auto &r : dirs )
            if ( d == r || startsWith( d, r + "/" ) )
                return true;
        return false;
    };
    auto hasDescendant = []( const std::vector<std::string> &dirs, const std::string &d ) {
        for ( const auto &r : dirs )
            if ( r != d && startsWith( r, d + "/" ) )
                return true;
        return false;
    };

    std::vector<std::pair<std::string, std::string>> overlays;      // {dest, rel path}
    std::vector<std::pair<std::string, std::string>> late_overlays; // mounted after binds (e.g. cwd under /tmp)
    struct BoundDir {
        std::string dest;
        std::string src;
        bool copied; // contents were copied from dest (vs starts empty)
    };
    std::vector<BoundDir> bound_dirs;
    std::set<std::string> emitted;

    std::vector<std::string> ro_dirs_c, hide_dirs_c;
    for ( const auto &r : ro_dirs ) {
        ro_dirs_c.push_back( canon( r ) );
        g_discard_dirs.push_back( ro_dirs_c.back( ) );
    }
    for ( const auto &t : hide_dirs ) {
        hide_dirs_c.push_back( canon( t ) );
        g_discard_dirs.push_back( hide_dirs_c.back( ) );
    }

    std::function<void( const std::string &, int )> planDir = [ & ]( const std::string &d, int depth ) {
        if ( depth > 16 || emitted.count( d ) || emitted.size( ) > 1024 )
            return;
        emitted.insert( d );

        if ( d == scratch_canon ) {
            // hide the scratch dir from the payload entirely
            bound_dirs.push_back( { d, scratch_canon + "/hide", false } );
            return;
        }
        if ( underAny( hide_dirs_c, d ) )
            return; // fresh tmpfs emitted later
        if ( d == "/tmp" ) {
            // most common write target; give it a fresh writable dir so
            // arbitrary writes there are captured (real contents hidden)
            bound_dirs.push_back( { d, scratch_canon + "/bound/tmp", false } );
            return;
        }
        // scratch must never sit inside its own overlay lowerdir, and
        // --hide targets must not be shadowed by an overlay above them:
        // descend past ancestors of all of these instead of overlaying them.
        // (--ro dirs are overlaid like anything else — writes are silently
        // discarded by filtering them out of the diff below.)
        if ( startsWith( scratch_canon, d + "/" ) || hasDescendant( hide_dirs_c, d ) || hasSubmounts( d ) ) {
            DIR *dir = opendir( d.c_str( ) );
            if ( !dir )
                return;
            std::vector<std::string> kids;
            struct dirent *ent;
            while ( ( ent = readdir( dir ) ) != NULL ) {
                if ( !strcmp( ent->d_name, "." ) || !strcmp( ent->d_name, ".." ) )
                    continue;
                std::string c = canon( d + "/" + ent->d_name );
                if ( c != d && isDir( c ) )
                    kids.push_back( c );
            }
            closedir( dir );
            std::sort( kids.begin( ), kids.end( ) );
            for ( const auto &c : kids )
                planDir( c, depth + 1 );
            return;
        }
        if ( fsUnsafe( fsAt( d ) ) )
            return; // can't be a lowerdir; stays read-only
        if ( access( d.c_str( ), R_OK | X_OK ) != 0 )
            return; // unreadable (e.g. /root, lost+found); stays read-only
        overlays.push_back( { d, d.substr( 1 ) } );
    };

    // plan overlays for every top-level dir of /
    {
        DIR *root = opendir( "/" );
        struct dirent *ent;
        while ( root && ( ent = readdir( root ) ) != NULL ) {
            if ( !strcmp( ent->d_name, "." ) || !strcmp( ent->d_name, ".." ) )
                continue;
            std::string c = canon( "/" + std::string( ent->d_name ) );
            if ( c == "/proc" || c == "/sys" || c == "/dev" )
                continue;
            if ( !isDir( c ) )
                continue;
            planDir( c, 0 );
        }
        if ( root )
            closedir( root );
    }

    // ancestors of the scratch dir were descended rather than overlaid, so
    // nothing new can be created directly inside them — warn once.
    {
        bool under_bound = false;
        for ( const auto &bd : bound_dirs )
            if ( startsWith( scratch_canon, bd.dest + "/" ) )
                under_bound = true;
        if ( !under_bound )
            fprintf( stderr, "repdry: note: scratch dir is under %s; directories containing it stay read-only (new files there can't be captured)\n", scratch_canon.substr( 0, scratch_canon.rfind( '/' ) ).c_str( ) );
    }

    // --- cwd: must exist inside the sandbox ---
    char cwdbuf[ PATH_MAX ];
    std::string cwd_canon;
    if ( getcwd( cwdbuf, sizeof cwdbuf ) )
        cwd_canon = canon( cwdbuf );
    if ( !cwd_canon.empty( ) ) {
        if ( cwd_canon == scratch_canon || startsWith( cwd_canon, scratch_canon + "/" ) ) {
            fprintf( stderr, "repdry: warning: cwd is inside the scratch dir; not preserving it\n" );
            cwd_canon.clear( );
        } else {
            // if cwd sits under a dir replaced by an empty scratch dir it
            // doesn't exist in the sandbox — give it its own overlay so
            // reads and writes there are captured like anywhere else.
            for ( const auto &bd : bound_dirs ) {
                if ( !bd.copied && ( cwd_canon == bd.dest || startsWith( cwd_canon, bd.dest + "/" ) ) ) {
                    late_overlays.push_back( { cwd_canon, cwd_canon.substr( 1 ) } );
                    // the mountpoint must exist under the bound dir — create
                    // it in the bound's source tree
                    mkdirs( bd.src + cwd_canon.substr( bd.dest.size( ) ) );
                    break;
                }
            }
        }
    }

    // --- build bwrap argv ---
    std::vector<std::string> bargs;
    bargs.push_back( "bwrap" );
    bargs.push_back( "--die-with-parent" );
    bargs.push_back( "--unshare-all" );
    if ( share_net )
        bargs.push_back( "--share-net" );
    bargs.push_back( "--ro-bind" );
    bargs.push_back( "/" );
    bargs.push_back( "/" );

    std::sort( overlays.begin( ), overlays.end( ) );
    for ( const auto &ov : overlays ) {
        std::string up = scratch_canon + "/upper/" + ov.second;
        std::string wk = scratch_canon + "/work/" + ov.second;
        mkdirs( up );
        mkdirs( wk );
        bargs.push_back( "--overlay-src" );
        bargs.push_back( ov.first );
        bargs.push_back( "--overlay" );
        bargs.push_back( up );
        bargs.push_back( wk );
        bargs.push_back( ov.first );
    }
    for ( const auto &bd : bound_dirs ) {
        mkdirs( bd.src );
        bargs.push_back( "--bind" );
        bargs.push_back( bd.src );
        bargs.push_back( bd.dest );
    }
    for ( const auto &ov : late_overlays ) {
        std::string up = scratch_canon + "/upper/" + ov.second;
        std::string wk = scratch_canon + "/work/" + ov.second;
        mkdirs( up );
        mkdirs( wk );
        bargs.push_back( "--overlay-src" );
        bargs.push_back( ov.first );
        bargs.push_back( "--overlay" );
        bargs.push_back( up );
        bargs.push_back( wk );
        bargs.push_back( ov.first );
    }
    for ( const auto &d : hide_dirs_c ) {
        bargs.push_back( "--tmpfs" );
        bargs.push_back( d );
    }
    bargs.push_back( "--proc" );
    bargs.push_back( "/proc" );
    bargs.push_back( "--dev" );
    bargs.push_back( "/dev" );

    if ( !cwd_canon.empty( ) ) {
        bargs.push_back( "--chdir" );
        bargs.push_back( cwd_canon );
    }

    bargs.push_back( "--" );
    for ( i = cmdStart; i < argc; i++ )
        bargs.push_back( argv[ i ] );

    std::vector<char *> bargv;
    for ( auto &s : bargs )
        bargv.push_back( ( char * )s.c_str( ) );
    bargv.push_back( NULL );

    if ( verbose ) {
        fprintf( stderr, "repdry: " );
        for ( auto &s : bargs )
            fprintf( stderr, "%s ", s.c_str( ) );
        fprintf( stderr, "\n" );
    }

    // --- fork & trace ---
    pid_t pid = fork( );
    if ( pid < 0 ) {
        perror( "fork" );
        return 1;
    }
    if ( pid == 0 ) {
        tracer::runTracedExec( bargv.data( ), trace_syscalls, fd_arg_syscalls );
        _exit( 127 );
    }

    int status;
    waitpid( pid, &status, 0 );
    ptrace( PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK );
    procs[ pid ].cwd = cwdbuf;
    procs[ pid ].exe = "bwrap";
    procs[ pid ].infra = true;

    Report rep;
    int ret = traceRun( pid, rep, ignore );

    // --- diff the upper layers and bound dirs ---
    UpperDiff diff;
    for ( const auto &ov : overlays ) {
        walkUpper( scratch_canon + "/upper/" + ov.second, ov.first, "", diff );
    }
    for ( const auto &ov : late_overlays ) {
        walkUpper( scratch_canon + "/upper/" + ov.second, ov.first, "", diff );
    }
    for ( const auto &bd : bound_dirs ) {
        if ( bd.dest == scratch_canon )
            continue; // the scratch-hide bind is not a diff
        walkBound( bd.src, bd.dest, "", bd.copied, diff );
        if ( bd.copied )
            walkBoundDeleted( bd.src, bd.dest, "", diff );
    }

    printReport( rep, diff, ignore );

    // --- prompt to apply; anything but an explicit "y" discards ---
    bool changes = !diff.created.empty( ) || !diff.modified.empty( ) || !diff.deleted.empty( );
    bool apply = false;
    if ( changes ) {
        fprintf( stderr, "\napply these changes to the real filesystem? [y/N] " );
        char ans[ 16 ] = { 0 };
        apply = fgets( ans, sizeof ans, stdin ) != NULL && ( ans[ 0 ] == 'y' || ans[ 0 ] == 'Y' );
        if ( !apply )
            fprintf( stderr, "repdry: not applying; discarding changes\n" );
    }

    if ( apply ) {
        int errs = 0;
        for ( const auto &ov : overlays ) {
            errs += applyUpper( scratch_canon + "/upper/" + ov.second, ov.first );
        }
        for ( const auto &ov : late_overlays ) {
            errs += applyUpper( scratch_canon + "/upper/" + ov.second, ov.first );
        }
        for ( const auto &bd : bound_dirs ) {
            if ( bd.dest == scratch_canon )
                continue;
            errs += applyBound( bd.src, bd.dest, "", bd.copied );
        }
        if ( errs )
            fprintf( stderr, "repdry: %d error(s) applying changes\n", errs );
    }

    // kill the babysitter before cleaning up so it doesn't double-delete
    if ( babysitter > 0 ) {
        kill( babysitter, SIGKILL );
        waitpid( babysitter, NULL, 0 );
    }
    // overlay workdirs are created root-owned and unreadable
    std::string cmd = "chmod -R u+rwX -- '" + scratch_canon + "' 2>/dev/null; rm -rf -- '" + scratch_canon + "'";
    if ( system( cmd.c_str( ) ) != 0 )
        fprintf( stderr, "repdry: failed to remove %s\n", scratch_canon.c_str( ) );
    return rep.child_exit;
}
