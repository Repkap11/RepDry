// repdry test harness — one binary, subcommands that each exercise a
// specific syscall so the tracer's coverage can be asserted per-call.
//   ./harness <subcommand> [args...]
// Subcommands are intentionally terse; each returns nonzero on syscall
// failure unless the failure itself is what we're testing.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <utime.h>

extern char **environ;

static int die( const char *m ) {
    perror( m );
    return 1;
}

int main( int argc, char **argv ) {
    if ( argc < 2 )
        return 2;
    const char *c = argv[ 1 ];
    int fd, ret = 0;
    char buf[ 8192 ];
    struct stat st;
    struct iovec iov;

    // --- mmap channels -------------------------------------------------
    if ( !strcmp( c, "mmapr" ) ) {
        fd = open( argv[ 2 ], O_RDONLY );
        fstat( fd, &st );
        void *p = mmap( 0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0 );
        volatile char x = ( ( char * )p )[ 0 ];
        ( void )x;
        return 0;
    }
    if ( !strcmp( c, "mmapw" ) ) {
        fd = open( argv[ 2 ], O_RDWR );
        char *p = mmap( 0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 );
        memcpy( p, "MAPW", 4 );
        msync( p, 4096, MS_SYNC ); // flush so the upper-layer diff sees it
        return 0;
    }

    // --- legacy create paths --------------------------------------------
    if ( !strcmp( c, "creat" ) )
        return creat( argv[ 2 ], 0644 ) < 0 ? die( "creat" ) : 0;
    if ( !strcmp( c, "mknod" ) )
        return mknod( argv[ 2 ], S_IFIFO | 0644, 0 ) < 0 ? die( "mknod" ) : 0;

    // --- zero-copy data paths --------------------------------------------
    if ( !strcmp( c, "vmsplice" ) ) {
        int pp[ 2 ];
        if ( pipe( pp ) )
            return die( "pipe" );
        char m[] = "vmspliced\n";
        iov.iov_base = m;
        iov.iov_len = 10;
        syscall( SYS_vmsplice, pp[ 1 ], &iov, 1, 0 );
        fd = open( argv[ 2 ], O_WRONLY | O_CREAT | O_TRUNC, 0644 );
        splice( pp[ 0 ], NULL, fd, NULL, 10, 0 );
        return 0;
    }
    if ( !strcmp( c, "sendfile" ) ) {
        int s = open( argv[ 2 ], O_RDONLY );
        fstat( s, &st );
        int d = open( argv[ 3 ], O_WRONLY | O_CREAT | O_TRUNC, 0644 );
        return sendfile( d, s, NULL, st.st_size ) < 0 ? die( "sendfile" ) : 0;
    }

    // --- metadata / allocation -------------------------------------------
    if ( !strcmp( c, "fallocate" ) ) {
        fd = open( argv[ 2 ], O_WRONLY | O_CREAT, 0644 );
        return posix_fallocate( fd, 0, 128 ) ? die( "fallocate" ) : 0;
    }
    if ( !strcmp( c, "futimens" ) ) {
        fd = open( argv[ 2 ], O_WRONLY | O_CREAT, 0644 );
        return syscall( SYS_utimensat, fd, NULL, NULL, 0 ) < 0 ? die( "futimens" ) : 0;
    }
    if ( !strcmp( c, "futimesat" ) ) {
        int d = open( argv[ 2 ], O_RDONLY );
        return syscall( SYS_futimesat, d, argv[ 3 ], NULL ) < 0 ? die( "futimesat" ) : 0;
    }
    if ( !strcmp( c, "fchmod" ) ) {
        fd = open( argv[ 2 ], O_RDWR );
        return fchmod( fd, 0600 ) < 0 ? die( "fchmod" ) : 0;
    }
    if ( !strcmp( c, "fchown" ) ) {
        fd = open( argv[ 2 ], O_RDWR );
        return fchown( fd, getuid( ), getgid( ) ) < 0 ? die( "fchown" ) : 0;
    }
    if ( !strcmp( c, "ftrunc" ) ) {
        fd = open( argv[ 2 ], O_RDWR );
        return ftruncate( fd, 3 ) < 0 ? die( "ftrunc" ) : 0;
    }
    if ( !strcmp( c, "legacymeta" ) ) {
        // utime, utimes, access, stat, lstat, lchown, chown — the legacy
        // non-*at variants all in one shot
        struct stat b2;
        utime( argv[ 2 ], NULL );
        utimes( argv[ 2 ], NULL );
        access( argv[ 2 ], R_OK );
        stat( argv[ 2 ], &b2 );
        lstat( argv[ 2 ], &b2 );
        ret |= lchown( argv[ 2 ], ( uid_t )-1, ( gid_t )-1 );
        ret |= chown( argv[ 2 ], ( uid_t )-1, ( gid_t )-1 );
        return 0;
    }
    if ( !strcmp( c, "legacyprobe" ) ) {
        // access, stat, lstat — probe-only, kept separate from legacymeta
        // because probed entries are suppressed once a path is written
        struct stat b2;
        access( argv[ 2 ], R_OK );
        stat( argv[ 2 ], &b2 );
        lstat( argv[ 2 ], &b2 );
        return 0;
    }
    if ( !strcmp( c, "legacy" ) ) {
        // link, symlink, rename, unlink — legacy non-*at variants
        char p2[ 512 ], p3[ 512 ];
        snprintf( p2, sizeof p2, "%s.h", argv[ 2 ] );
        ret |= link( argv[ 2 ], p2 );
        snprintf( p3, sizeof p3, "%s.s", argv[ 2 ] );
        ret |= symlink( argv[ 2 ], p3 );
        snprintf( p2, sizeof p2, "%s.h", argv[ 2 ] );
        snprintf( p3, sizeof p3, "%s.r", argv[ 2 ] );
        rename( p2, p3 );
        snprintf( p2, sizeof p2, "%s.s", argv[ 2 ] );
        unlink( p2 );
        return 0;
    }

    // --- fd-based probes ---------------------------------------------------
    if ( !strcmp( c, "fstat" ) ) {
        fd = open( argv[ 2 ], O_RDONLY );
        return fstat( fd, &st ) < 0 ? die( "fstat" ) : 0;
    }
    if ( !strcmp( c, "fstatfs" ) ) {
        fd = open( argv[ 2 ], O_RDONLY );
        struct statfs s2;
        return fstatfs( fd, &s2 ) < 0 ? die( "fstatfs" ) : 0;
    }
    if ( !strcmp( c, "getdents" ) ) {
        fd = open( argv[ 2 ], O_RDONLY );
        return syscall( SYS_getdents, fd, buf, sizeof buf ) < 0 ? die( "getdents" ) : 0;
    }
    if ( !strcmp( c, "finitmod" ) ) {
        fd = open( argv[ 2 ], O_RDONLY );
        syscall( SYS_finit_module, fd, "", 0 ); // fails EINVAL; still traced
        return 0;
    }

    // --- xattrs -----------------------------------------------------------
    if ( !strcmp( c, "xattr" ) ) {
        char v[ 8 ];
        setxattr( argv[ 2 ], "user.t", "v", 1, 0 );
        getxattr( argv[ 2 ], "user.t", v, sizeof v );
        removexattr( argv[ 2 ], "user.t" );
        return 0;
    }
    if ( !strcmp( c, "fxattr" ) ) {
        fd = open( argv[ 2 ], O_RDONLY );
        char v[ 8 ];
        fsetxattr( fd, "user.t", "v", 1, 0 );
        fgetxattr( fd, "user.t", v, sizeof v );
        fremovexattr( fd, "user.t" );
        return 0;
    }
#ifdef SYS_setxattrat
    if ( !strcmp( c, "xattrat" ) ) {
        // the *xattrat API passes a struct { name, value, size, flags }
        struct xattr_args {
            const char *name;
            void *value;
            size_t size;
            unsigned int flags;
        } xa = { "user.t2", ( void * )"v", 1, 0 };
        syscall( SYS_setxattrat, AT_FDCWD, argv[ 2 ], 0, &xa, sizeof xa );
        return 0;
    }
#endif

    // --- open / exec variants ----------------------------------------------
    if ( !strcmp( c, "openat2" ) ) {
        struct open_how how = { .flags = O_RDONLY };
        return syscall( SYS_openat2, AT_FDCWD, argv[ 2 ], &how, sizeof how ) < 0 ? die( "openat2" ) : 0;
    }
    if ( !strcmp( c, "execveat" ) ) {
        char *a[] = { argv[ 2 ], NULL };
        return syscall( SYS_execveat, AT_FDCWD, argv[ 2 ], a, environ, 0 ) < 0 ? die( "execveat" ) : 0;
    }
    if ( !strcmp( c, "execveat_empty" ) ) {
        // AT_EMPTY_PATH: path is "", resolved through the fd instead
        fd = open( "/bin/true", O_RDONLY );
        char *a[] = { ( char * )"/bin/true", NULL };
        syscall( SYS_execveat, fd, "", a, environ, AT_EMPTY_PATH );
        return die( "execveat_empty" );
    }

    // --- positioned/vectored I/O --------------------------------------------
    if ( !strcmp( c, "pread" ) ) {
        fd = open( argv[ 2 ], O_RDONLY );
        return pread( fd, buf, 4, 0 ) < 0 ? die( "pread" ) : 0;
    }
    if ( !strcmp( c, "pwrite" ) ) {
        fd = open( argv[ 2 ], O_WRONLY | O_CREAT, 0644 );
        return pwrite( fd, "pw", 2, 0 ) < 0 ? die( "pwrite" ) : 0;
    }
    if ( !strcmp( c, "readv" ) ) {
        fd = open( argv[ 2 ], O_RDONLY );
        iov.iov_base = buf;
        iov.iov_len = 8;
        return readv( fd, &iov, 1 ) < 0 ? die( "readv" ) : 0;
    }
    if ( !strcmp( c, "writev" ) ) {
        fd = open( argv[ 2 ], O_WRONLY | O_CREAT, 0644 );
        iov.iov_base = ( void * )"wv";
        iov.iov_len = 2;
        return writev( fd, &iov, 1 ) < 0 ? die( "writev" ) : 0;
    }
    if ( !strcmp( c, "preadv" ) ) {
        fd = open( argv[ 2 ], O_RDONLY );
        iov.iov_base = buf;
        iov.iov_len = 8;
        return syscall( SYS_preadv, fd, &iov, 1, 0 ) < 0 ? die( "preadv" ) : 0;
    }
    if ( !strcmp( c, "pwritev" ) ) {
        fd = open( argv[ 2 ], O_WRONLY | O_CREAT, 0644 );
        iov.iov_base = ( void * )"pv";
        iov.iov_len = 2;
        return syscall( SYS_pwritev, fd, &iov, 1, 0 ) < 0 ? die( "pwritev" ) : 0;
    }
#ifdef SYS_preadv2
    if ( !strcmp( c, "preadv2" ) ) {
        fd = open( argv[ 2 ], O_RDONLY );
        iov.iov_base = buf;
        iov.iov_len = 8;
        return syscall( SYS_preadv2, fd, &iov, 1, 0, 0 ) < 0 ? die( "preadv2" ) : 0;
    }
    if ( !strcmp( c, "pwritev2" ) ) {
        fd = open( argv[ 2 ], O_WRONLY | O_CREAT, 0644 );
        iov.iov_base = ( void * )"p2";
        iov.iov_len = 2;
        return syscall( SYS_pwritev2, fd, &iov, 1, 0, 0 ) < 0 ? die( "pwritev2" ) : 0;
    }
#endif

    // --- fd aliasing / cwd ---------------------------------------------------
    if ( !strcmp( c, "dup3w" ) ) {
        fd = open( argv[ 2 ], O_WRONLY | O_CREAT, 0644 );
        dup3( fd, 9, 0 );
        return write( 9, "d3", 2 ) < 0 ? die( "dup3w" ) : 0;
    }
    if ( !strcmp( c, "fdupw" ) ) {
        fd = open( argv[ 2 ], O_WRONLY | O_CREAT, 0644 );
        int n = fcntl( fd, F_DUPFD, 10 );
        return write( n, "fd", 2 ) < 0 ? die( "fdupw" ) : 0;
    }
    if ( !strcmp( c, "fchdirw" ) ) {
        fd = open( argv[ 2 ], O_RDONLY );
        if ( fchdir( fd ) )
            return die( "fchdir" );
        return creat( argv[ 3 ], 0644 ) < 0 ? die( "fchdirw" ) : 0;
    }

    // --- namespace ops (traced as probes regardless of outcome) ---------------
    if ( !strcmp( c, "mount" ) )
        return mount( "none", argv[ 2 ], "tmpfs", 0, NULL ) < 0 ? die( "mount" ) : 0;
    if ( !strcmp( c, "umount" ) )
        return umount2( argv[ 2 ], 0 ) < 0 ? die( "umount" ) : 0;
    if ( !strcmp( c, "chroot" ) )
        return chroot( argv[ 2 ] ) < 0 ? die( "chroot" ) : 0;
    if ( !strcmp( c, "pivot" ) )
        return syscall( SYS_pivot_root, argv[ 2 ], argv[ 3 ] ) < 0 ? die( "pivot" ) : 0;

    // --- io_uring --------------------------------------------------------------
    if ( !strcmp( c, "iouring" ) ) {
        char params[ 120 ];
        memset( params, 0, sizeof params );
        long ring = syscall( 425, 8, params ); // io_uring_setup
        if ( ring < 0 )
            return die( "io_uring_setup" );
        int a = open( argv[ 2 ], O_RDONLY ), b = open( argv[ 3 ], O_RDONLY );
        int fds[ 3 ] = { a, b, -1 };
        syscall( 427, ring, 2, fds, 3 );          // IORING_REGISTER_FILES
        syscall( 426, ring, 0, 0, 0, NULL, 0 );   // io_uring_enter
        return 0;
    }

    // --- networking ------------------------------------------------------------
    if ( !strcmp( c, "listen" ) ) {
        int s = socket( AF_INET, SOCK_STREAM, 0 );
        struct sockaddr_in a = { 0 };
        a.sin_family = AF_INET;
        a.sin_port = htons( atoi( argv[ 2 ] ) );
        a.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
        if ( bind( s, ( void * )&a, sizeof a ) < 0 || listen( s, 1 ) < 0 )
            return die( "listen" );
        ret |= write( 1, "ready\n", 6 ) < 0;
        return accept( s, NULL, NULL ) < 0 ? die( "accept" ) : 0;
    }
    if ( !strcmp( c, "connect" ) ) {
        int s = socket( AF_INET, SOCK_STREAM, 0 );
        struct sockaddr_in a = { 0 };
        a.sin_family = AF_INET;
        a.sin_port = htons( atoi( argv[ 2 ] ) );
        a.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
        if ( connect( s, ( void * )&a, sizeof a ) < 0 )
            return die( "connect" );
        return 0;
    }

    fprintf( stderr, "harness: unknown subcommand %s\n", c );
    return 2;
}
