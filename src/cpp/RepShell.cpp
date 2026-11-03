#include <string.h>
#include <sstream>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <unistd.h>
#include <sys/stat.h>

#include <iostream>
#include <queue>
#include <set>
#include <map>
#include <fstream>
#include <regex>

#include "utils.hpp"
#include "logging.hpp"
#include "rules.hpp"
#include "sys_map.hpp"
#include "tracer.hpp"

#include "RepShellLexer.h"
#include "RepShellParser.h"
#include "antlr4-runtime.h"

using namespace antlr4;
using namespace antlr4::tree;

#define REP_DEP_FILE_NAME "RepDep.d"

static const std::vector<int> trace_syscalls = {
    SYS_read, SYS_openat, SYS_access, SYS_execve, SYS_newfstatat, SYS_unlinkat,
};

// Support nested trace?
// https://stackoverflow.com/questions/2359581/calling-ptrace-inside-a-ptraced-linux-process
static void sigchld_handler( int sig ) {
    int result, status;
    pid_t child_pid = wait( &status ); // find who send us this SIGCHLD

    printf( "%d received SIGCHLD on %d\n", getpid( ), child_pid );
    if ( WIFSTOPPED( status ) ) {
        result = ptrace( PTRACE_CONT, child_pid, 0, WSTOPSIG( status ) );
        if ( result ) {
            perror( "continuing after SIGCHLD" );
        }
    }
}

static int traceBash( pid_t child, pid_t current_pid, Rule &new_rules, const std::vector<std::regex> &ignore ) {
    int status;
    const char **sysmap = getSysMap( );
    std::map<long, std::string> fd_path_map;
    while ( 1 ) {
        ptrace( PTRACE_CONT, current_pid, 0, 0 );

        current_pid = waitpid( 0, &status, 0 );
        // pr_debug( "PID:%d", current_pid );

        if ( WIFEXITED( status ) ) {
            int child_status = WEXITSTATUS( status );
            if ( current_pid == child ) {
                // pr_debug( "Child quit!" );
                return child_status;
            } else {
                // pr_debug("[Proc exit with status %d]", child_status);
                continue;
            }
        }

        int isSECTrap = status >> 8 == ( SIGTRAP | ( PTRACE_EVENT_SECCOMP << 8 ) );
        if ( !isSECTrap ) {
            continue;
        }
        struct user_regs_struct regs;
        if ( ptrace( PTRACE_GETREGS, current_pid, 0, &regs ) == -1 ) {
            if ( errno == ESRCH ) {
                pr_debug( "Child is exiting:%d: %s", errno, strerror( errno ) );
            } else {
                pr_debug( "Get Regs Error %d: %s", errno, strerror( errno ) );
            }
        }
        long syscall = regs.orig_rax;

        bool hasPathAddr = false;
        long pathAddr = -1;

        bool hasFd = false;
        long fdValue = -1;

        bool addFileAsDep = false;
        bool removeFileAsDep = false;
        bool trackFile = false;
        bool unTrackFile = false;

        bool mayBeTarget = false;
        if ( syscall == SYS_unlinkat ) {
            hasPathAddr = true;
            pathAddr = regs.rsi;
        } else if ( syscall == SYS_execve ) {
            hasPathAddr = true;
            pathAddr = regs.rdi;
            addFileAsDep = true;
            // } else if ( syscall == SYS_close ) {
            //     hasFd = true;
            //     fdValue = regs.rdi;
            //     unTrackFile = true;
        } else if ( syscall == SYS_read ) {
            hasFd = true;
            fdValue = regs.rdi;
            addFileAsDep = true;
        } else if ( syscall == SYS_access ) {
            hasPathAddr = true;
            pathAddr = regs.rdi;
            addFileAsDep = true;
        } else if ( syscall == SYS_newfstatat ) {
            bool isRelativeFile = ( int )regs.rdi == AT_FDCWD;
            if ( !isRelativeFile ) {
                // Not a relitive path, it's something strange give up.
                continue;
            }
            hasPathAddr = true;
            pathAddr = regs.rsi;
            trackFile = true;
        } else if ( syscall == SYS_openat ) {
            bool isRelativeFile = ( int )regs.rdi == AT_FDCWD;
            if ( !isRelativeFile ) {
                // Not a relitive path, it's something strange give up.
                continue;
            }
            hasPathAddr = true;
            pathAddr = regs.rsi;

            long flags = regs.rdx;
            // char flags_str[1024];
            // flagsToString(flags, flags_str, sizeof(flags_str));
            if ( ( flags & O_ACCMODE ) == O_RDONLY ) {
                // isRead = true;
                // doTrackFD = true;
                trackFile = true;
            } else if ( ( flags & O_ACCMODE ) == O_WRONLY ) {
                mayBeTarget = true;
            } else if ( ( flags & O_ACCMODE ) == O_RDWR ) {
                mayBeTarget = true;
                trackFile = true;
            }
        } else {
            // Some other syscall, we don't care.
            continue;
        }
        // if ( trackFile && unTrackFile ) {
        //     pr_debug( "Can't track and untrack" );
        //     exit( 1 );
        // }
        if ( hasPathAddr && hasFd ) {
            pr_debug( "Not expected to have both parts of file" );
            exit( 1 );
        }
        std::string orig_file;
        if ( hasPathAddr ) {
            char orig_file_from_addr[ PATH_MAX ];
            tracer::read_file( current_pid, pathAddr, orig_file_from_addr );
            orig_file = orig_file_from_addr;
        }
        if ( hasFd ) {
            auto iter = fd_path_map.find( fdValue );
            if ( iter != fd_path_map.end( ) ) {
                orig_file = iter->second;
            }
        }
        // pr_debug( "Got file:%ld %s", fdValue, orig_file.c_str( ) );
        if ( orig_file.empty( ) ) {
            // We don't know what this is
            // pr_debug( "Dont know" );
            continue;
        }
        bool isDir = false;
        if ( true ) {
            // char resolved_path[ PATH_MAX ];
            // realpath( orig_file, resolved_path );
            // const char *prefix_strs[] = { "/tmp/", "/usr/", "/etc/", "/lib/", "/dev/", "/sys/", "/proc/", "/run/", "/snap/", NULL };
            std::vector<std::string> prefix_strs = { "/" }; // any non relative files.
            // const char* prefix_strs[] = {NULL};
            if ( str_startsWith( orig_file, prefix_strs ) ) {
                // Starts with a path we don't care about.
                continue;
            }
            std::vector<std::string> equal_strs = { "/tmp", "." };
            // const char* equal_strs[] = {NULL};
            if ( str_equalsAny( orig_file, equal_strs ) ) {
                // Starts with a path we don't care about.
                continue;
            }
            // pr_debug( "WroteFile: orig_file: \"%s\"  resolved: \"%s\"", orig_file, resolved_path );
            // pr_debug( "" );
            if ( tracer::matchsAnyIgnore( orig_file, ignore ) ) {
                // Bad file
                // pr_debug( "Bad file:%s", orig_file );
                continue;
            }

            // int fd = openat( AT_FDCWD, resolved_path, O_RDONLY );
            // bool file_avail = fd >= 0;
            // close( fd );
            struct stat statbuf;
            isDir = false;
            if ( stat( orig_file.c_str( ), &statbuf ) == 0 ) {
                isDir = S_ISDIR( statbuf.st_mode );
            }
            if ( isDir ) {
                continue; // I thinik?
            }
        }

        long syscall_ret = 0;
        // TODO track all syscall_ret per file.
        //  if the final child fails:
        // make all files sus deps
        // if the file child success:
        // only mark files that exist as sus deps
        if ( trackFile ) {
            syscall_ret = tracer::waitForSyscallRet( current_pid );
            // pr_debug( "Tracking:%ld: %s", syscall_ret, orig_file.c_str( ) );
            fd_path_map[ syscall_ret ] = orig_file;
            new_rules.sus_deps.insert( orig_file ).second;
        }
        if ( mayBeTarget && new_rules.name.empty( ) ) {
            new_rules.name = orig_file;
        }

        if ( removeFileAsDep ) {
            new_rules.real_deps.erase( orig_file );
            new_rules.sus_deps.erase( orig_file );
        }
        if ( addFileAsDep ) {
            bool actuallyInserted = new_rules.real_deps.insert( orig_file ).second;
            if ( !actuallyInserted ) {
                continue;
            }
        }
        // if ( isRead ) {
        //     new_rules.deps.insert( orig_file );
        // }

        // if ( isDelete ) {
        //     new_rules.deps.erase( orig_file );
        // }

        pr_debug( "Access: track:%d add:%d remove:%d dir:%d %s \"%s\"", trackFile, addFileAsDep, removeFileAsDep, isDir, sysmap[ syscall ], orig_file.c_str( ) );
    }
}

std::pair<char *, std::streampos> readEntireFile( const char *inputFile ) {
    std::ifstream stream;
    stream.open( inputFile );
    stream.seekg( 0, std::ios::end );
    std::streampos fileSize = stream.tellg( );
    fileSize += 1;
    stream.seekg( 0, std::ios::beg );

    char *buffer = new char[ fileSize ];
    // Add a new line since i couldn't figure out how to write my rule without needing start of line token.
    // Use \n instead of \n so it doesn't offset the line count (kinda hacky, but works).
    buffer[ 0 ] = '\r';
    stream.read( &buffer[ 1 ], fileSize );
    return { buffer, fileSize };
}

bool parseExistingRules( std::set<Rule> &all_rules, const std::vector<std::regex> &ignore ) {
    const char *inputFile = "RepDep.d";
    auto inputBuffer = readEntireFile( inputFile );
    ANTLRInputStream input( inputBuffer.first, inputBuffer.second );
    delete[] inputBuffer.first;
    input.name = REP_DEP_FILE_NAME;
    RepShellLexer lexer( &input );
    CommonTokenStream tokens( &lexer );
    RepShellParser parser( &tokens );
    if ( parser.getNumberOfSyntaxErrors( ) != 0 ) {
        return 1;
    }
    auto context = parser.repshell( );
    if ( parser.repshell( ) == NULL ) {
        return 1;
    }

    std::vector<RepShellParser::Rep_shell_ruleContext *> parseRules = context->rep_shell_rule( );
    for ( RepShellParser::Rep_shell_ruleContext *const parseRule : parseRules ) {
        std::string rule_name = parseRule->rule_name( )->IDENTIFIER( )->getText( );
        if ( tracer::matchsAnyIgnore( rule_name, ignore ) ) {
            continue;
        }

        std::set<Rule>::iterator iter = all_rules.find( rule_name );

        std::set<std::string> *real_deps;
        std::set<std::string> *sus_deps;
        if ( iter != all_rules.end( ) ) {
            // Already exists in rules, add the deps we found, if any.
            const Rule &previous_rule = *iter;
            // Cast away const since the deps of a rules don't impact the hash of the item in the set.
            Rule &editable_rules = const_cast<Rule &>( previous_rule );
            real_deps = &editable_rules.real_deps;
            sus_deps = &editable_rules.sus_deps;
        } else {
            // Rule is new, add it to the set;
            auto it = all_rules.emplace( rule_name );
            const Rule &emplaced_rule = *it.first;
            // Cast away const since the deps of a rules don't impact the hash of the item in the set.
            Rule &editable_rules = const_cast<Rule &>( emplaced_rule );
            real_deps = &editable_rules.real_deps;
            sus_deps = &editable_rules.sus_deps;
        }

        auto parseRealDepList = parseRule->real_dependency_list( );
        if ( parseRealDepList != NULL ) {
            std::vector<RepShellParser::Rule_nameContext *> parseRealDeps = parseRealDepList->rule_name( );
            for ( RepShellParser::Rule_nameContext *parseRealDep : parseRealDeps ) {
                std::string parseRealDepName = parseRealDep->IDENTIFIER( )->getText( );
                if ( tracer::matchsAnyIgnore( parseRealDepName, ignore ) ) {
                    continue;
                }
                // pr_debug( "Dep for rule \"%s\": \"%s\" real", rule_name.c_str( ), parseRealDepName.c_str( ) );
                real_deps->insert( parseRealDepName );
            }
        }
        auto parseSusDepList = parseRule->sus_dependency_list( );
        if ( parseSusDepList != NULL ) {
            std::vector<RepShellParser::Rule_nameContext *> parseSusDeps = parseSusDepList->rule_name( );
            for ( RepShellParser::Rule_nameContext *parseSusDep : parseSusDeps ) {
                std::string parseSusDepName = parseSusDep->IDENTIFIER( )->getText( );
                if ( tracer::matchsAnyIgnore( parseSusDepName, ignore ) ) {
                    continue;
                }
                if ( real_deps->find( parseSusDepName ) != real_deps->end( ) ) {
                    // pr_debug( "Dep for rule \"%s\": \"%s\" DUPE", rule_name.c_str( ), parseSusDepName.c_str( ) );
                    continue;
                }
                // pr_debug( "Dep for rule \"%s\": \"%s\" sus", rule_name.c_str( ), parseSusDepName.c_str( ) );
                sus_deps->insert( parseSusDepName );
            }
        }
    }
    return 0;
}

int main( int argc, char *argv[] ) {
    // pr_debug_raw( "Args: " );
    // for ( int i = 0; i < argc; i++ ) {
    //     pr_debug_raw( "%s ", argv[ i ] );
    // }
    // pr_debug_raw( "\n" );

    // if ( false ) {
    //     char proc_str[ 64 ];
    //     char cmdLine[ PATH_MAX ];
    //     FILE *proc_file;
    //     pid_t parent_pid = getppid( );
    //     pr_debug( "Parent pid:%d", parent_pid );

    //     snprintf( proc_str, PATH_MAX, "/proc/%i/cmdline", parent_pid );
    //     proc_file = fopen( proc_str, "r" );
    //     fgets( cmdLine, PATH_MAX, proc_file );
    //     fclose( proc_file );
    //     pr_debug( "Parent cmdline:%s", cmdLine );

    //     // This can be used to re-exec make.
    //     sprintf( proc_str, "/proc/%i/exe", parent_pid );
    // }

    std::vector<std::regex> ignore_files;
    bool pendingDashTask = false;
    bool pendingDashIgnore = false;
    bool pendingDashShell = false;
    bool foundArgEndMarker = false;
    const char *task = NULL;
    const char *shell = NULL;
    int i;
    for ( i = 1; i < argc; i++ ) {
        const char *arg = argv[ i ];
        // pr_debug( "Arg:%d %s", i, arg );
        if ( strncmp( "--", arg, 3 ) == 0 ) {
            foundArgEndMarker = true;
            break;
        } else if ( pendingDashTask ) {
            task = arg;
            pendingDashTask = false;
        } else if ( pendingDashIgnore ) {
            // pr_debug( "Ignore:%s", arg );
            ignore_files.emplace_back( arg );
            pendingDashIgnore = false;
        } else if ( pendingDashShell ) {
            shell = arg;
            pendingDashShell = false;
        } else if ( strcmp( "--task", arg ) == 0 ) {
            pendingDashIgnore = false;
            pendingDashTask = true;
            pendingDashShell = false;
        } else if ( strcmp( "--shell", arg ) == 0 ) {
            pendingDashIgnore = false;
            pendingDashTask = false;
            pendingDashShell = true;
        } else if ( strcmp( "--ignore", arg ) == 0 ) {
            pendingDashIgnore = true;
            pendingDashTask = false;
            pendingDashShell = false;

        } else {
            pr_debug( "Unexpected arg:%s", arg );
            return 1;
        }
    }
    if ( !foundArgEndMarker ) {
        pr_debug( "uage: RepShell [--task task_name] -- [shell args...]" );
        return 1;
    }
    if ( i == argc - 1 ) {
        pr_debug( "No args to shell given." );
        return 1;
    }
    int argEndMarker = i;

    if ( task == NULL ) {
        pr_debug( "Traceing Unknown" );
        task = "";
    } else {
        pr_debug( "Traceing task: %s", task );
    }
    if ( shell == NULL ) {
        shell = "bash";
    }

    pid_t pid = fork( );
    if ( pid == -1 ) {
        std::cout << "Fork error" << std::endl;
    }
    if ( pid == 0 ) {
        char *shell_copy = strdup( shell );
        argv[ argEndMarker ] = shell_copy;
        tracer::runTracedExec( &argv[ argEndMarker ], trace_syscalls );
        free( shell_copy );
        exit( 0 );
    }
    int status;
    waitpid( pid, &status, 0 );
    ptrace( PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK );

    Rule new_rule( task );

    int childRet = traceBash( pid, pid, new_rule, ignore_files );

    int fd = open( REP_DEP_FILE_NAME, O_RDWR | O_CREAT, 0666 );
    int rc = flock( fd, LOCK_EX );
    if ( rc ) {
        pr_debug( "Flock failed:%d errno:%d: %s", rc, errno, strerror( errno ) );
        close( fd );
        return rc;
    }

    std::set<Rule> all_rules; // TODO parse out previous rules.
    parseExistingRules( all_rules, ignore_files );

    new_rule.real_deps.erase( new_rule.name ); // Don't set a rule depend on itself.
    new_rule.sus_deps.erase( new_rule.name );  // Don't set a rule depend on itself.

    std::set<Rule>::iterator iter = all_rules.find( new_rule );
    if ( iter != all_rules.end( ) ) {
        // Already exists in rules, add the deps we found, if any.
        const Rule &previous_rule = *iter;
        // Cast away const since the deps of a rules don't impact the hash of the item in the set.
        Rule &editable_rules = const_cast<Rule &>( previous_rule );
        editable_rules.real_deps.insert( new_rule.real_deps.begin( ), new_rule.real_deps.end( ) );
        editable_rules.sus_deps.insert( new_rule.sus_deps.begin( ), new_rule.sus_deps.end( ) );
    } else {
        // Rule is new, add it to the set;
        all_rules.insert( new_rule );
    }

    std::ofstream rep_dep_out( "RepDep.d" );
    std::set<std::string> all_deps;

    rep_dep_out << ".PHONY: REP_SPACE" << std::endl;

    for ( const Rule &rule : all_rules ) {
        if ( rule.name.empty( ) ) {
            // pr_debug_raw( "Empty: " );
            // for ( const auto &dep : rule.deps ) {
            //     pr_debug_raw( "%s ", dep.c_str( ) );
            // }
            // pr_debug( "" );
            continue;
        }
        int total_size = rule.real_deps.size( );
        if ( childRet != 0 ) {
            total_size += rule.sus_deps.size( );
        }
        if ( total_size == 0 ) {
            continue;
        }

        rep_dep_out << rule.name << ":";
        for ( const auto &dep : rule.real_deps ) {
            rep_dep_out << " " << dep;
            all_deps.insert( dep );
        }
        if ( childRet != 0 ) {
            if ( rule.sus_deps.size( ) > 0 ) {
                rep_dep_out << " REP_SPACE";
                for ( const auto &dep : rule.sus_deps ) {
                    rep_dep_out << " " << dep;
                    all_deps.insert( dep );
                }
            }
        }
        rep_dep_out << std::endl;
    }
    rep_dep_out << std::endl;
    for ( const auto &dep : all_deps ) {
        rep_dep_out << dep << ":" << std::endl;
    }
    rep_dep_out << std::endl;
    rep_dep_out.close( );
    flock( fd, LOCK_UN );
    close( fd );

    // pr_debug( "Exiting with:%d (%s)", ret, strerror( ret ) );
    return childRet;
}
