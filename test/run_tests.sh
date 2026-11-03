#!/usr/bin/env bash
# repdry end-to-end tests — run via `make test`.
# Each check runs repdry (answering the apply prompt via stdin) and greps
# the report/fixtures. Fixture dirs live under test/.run.* on the real fs
# (NOT /tmp — /tmp is a bound-empty dir inside the sandbox).
set -u
cd "$(dirname "$0")/.."
ROOT=$PWD
REPDRY="$ROOT/out/RepDry"
T="$ROOT/test/.run.$$"
mkdir -p "$T"
trap 'rm -rf "$T" 2>/dev/null' EXIT

P="$T/play"
mkdir -p "$P/sub" "$P/rodir" "$P/hidedir"
echo "0123456789" >"$P/mm.txt"
echo secret-content >"$P/hidedir/real.txt"
echo ro-content >"$P/rodir/orig.txt"
echo preexisting >"$P/old.txt"
echo futimesat-target >"$P/futimesat.txt"
echo link-target-content >"$P/linktarget.txt"
echo abcdefghijklmnop >"$P/src.txt"
ln -sf nonexistent "$P/dangling.lnk"

# --- harness binary for syscalls coreutils can't reach --------------------
H="$T/harness"
if ! gcc -O2 -Wall -o "$H" "$ROOT/test/harness.c" 2>"$T/gcc.log"; then
    echo "FATAL: harness build failed"
    cat "$T/gcc.log"
    exit 1
fi

n=0
ok=0
bad=0
rc=0
check() { # check <desc> <expr>
    n=$((n + 1))
    if eval "$2"; then
        ok=$((ok + 1))
        echo "ok $n - $1"
    else
        bad=$((bad + 1))
        echo "not ok $n - $1"
    fi
}
has() { grep -qF -- "$1" "$T/out"; }
sec() { awk -v t="$1" 'index($0,t" (")==1{f=1;next} /^[^ ]/ && / \([0-9]+\)$/{f=0} f' "$T/out"; }
RD()  { printf 'n\n' | "$REPDRY" "$@" >"$T/out" 2>&1; }
RDY() { printf 'y\n' | "$REPDRY" "$@" >"$T/out" 2>&1; }
snap() { ls -d /tmp/repdry.* 2>/dev/null | sort; }

# ==========================================================================
# CLI surface
# ==========================================================================
printf 'n\n' | "$REPDRY" --help >"$T/out" 2>&1; rc=$?
check "--help prints usage"              'has "usage: repdry" && [ $rc -eq 0 ]'
"$REPDRY" >"$T/out" 2>&1; rc=$?
check "missing -- fails with usage"      'has "usage: repdry" && [ $rc -eq 1 ]'
"$REPDRY" --bogus -- true >"$T/out" 2>&1; rc=$?
check "unknown flag rejected"            'has "repdry: unexpected arg: --bogus" && [ $rc -eq 1 ]'
RD -v -- true
check "-v dumps bwrap argv"              'has "repdry: bwrap --die-with-parent --unshare-all"'
RD -- sh -c 'exit 42'; rc=$?
check "payload exit code passthrough"    '[ $rc -eq 42 ]'

# ==========================================================================
# Apply prompt semantics
# ==========================================================================
RD -- true
check "no diff -> no prompt"             '! has "apply these changes"'
RD -- touch "$P/prompt.txt"
check "diff -> prompt shown"             'has "apply these changes to the real filesystem?"'
check "n -> not applying message"        'has "repdry: not applying; discarding changes"'
check "n -> file not created on host"    '[ ! -e "$P/prompt.txt" ]'
RDY -- touch "$P/yes.txt"
check "y -> file created on host"        '[ -f "$P/yes.txt" ]'
"$REPDRY" -- touch "$P/eof.txt" </dev/null >"$T/out" 2>&1
check "EOF -> discarded"                 'has "repdry: not applying" && [ ! -e "$P/eof.txt" ]'

# ==========================================================================
# Filesystem diff (authoritative half)
# ==========================================================================
RDY -- touch "$P/created.txt"
check "created file applied on y"        '[ -f "$P/created.txt" ]'
check "created listed in diff"           'sec "Created (sandbox only)" | grep -qF "created.txt"'
echo orig >"$P/mod.txt"
RDY -- sh -c "echo changed >'$P/mod.txt'"
check "modified file applied"            'grep -qF changed "$P/mod.txt"'
check "modified listed in diff"          'sec "Modified (sandbox only)" | grep -qF "mod.txt"'
echo doomed >"$P/del.txt"
RDY -- rm "$P/del.txt"
check "deleted file applied"             '[ ! -e "$P/del.txt" ]'
RDY -- rm "$P/old.txt"
check "delete listed in diff"            'sec "Deleted (sandbox only)" | grep -qF "old.txt"'
RDY -- mkdir "$P/newdir"
check "mkdir applied"                    '[ -d "$P/newdir" ]'
RDY -- mkdir "$P/gonedir"; RDY -- rmdir "$P/gonedir"
check "rmdir applied"                    '[ ! -e "$P/gonedir" ]'
echo mvsrc >"$P/mvsrc.txt"
RDY -- mv "$P/mvsrc.txt" "$P/mvdst.txt"
check "rename applied"                   '[ -f "$P/mvdst.txt" ] && [ ! -e "$P/mvsrc.txt" ]'
RDY -- ln -s /etc/hostname "$P/sym.lnk"
check "symlink applied as symlink"       '[ -L "$P/sym.lnk" ]'
RDY -- ln "$P/linktarget.txt" "$P/hard.lnk"
check "hardlink applied"                 '[ -f "$P/hard.lnk" ]'

# ==========================================================================
# Traced attribution (narrative half)
# ==========================================================================
RD -- touch "$P/t.txt"
check "touch -> Wrote (traced)"          'sec "Wrote (traced)" | grep -qE "t\.txt +by touch\("'
RD -- cat "$P/src.txt"
check "cat -> Read (splice path)"        'sec "Read" | grep -qE "src\.txt +by cat\("'
RD -- cp "$P/src.txt" "$P/cp.txt"
check "cp -> source read"                'sec "Read" | grep -qE "src\.txt +by cp\("'
check "cp -> dest write"                 'sec "Wrote (traced)" | grep -qE "cp\.txt +by cp\("'
RD -- cp --reflink "$P/src.txt" "$P/rf.txt"
check "cp --reflink (FICLONE ioctl)"     'sec "Wrote (traced)" | grep -qE "rf\.txt +by cp\("'
RD -- rm "$P/mm.txt"
check "rm -> Deleted (traced)"           'sec "Deleted (traced)" | grep -qE "mm\.txt +by rm\("'
RD -- mkdir "$P/mk.txt"
check "mkdir -> Wrote"                   'sec "Wrote (traced)" | grep -qE "mk\.txt +by mkdir\("'
RD -- ln -s a "$P/ln.txt"
check "symlinkat -> Wrote"               'sec "Wrote (traced)" | grep -qE "ln\.txt +by ln\("'
RD -- chmod 600 "$P/src.txt"
check "fchmodat -> Wrote"                'sec "Wrote (traced)" | grep -qE "src\.txt +by chmod\("'
RD -- truncate -s 0 "$P/src.txt"
check "truncate -> Wrote"                'sec "Wrote (traced)" | grep -qE "src\.txt +by truncate\("'
RD -- mkfifo "$P/fifo"
check "mknodat -> Wrote"                 'sec "Wrote (traced)" | grep -qE "fifo +by mkfifo\("'
RD -- touch -d @0 "$P/src.txt"
check "utimensat -> Wrote"               'sec "Wrote (traced)" | grep -qE "src\.txt +by touch\("'
RD -- stat "$P/src.txt"
check "statx -> Probed"                  'sec "Probed or statted only" | grep -qF "src.txt"'
RD -- stat "$P/does-not-exist"
check "missing file -> (missing)"        'sec "Probed or statted only" | grep -qF "(missing)"'
RD -- sh -c "[ -e '$P/src.txt' ]"
check "faccessat -> Probed"              'sec "Probed or statted only" | grep -qF "src.txt"'
RD -- ls "$P/sub"
check "getdents64 -> Read"               'sec "Read" | grep -qE "sub +by ls\("'
RD -- df "$P"
check "statfs -> Probed"                 'sec "Probed or statted only" | grep -qF "$P"'
RD -- readlink "$P/dangling.lnk"
check "readlinkat -> Probed"             'sec "Probed or statted only" | grep -qF "dangling.lnk"'
RD -- sh -c "cd '$P/sub' && touch rel.txt"
check "relative path resolved via cwd"   'sec "Created (sandbox only)" | grep -qF "sub/rel.txt"'
RD -- sh -c "exec 9>'$P/viafd.txt'; echo hi >&9"
check "dup2'd fd write attributed"       'sec "Wrote (traced)" | grep -qF "viafd.txt"'
RD --full -- true
check "mmap'd ld.so.cache -> Read"       'sec "Read" | grep -qF "ld.so.cache"'
RD -- touch "$P/x.txt"
check "Executed shows payload"           'sec "Executed" | grep -qF "bin/touch"'
check "Executed hides bwrap"             '! sec "Executed" | grep -q bwrap'
check "no bwrap attributions"            '! grep -q "by bwrap(" "$T/out"'
# The inner bwrap can't actually unshare userns inside our sandbox (Ubuntu's
# unprivileged-userns restriction applies to nested execs too), but its exec
# and activity must be attributed as payload — unlike the outer bwrap.
RD -- sh -c "bwrap --ro-bind / / --tmpfs /tmp -- touch /tmp/inner.txt"
check "nested bwrap exec attributed"     'sec "Executed" | grep -qF "bin/bwrap"'
check "nested bwrap activity = payload"  'grep -q "by bwrap(" "$T/out"'

# ==========================================================================
# Harness-driven syscall coverage
# ==========================================================================
RD -- "$H" mmapr "$P/src.txt"
check "mmap read -> Read"                'sec "Read" | grep -qF "src.txt"'
RDY -- "$H" mmapw "$P/mm.txt"
check "mmap MAP_SHARED write -> Wrote"   'sec "Wrote (traced)" | grep -qF "mm.txt"'
check "mmap write applied to host"       'grep -qF MAPW "$P/mm.txt"'
RD -- "$H" creat "$P/cr.txt"
check "creat -> Wrote"                   'sec "Wrote (traced)" | grep -qF "cr.txt"'
RD -- "$H" mknod "$P/node"
check "mknod -> Wrote"                   'sec "Wrote (traced)" | grep -qF "node"'
RD -- "$H" vmsplice "$P/vm.txt"
check "vmsplice -> Wrote"                'sec "Wrote (traced)" | grep -qF "vm.txt"'
RD -- "$H" sendfile "$P/src.txt" "$P/sf.txt"
check "sendfile -> read+write"           'sec "Read" | grep -qF "src.txt" && sec "Wrote (traced)" | grep -qF "sf.txt"'
RD -- "$H" fallocate "$P/fa.txt"
check "fallocate -> Wrote"               'sec "Wrote (traced)" | grep -qF "fa.txt"'
RD -- "$H" futimens "$P/fu.txt"
check "futimens (NULL path, no crash)"   'sec "Wrote (traced)" | grep -qF "fu.txt"'
RD -- "$H" futimesat "$P" futimesat.txt
check "futimesat -> Wrote"               'sec "Wrote (traced)" | grep -qF "futimesat.txt"'
RD -- "$H" fchmod "$P/src.txt"
check "fchmod -> Wrote"                  'sec "Wrote (traced)" | grep -qF "src.txt"'
RD -- "$H" fchown "$P/src.txt"
check "fchown -> Wrote"                  'sec "Wrote (traced)" | grep -qF "src.txt"'
RD -- "$H" ftrunc "$P/src.txt"
check "ftruncate -> Wrote"               'sec "Wrote (traced)" | grep -qF "src.txt"'
RD -- "$H" legacymeta "$P/src.txt"
check "utime/utimes/lchown/chown -> Wrote" 'sec "Wrote (traced)" | grep -qF "src.txt"'
RD -- "$H" legacyprobe "$P/src.txt"
check "access/stat/lstat -> Probed"      'sec "Probed or statted only" | grep -qF "src.txt"'
RD -- "$H" legacy "$P/src.txt"
check "link/symlink/rename/unlink"       'sec "Wrote (traced)" | grep -qF "src.txt.r" && sec "Deleted (traced)" | grep -qF "src.txt"'
RD -- "$H" fstat "$P/src.txt"
check "fstat -> Probed"                  'sec "Probed or statted only" | grep -qF "src.txt"'
RD -- "$H" fstatfs "$P"
check "fstatfs -> Probed"                'sec "Probed or statted only" | grep -qF "$P"'
RD -- "$H" getdents "$P/sub"
check "getdents -> Read"                 'sec "Read" | grep -qF "sub"'
RD -- "$H" finitmod "$P/src.txt"
check "finit_module -> Read"             'sec "Read" | grep -qF "src.txt"'
RD -- "$H" xattr "$P/src.txt"
check "setxattr et al -> Wrote"          'sec "Wrote (traced)" | grep -qF "src.txt"'
RD -- "$H" fxattr "$P/src.txt"
check "fsetxattr et al -> Wrote"         'sec "Wrote (traced)" | grep -qF "src.txt"'
RD -- "$H" xattrat "$P/src.txt"
check "setxattrat -> Wrote"              'sec "Wrote (traced)" | grep -qF "src.txt"'
RD -- "$H" openat2 "$P/src.txt"
check "openat2 -> Probed"                'sec "Probed or statted only" | grep -qF "src.txt"'
RD -- "$H" execveat /bin/true
check "execveat -> Executed"             'sec "Executed" | grep -qF "bin/true"'
RD -- "$H" execveat_empty
check "execveat AT_EMPTY_PATH -> Executed" 'sec "Executed" | grep -qF "bin/true"'
RD -- "$H" pread "$P/src.txt"
check "pread -> Read"                    'sec "Read" | grep -qF "src.txt"'
RD -- "$H" pwrite "$P/pw.txt"
check "pwrite -> Wrote"                  'sec "Wrote (traced)" | grep -qF "pw.txt"'
RD -- "$H" readv "$P/src.txt"
check "readv -> Read"                    'sec "Read" | grep -qF "src.txt"'
RD -- "$H" writev "$P/wv.txt"
check "writev -> Wrote"                  'sec "Wrote (traced)" | grep -qF "wv.txt"'
RD -- "$H" preadv "$P/src.txt"
check "preadv -> Read"                   'sec "Read" | grep -qF "src.txt"'
RD -- "$H" pwritev "$P/pv.txt"
check "pwritev -> Wrote"                 'sec "Wrote (traced)" | grep -qF "pv.txt"'
RD -- "$H" preadv2 "$P/src.txt"
check "preadv2 -> Read"                  'sec "Read" | grep -qF "src.txt"'
RD -- "$H" pwritev2 "$P/p2.txt"
check "pwritev2 -> Wrote"                'sec "Wrote (traced)" | grep -qF "p2.txt"'
RD -- "$H" dup3w "$P/d3.txt"
check "dup3 aliased write -> Wrote"      'sec "Wrote (traced)" | grep -qF "d3.txt"'
RD -- "$H" fdupw "$P/fd.txt"
check "fcntl F_DUPFD write -> Wrote"     'sec "Wrote (traced)" | grep -qF "fd.txt"'
RD -- "$H" fchdirw "$P/sub" fcd.txt
check "fchdir cwd -> resolved path"      'sec "Wrote (traced)" | grep -qF "sub/fcd.txt"'
RD -- "$H" mount "$P/sub"
check "mount -> Probed"                  'sec "Probed or statted only" | grep -qF "sub"'
RD -- "$H" umount "$P/sub"
check "umount2 -> Probed"                'sec "Probed or statted only" | grep -qF "sub"'
RD -- "$H" chroot "$P/sub"
check "chroot -> Probed"                 'sec "Probed or statted only" | grep -qF "sub"'
RD -- "$H" pivot "$P/sub" "$P"
check "pivot_root -> Probed"             'sec "Probed or statted only" | grep -qF "sub"'
RD -- "$H" iouring /etc/hostname /etc/os-release
check "io_uring detected"                'sec "io_uring detected" | grep -qF "ring I/O invisible"'
check "io_uring registered files listed" 'sec "io_uring detected" | grep -qF "/etc/hostname"'

# ==========================================================================
# Flags
# ==========================================================================
RD --ignore '.*secretfile.*' -- touch "$P/secretfile.txt"
check "--ignore drops traced attribution" '! sec "Wrote (traced)" | grep -qF "secretfile"'
check "--ignore keeps real diff visible" 'sec "Created (sandbox only)" | grep -qF "secretfile"'
RD -- cat "$P/src.txt"
check "default hides ld.so.cache read"   '! sec "Read" | grep -qF "ld.so.cache"'
check "default keeps real reads"         'sec "Read" | grep -qF "src.txt"'
check "default reports hidden count"     'grep -q "common low-risk rows hidden" "$T/out"'
RD -- sh -c "echo hi >/dev/null; echo hi >'$P/dev.txt'"
check "default hides /dev/null write"    '! sec "Wrote (traced)" | grep -qF "/dev/null"'
check "default keeps real writes"        'sec "Wrote (traced)" | grep -qF "dev.txt"'
RD -- stat /etc/passwd "$P/src.txt"
check "default hides /etc/passwd read"   '! sec "Read" | grep -qF "/etc/passwd"'
check "default keeps real probes"        'sec "Probed or statted only" | grep -qF "src.txt"'
check "default keeps Executed"           'sec "Executed" | grep -qF "bin/stat"'
RD --full -- sh -c "echo hi >/dev/null"
check "--full shows /dev/null write"     'sec "Wrote (traced)" | grep -qF "/dev/null"'
check "--full prints no hidden count"    '! grep -q "common low-risk rows hidden" "$T/out"'
RD --full -- stat /etc/passwd
check "--full shows /etc/passwd read"    'sec "Read" | grep -qF "/etc/passwd"'
check "--full shows ld.so.preload probe" 'sec "Probed or statted only" | grep -qF "/etc/ld.so.preload"'
RD --ro "$P/rodir" -- sh -c "cat '$P/rodir/orig.txt'; echo changed >'$P/rodir/orig.txt'; cat '$P/rodir/orig.txt'"
check "--ro: real content readable"      'grep -qF ro-content "$T/out"'
check "--ro: write reads back in-sandbox" 'grep -qF changed "$T/out"'
check "--ro: write marked discarded"     'sec "Wrote (traced)" | grep -qF "(discarded)"'
check "--ro: host file unchanged"        'grep -qF ro-content "$P/rodir/orig.txt"'
RDY --ro "$P/rodir" -- sh -c "echo changed >'$P/rodir/orig.txt'"
check "--ro: y applies nothing"          'grep -qF ro-content "$P/rodir/orig.txt" && ! has "apply these changes"'
RD --hide "$P/hidedir" -- sh -c "cat '$P/hidedir/real.txt' 2>&1; echo wrote >'$P/hidedir/new.txt'; cat '$P/hidedir/new.txt'"
check "--hide: real file invisible"      'grep -qF "No such file" "$T/out"'
check "--hide: write readable in-run"    'grep -qxF "wrote" "$T/out"'
check "--hide: write marked discarded"   'sec "Wrote (traced)" | grep -qF "(discarded)"'
check "--hide: host dir untouched"       '[ "$(ls "$P/hidedir")" = "real.txt" ]'

# ==========================================================================
# Networking
# ==========================================================================
PORT=$((20000 + $$ % 25000))
"$H" listen "$PORT" >"$T/listen.out" 2>&1 &
LPID=$!
for _ in $(seq 30); do grep -q ready "$T/listen.out" 2>/dev/null && break; sleep 0.1; done
RDY --allow-net -- "$H" connect "$PORT"; rc=$?
check "--allow-net: connect succeeds"    '[ $rc -eq 0 ]'
check "--allow-net: connect reported"    'sec "Network connects" | grep -qF "127.0.0.1:'$PORT'"'
wait $LPID 2>/dev/null
RD -- "$H" connect "$PORT"; rc=$?
check "default: connect fails (no net)"  '[ $rc -ne 0 ]'
check "default: attempt still reported"  'sec "Network connects" | grep -qF "127.0.0.1:'$PORT'"'

# ==========================================================================
# Scratch cleanup
# ==========================================================================
snap >"$T/sb"
RD -- touch "$P/cl.txt"
snap >"$T/sa"
check "normal run leaves no scratch"     '[ -z "$(comm -13 "$T/sb" "$T/sa")" ]'

snap >"$T/sb2"
"$REPDRY" -- sleep 30 >/dev/null 2>&1 &
RD_PID=$!
sleep 0.8
snap >"$T/sa2"
newdir=$(comm -13 "$T/sb2" "$T/sa2" | head -1)
check "scratch dir exists mid-run"       '[ -n "$newdir" ]'
kill -9 $RD_PID 2>/dev/null
sleep 0.8
check "SIGKILL: babysitter wipes scratch" '[ -z "$newdir" ] || [ ! -d "$newdir" ]'

# ==========================================================================
echo
echo "$n checks, $ok passed, $bad failed"
[ $bad -eq 0 ]
