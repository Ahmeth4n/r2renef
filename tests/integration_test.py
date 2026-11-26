#!/usr/bin/env python3
"""End-to-end tests: the real `r2` binary + the built plugin + a mock renef_server.

    python3 tests/integration_test.py --plugin build/io_renef.dylib [-k name] [-v]

Nothing is installed: the plugin file is handed to r2 with -I (r2 >= 6 has
no -l any more; -I runs before the file is opened, and a shared object
given to it is loaded as a plugin). User settings are skipped with -N.

Every test starts its own tests/mock_renef_server.py on a free port (never
1907) and most of them run twice, against a framing-aware server and
against a legacy one. The mock executes the Lua the plugin sends in a real
interpreter, so it needs `lua` (5.4 or newer) on PATH, or $LUA; without
one the run is skipped with exit status 77.
"""

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.dont_write_bytecode = True   # no __pycache__ in the source tree
import mock_renef_server as mock  # noqa: E402

LIBC = mock.LIBC_BASE
TARGET = mock.LIBTARGET_BASE
CRYPTO = mock.LIBCRYPTO_BASE
HEAP = mock.HEAP_BASE
STACK = 0x7ff0000000

ARGS = None
VERBOSE = False


class Result:
    def __init__(self, out, err, rc, log):
        self.out, self.err, self.rc, self.log = out, err, rc, log

    def events(self, ev):
        return [e for e in self.log if e.get("ev") == ev]

    def cmds(self, name=None):
        return [e for e in self.events("cmd") if name is None or e["name"] == name]


class Mock:
    def __init__(self, mode, *extra):
        self.tmp = tempfile.mkdtemp(prefix="r2renef_it_")
        self.logpath = os.path.join(self.tmp, "mock.log")
        self.proc = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "mock_renef_server.py"), "--port", "0", "--mode", mode,
             "--lua", ARGS.lua, "--log", self.logpath] + list(extra),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = self.proc.stdout.readline()
        if not line.startswith("LISTENING"):
            raise RuntimeError("mock server did not start: " + line + self.proc.stderr.read())
        self.port = int(line.split()[1])

    def log(self):
        if not os.path.exists(self.logpath):
            return []
        with open(self.logpath) as f:
            return [json.loads(l) for l in f if l.strip()]

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self.tmp, ignore_errors=True)


def r2_env(port, env=None):
    e = dict(os.environ)
    for k in list(e):
        if k.startswith("RENEF_"):
            del e[k]
    if port:
        e["RENEF_PORT"] = str(port)
    e.update(env or {})
    if ARGS.sanitizer_runtime:
        # a plugin built with -fsanitize=address needs its runtime loaded first
        e["DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD"] = ARGS.sanitizer_runtime
        e["ASAN_OPTIONS"] = "detect_leaks=0"
    return e


def r2_argv(cmds, uri):
    argv = [ARGS.r2, "-N", "-e", "scr.color=0", "-e", "scr.interactive=false", "-I", ARGS.plugin, "-q"]
    for c in cmds:
        argv += ["-c", c]
    return argv + [uri]


def no_sanitizer_report(err):
    if "AddressSanitizer" in err or "runtime error:" in err:
        raise Failure("sanitizer report:\n" + err[-4000:])


def run_r2(port, cmds, env=None, uri="renef://spawn/com.example.app", timeout=90):
    p = subprocess.run(r2_argv(cmds, uri), env=r2_env(port, env), stdin=subprocess.DEVNULL,
                       capture_output=True, timeout=timeout)
    err = p.stderr.decode("utf-8", "replace")
    no_sanitizer_report(err)
    return p.stdout.decode("utf-8", "replace"), err, p.returncode


def session(mode, cmds, mock_args=(), env=None, uri="renef://spawn/com.example.app", crash_ok=False):
    """one mock server, one r2 run -> Result"""
    m = Mock(mode, *mock_args)
    try:
        out, err, rc = run_r2(m.port, cmds, env, uri)
        time.sleep(0.05)
        res = Result(out, err, rc, m.log())
    finally:
        m.stop()
    if VERBOSE:
        print("---- stdout\n" + res.out + "---- stderr\n" + res.err)
    if not crash_ok:
        check(not res.events("crash"), "the fake target crashed: %r" % res.events("crash"))
    return res


class Failure(Exception):
    pass


def check(cond, msg):
    if not cond:
        raise Failure(msg)


def has(text, needle, what="output"):
    check(needle in text, "%s lacks %r\n--- got:\n%s" % (what, needle, text[-3000:]))


def lacks(text, needle, what="output"):
    check(needle not in text, "%s unexpectedly has %r\n--- got:\n%s" % (what, needle, text[-3000:]))


def lines(text):
    return [l for l in text.split("\n") if l]


def pattern(size, seed):
    return mock.FakeProcess._pattern(size, seed)


# ---------------------------------------------------------------- tests
# each takes the server mode; MODES lists the modes it runs in

def t_open(mode):
    r = session(mode, ["s", "e asm.arch", "e asm.bits", ":info"])
    has(r.err, "%s protocol" % mode, "stderr")
    has(r.err, "spawned com.example.app, pid 4242", "stderr")
    out = lines(r.out)
    check(out[0] == "0x%x" % LIBC, "initial seek is %s, expected libc base" % out[0])
    check(out[1] == "arm" and out[2] == "64", "arch/bits: %r" % out[1:3])
    has(r.out, "protocol  framed" if mode == "framed" else "protocol  legacy")
    has(r.out, "target    spawn com.example.app, pid 4242")
    # radare2 must not open the URI twice, and the probe comes first
    check(len(r.events("connect")) == 1, "%d connections" % len(r.events("connect")))
    names = [c["name"] for c in r.cmds()]
    if mode == "framed":
        check(names[:2] == ["ping", "spawn"], "handshake was %r" % names[:3])
    else:
        check(names[1] == "spawn", "handshake was %r" % names[:3])
    check(len(r.cmds("spawn")) == 1, "spawn sent %d times" % len(r.cmds("spawn")))


def t_attach_and_uri(mode):
    m = Mock(mode)
    try:
        # host and port in the URI, nothing in the environment
        out, err, rc = run_r2(0, [":info"], uri="renef://127.0.0.1:%d/attach/1234" % m.port)
        log = m.log()
    finally:
        m.stop()
    has(err, "attached to 1234, pid 1234", "stderr")
    has(out, "target    attach 1234, pid 1234")
    check(any(c["text"] == "attach 1234" for c in log if c.get("ev") == "cmd"), "attach not sent")


def t_read(mode):
    r = session(mode, [
        "p8 16 @ 0x%x" % LIBC,
        "p8 256 @ 0x%x" % (HEAP + 0x200),
        "p8 10 @ 0x%x" % (HEAP + 0x400),
        "p8 8 @ 0x%x" % (HEAP + 0x7ffc),
        "p8 4 @ 0x%x" % (CRYPTO + 0x4000),
        "p8 4 @ 0x%x" % 0x6000000000,
        "p8 100000 @ 0x%x" % STACK,
        "p8 4 @ 0x%x" % (HEAP + 0x123),
        ":info",
    ])
    out = lines(r.out)
    check(out[0].startswith("7f454c4602010100"), "ELF header: " + out[0])
    check(out[1] == bytes(range(256)).hex(), "all 256 byte values (NUL, 0x0a, 0x1e, ...) must survive")
    check(out[2] == (mock.DONE_MARK + b"7\n\x00").hex(), "marker look-alike in memory: " + out[2])
    heap_tail = pattern(0x8000, 0x11)[0x7ffc:].hex()
    check(out[3] == heap_tail + "ffffffff", "read across the end of a range: " + out[3])
    if mode == "framed":
        # the server reads it from /proc/<pid>/mem (see t_xom_read)
        check(out[4] == mock.PROLOGUE[:4].hex(), "execute-only memory through the server: " + out[4])
    else:
        check(out[4] == "ffffffff", "execute-only memory must read as unreadable: " + out[4])
    check(out[5] == "ffffffff", "unmapped memory: " + out[5])
    check(out[6] == pattern(0x21000, 0x33)[:100000].hex(), "100000 byte read differs")
    check(out[7] == mock.SECRET[:4].hex(), "heap read: " + out[7])
    # the Lua path is only chosen by itself on a framed connection
    has(r.out, "read path lua" if mode == "framed" else "read path md (lua reads 0,")
    lacks(r.out, "not yet checked")
    if mode == "legacy":
        # asked for explicitly it works there too
        r = session(mode, ["p8 256 @ 0x%x" % (HEAP + 0x200), "p8 9000 @ 0x%x" % STACK, ":info"],
                    env={"RENEF_READ": "lua"})
        out = lines(r.out)
        check(out[0] == bytes(range(256)).hex() and out[1] == pattern(0x21000, 0x33)[:9000].hex(),
              "RENEF_READ=lua on a legacy server")
        has(r.out, "read path lua")


def t_read_md_path(mode):
    r = session(mode, ["p8 256 @ 0x%x" % (HEAP + 0x200), "p8 9000 @ 0x%x" % STACK, ":info"],
                env={"RENEF_READ": "md"})
    out = lines(r.out)
    check(out[0] == bytes(range(256)).hex(), "md path: byte values")
    check(out[1] == pattern(0x21000, 0x33)[:9000].hex(), "md path: multi page read")
    has(r.out, "read path md (lua reads 0,")
    check(not any("Memory.read" in c["text"] for c in r.cmds("exec")), "RENEF_READ=md still used Memory.read")


def t_read_verification(mode):
    # the Lua path is only trusted after it reproduced an md read
    r = session(mode, ["p8 16 @ 0x%x" % (HEAP + 0x200), ":info"], env={"RENEF_NOSYNC": "1", "RENEF_READ": "auto"})
    names = [(c["name"], c["text"][:40]) for c in r.cmds() if c["name"] in ("md", "exec")]
    first_md = next(i for i, n in enumerate(names) if n[0] == "md")
    first_lua = next(i for i, n in enumerate(names) if n[0] == "exec" and "local a,n=" in n[1])
    check(first_md < first_lua, "md must come before the first Lua read: %r" % names[:4])
    has(r.out, "read path lua")
    lacks(r.out, "not yet checked")


def t_no_maps(mode):
    # /proc/self/maps cannot be opened in the target
    r = session(mode, ["p8 16 @ 0x%x" % (HEAP + 0x200), "wx 41424344 @ 0x%x" % (HEAP + 0x123),
                       "p8 4 @ 0x%x" % (HEAP + 0x123), ":sync", ":info", "om~?"],
                mock_args=["--no-maps"])
    out = lines(r.out)
    check(out[0] == bytes(range(16)).hex(), "read without maps: " + out[0])
    check(out[1] == "41424344", "write without maps: " + out[1])
    has(r.out, "only the first mapping of each library is known")
    has(r.out, "read path md")
    if mode == "framed":
        has(r.err, "Lua read path disabled", "stderr")
    # the catch-all map stays when the real ranges are unknown
    check(out[-1] == "1", "io maps: " + out[-1])


def t_write(mode):
    blob = bytes((i * 13 + 5) & 0xff for i in range(40000))
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(blob)
    tmp.close()
    try:
        r = session(mode, [
            "wx 41424344 @ 0x%x" % (HEAP + 0x123),
            "p8 8 @ 0x%x" % (HEAP + 0x123),
            "wx 1f2003d5 @ 0x%x" % (LIBC + 0x4108),        # code: r-x, needs Memory.patch
            "p8 4 @ 0x%x" % (LIBC + 0x4108),
            "pi 1 @ 0x%x" % (LIBC + 0x4108),
            "wff %s @ 0x%x" % (tmp.name, STACK + 0x100),   # bigger than one write request
            "p8 40000 @ 0x%x" % (STACK + 0x100),
            "p8 4 @ 0x%x" % (STACK + 0x100 + 40000),
        ])
    finally:
        os.unlink(tmp.name)
    out = lines(r.out)
    check(out[0] == "41424344" + mock.SECRET[4:8].hex(), "heap write: " + out[0])
    check(out[1] == "1f2003d5" and out[2] == "nop", "code patch: %r" % out[1:3])
    check(out[3] == blob.hex(), "40000 byte write differs")
    check(out[4] == pattern(0x21000, 0x33)[0x100 + 40000:0x100 + 40004].hex(), "write ran past its end")
    writes = [c for c in r.cmds("exec") if ' local d="' in c["text"]]
    check(len(writes) >= 5, "expected the 40000 byte write to be split, saw %d requests" % len(writes))
    # a public agent truncates commands at 64KB
    check(max(c["size"] for c in writes) < 60000, "a write request is larger than a public agent accepts")


def t_write_unmapped(mode):
    # with one catch-all map radare2 lets the write through: the plugin must refuse it
    r = session(mode, ["wx 00 @ 0x9000000000", "p8 2 @ 0x%x" % HEAP, ":mock.state"],
                env={"RENEF_MAPS": "full"})
    has(r.err, "address range is not mapped", "stderr")
    has(r.out, '"crashed": false')


def t_native_search_and_seek(mode):
    # radare2's own search reads with seek+read pairs all over the place
    r = session(mode, ["e search.in=io.maps", "/x 504b0304", "s 0x%x" % (TARGET + 0x4100), "s", "s+ 16", "s",
                       "pi 2 @ 0x%x" % (LIBC + 0x4100)])
    has(r.out, "0x%x hit0_0 504b0304" % (HEAP + 0x1000))
    has(r.out, "0x%x hit0_1 504b0304" % (HEAP + 0x5000))
    out = lines(r.out)
    check("0x%x" % (TARGET + 0x4100) in out and "0x%x" % (TARGET + 0x4110) in out, "seek: %r" % out[-5:])
    has(r.out, "stp x29, x30, [sp, -0x10]!")


def t_maps_and_flags(mode):
    r = session(mode, ["om", "f~lib.", ":sync libc.so", "f~sym.libc.so.open", "f~sym.libc.so.fn_1499",
                       ":dm", ":il", ":ie libtarget.so", ":is libtarget.so", ".:ie* libtarget.so",
                       "f~sym.libtarget", ":dm libcrypto", ".:il*", ":ie nosuchlib.so"])
    check(sum(1 for l in lines(r.out) if " fd: " in l) == 16, "expected 16 io maps")
    # radare2 6.2.6's `om` prints the io-map perm and the underlying range's
    # perm as two columns; they are equal here (RENEF_MAPS test default).
    has(r.out, "0x%x - 0x%x rwx rwx libc.so" % (LIBC + 0x4000, LIBC + 0xffff))
    # execute-only code is readable for radare2 where the server can read it
    perm = "rwx" if mode == "framed" else "-wx"
    has(r.out, "0x%x - 0x%x %s %s libcrypto.so" % (CRYPTO + 0x4000, CRYPTO + 0xbfff, perm, perm))
    has(r.out, "0x%x 73728 lib.libc.so" % LIBC)
    has(r.out, "17 ranges, 4 modules, 16 io maps")
    has(r.out, "1506 exports of libc.so flagged")        # several pages of output
    has(r.out, "0x%x 1 sym.libc.so.open" % (LIBC + 0x4100))
    has(r.out, "0x%x 1 sym.libc.so.fn_1499" % (LIBC + 0x5000 + 1499 * 16))
    has(r.out, "0x%016x - 0x%016x --xp 00004000 /system/lib64/libcrypto.so" % (CRYPTO + 0x4000, CRYPTO + 0xc000))
    has(r.out, "0x%016x - 0x%016x xom libcrypto.so /system/lib64/libcrypto.so" % (CRYPTO, CRYPTO + 0xe000))
    has(r.out, "0x%016x secret_check" % (TARGET + 0x4200))
    has(r.out, "0x%x 1 sym.libtarget.so.Java_com_example_app_MainActivity_check" % (TARGET + 0x4140))
    has(r.out, "nosuchlib.so")


def t_maps_modes(mode):
    r = session(mode, ["om~?", "f~lib.~?", "s"], env={"RENEF_MAPS": "full"})
    check(lines(r.out) == ["1", "4", "0x%x" % LIBC], "RENEF_MAPS=full: %r" % lines(r.out))
    r = session(mode, ["om~?", "f~lib.~?", "s", ":sync", "om~?"], env={"RENEF_NOSYNC": "1"})
    out = lines(r.out)
    check(out[:3] == ["1", "0", "0x0"], "RENEF_NOSYNC=1: %r" % out)
    check(out[-1] == "16", "explicit :sync after RENEF_NOSYNC: %r" % out)
    listings = [c for c in r.cmds("exec") if "@r2:M" in c["text"]]
    check(len(listings) == 1, "RENEF_NOSYNC: %d map listings, expected only the one of :sync" % len(listings))


def t_many_ranges(mode):
    t0 = time.time()
    r = session(mode, ["om~?", ":il~?", "p8 4 @ 0x%x" % (HEAP + 0x123)], mock_args=["--ranges", "3000"])
    out = lines(r.out)
    check(out[0] == "3016" and out[1] == "4", "maps/modules with 3000 extra ranges: %r" % out[:2])
    check(out[2] == mock.SECRET[:4].hex(), "read with many ranges")
    # the map does not fit one reply: it has to be fetched in pages
    pages = [c for c in r.cmds("exec") if "/proc/self/maps" in c["text"] and "@r2:M" in c["text"]]
    if mode == "framed":
        # the agent's output queue is bounded: the listing has to come in pages
        check(len(pages) >= 8, "expected a paged map listing, saw %d requests" % len(pages))
    else:
        # a public server is slow per exec and has no such bound: one request
        # per listing (the one on open and the one of :il)
        check(len(pages) == 2, "expected two map listing requests, saw %d" % len(pages))
    if VERBOSE:
        print("many ranges: %.2fs" % (time.time() - t0))


def t_hooks(mode):
    a_onload, a_check = TARGET + 0x4100, TARGET + 0x4140
    r = session(mode, [
        ":sync libtarget.so",
        "s sym.libtarget.so.JNI_OnLoad",
        ":hook",                                   # at the cursor
        ":hook 0x%x -r -b" % a_check,
        ":hook 0x%x" % (HEAP + 0x100),             # not a library
        ":hook 0x%x" % (a_onload + 2),             # unaligned
        ":hook 0x%x" % (TARGET + 0x10),            # not executable
        ":hooks",
        ":mock.fire hook 0 1 2 3 4",
        ":mock.fire hook 1 0x10 0x20 0x30 0x40 5 6 7 8 0x99",
        ":mock.fire hook 0 9 9 9 9",
        ":watch 0.3",
        ":hooks",
        "CC",
        "f~hook.",
        ":bt",
        ".:bt*",
        "f~bt.",
        ":unhook 0",
        ":hooks",
        "f~hook.~?",
        ":unhook all",
        "f~hook.~?",
        "CC~?",
    ])
    has(r.out, "hook #0 installed at 0x%x (libtarget.so+0x4100, inline)" % a_onload)
    has(r.out, "hook #1 installed at 0x%x (libtarget.so+0x4140, inline)" % a_check)
    has(r.out, "is not inside a loaded library ([anon:scudo:primary])")
    has(r.out, "is not aligned to an AArch64 instruction")
    has(r.out, "(libtarget.so, r--p) is not executable")
    check(len(r.events("hook")) == 2, "the target saw %d hooks" % len(r.events("hook")))
    has(r.out, "[hook libtarget.so+0x4100 @0x%x] tid=4242 x0=0x1 x1=0x2 x2=0x3 x3=0x4" % a_onload)
    has(r.out, "[ret  libtarget.so+0x4140 @0x%x] tid=4242 x0=0x99" % a_check)
    has(r.out, "[bt   libtarget.so+0x4140 @0x%x] #01 0x%x libtarget.so JNI_OnLoad" % (a_check, TARGET + 0x4110))
    has(r.out, "  [0] 0x%x libtarget.so+0x4100 inline hits=2 last: tid=4242 x0=0x9" % a_onload)
    has(r.out, '0x%x CCu "renef hook #0 libtarget.so+0x4100 (inline): 2 hits, last tid=4242 x0=0x9 x1=0x9 x2=0x9 x3=0x9"'
        % a_onload)
    has(r.out, '0x%x CCu "renef hook #1 libtarget.so+0x4140 (inline): 1 hits, last tid=4242 x0=0x10 x1=0x20 x2=0x30 x3=0x40 ret=0x99"'
        % a_check)
    has(r.out, "0x%x 1 hook.libtarget.so_0x4100" % a_onload)
    has(r.out, "backtrace of the last call that hit libtarget.so+0x4140:")
    has(r.out, "#00 0x%016x libtarget.so+0x4150" % (TARGET + 0x4150))
    has(r.out, "#02 0x%016x libc.so+0x4190" % (LIBC + 0x4190))
    has(r.out, "0x%x 1 bt.01" % (TARGET + 0x4110))
    has(r.out, "Hook 0 removed")
    has(r.out, "  [0] (removed)")
    has(r.out, "Removed 1 hook(s)")
    tail = lines(r.out)[-3:]
    check(tail == ["Removed 1 hook(s)", "0", "0"], "flags/comments left after unhook all: %r" % tail)
    stops = r.events("watch_stop")
    if mode == "framed":
        # hook output has its own channel: :watch asks for it with `events`
        # requests and the stream command is not used at all
        check(not stops and r.events("events"), "watch must use events: %r" % r.events("events")[:3])
        # ... and the agent's own counters are what :hooks shows
        has(r.out, "  [0] target=0x%x hits=2" % a_onload)
    else:
        # watch must be stopped with a lone newline, which is not a command
        check(len(stops) == 1 and stops[0]["got"] == "\n", "watch stop: %r" % stops)


def t_event_channel(mode):
    # Hook output never travels inside a reply: it waits on the server, the
    # reply to the next command is that command's output only, with a note
    # saying how much is waiting, and :watch shows it.
    a = TARGET + 0x4100
    cmds = [":hook 0x%x" % a, ":mock.fire hook 0 1 2 3 4", ":mock.fire hook 0 5 6 7 8",
            ":hooks", "p8 4 @ 0x%x" % (HEAP + 0x123), ".:il*", ":watch 0.3", ":hooks"]
    r = session(mode, cmds)
    out = r.out
    first = out.index("Active hooks: 1")
    hook_line = "[hook libtarget.so+0x4100 @0x%x] tid=4242 x0=0x1" % a
    has(out, hook_line)
    check(out.index(hook_line) > out.index("Watching for 300 ms"), "hook output shown before :watch asked for it")
    check(hook_line not in r.err, "hook output on stderr")
    has(out, "(2 lines of hook output waiting, :watch shows them)")
    has(out[first:], "  [0] target=0x%x hits=2" % a)
    has(out, mock.SECRET[:4].hex())
    # after the watch nothing is waiting, so no note under the second :hooks
    tail = out[out.rindex("Active hooks: 1"):]
    lacks(tail, "hook output waiting")
    has(tail, "inline hits=2 last: tid=4242 x0=0x5")

    # a framed server whose agent has no event channel: output between
    # commands is shown on stderr as before, and nothing announces itself
    r = session(mode, cmds, mock_args=["--no-event-channel"])
    lacks(r.out, "hook output waiting")
    has(r.out, "Active hooks: 1")
    stops = r.events("watch_stop")
    check(len(stops) == 1 and stops[0]["got"] == "\n", "stream watch stop: %r" % stops)


def t_hook_safety(mode):
    xom = CRYPTO + 0x4000
    # an engine that dies when it patches execute-only code
    r = session(mode, [
        ":hook 0x%x" % xom,                        # guard: refused, target untouched
        ":mock.state",
        ":hook 0x%x -g=libtarget.so" % xom,        # explicit PLT/GOT on an export
        ":hook 0x%x -g" % (xom + 0x10),            # not an export: refused
        ":hooks",
        "f~hook.",
        ":mock.state",
    ], mock_args=["--xom-crash"])
    has(r.out, "libcrypto.so+0x4000 is in execute-only memory (--xp).")
    has(r.out, ":hook 0x%x -i" % xom)
    has(r.out, "hook #0 installed at 0x%x (libcrypto.so+0x4000, plt/got)" % xom)
    has(r.out, "PLT/GOT hook on the symbol 'SHA256_Init'")
    has(r.out, "no exported symbol starts at this address")
    hooks = r.events("hook")
    check(len(hooks) == 1 and hooks[0]["caller"] == "libtarget.so", "hooks in target: %r" % hooks)
    # the agent reports a GOT slot as "target" of such a hook: it must not become a flag
    has(r.out, "  [0] 0x%x libcrypto.so+0x4000 plt/got" % xom)
    check(sum(1 for l in lines(r.out) if " hook." in l) == 1, "exactly one hook flag expected")
    check(r.out.count('"crashed": false') == 2, "target state: " + r.out[-300:])

    # asked for explicitly, the inline hook is attempted - and reported when it kills the target
    r = session(mode, [":hook 0x%x -i" % xom, ":exec print(1)"], mock_args=["--xom-crash"], crash_ok=True)
    has(r.out, "hook at libcrypto.so+0x4000 failed")
    has(r.out, "ERROR: Failed to connect to agent")
    check(len(r.events("crash")) == 1, "expected the fake target to die exactly once")

    # with the fixed engine the same command works
    r = session(mode, [":hook 0x%x -i" % xom, ":mock.state"])
    has(r.out, "hook #0 installed at 0x%x (libcrypto.so+0x4000, inline)" % xom)
    has(r.out, '"crashed": false')


def t_xom_read(mode):
    xom = CRYPTO + 0x4000
    cmds = ["pi 2 @ 0x%x" % xom, "p8 8 @ 0x%x" % (xom + 0x7ff8), "p8 8 @ 0x%x" % (xom + 0x3000),
            "p8 4 @ 0x%x" % (xom - 4), ":info", ":mock.state"]
    r = session(mode, cmds)
    has(r.out, '"crashed": false')
    if mode == "framed":
        # the target cannot read this code; the server reads it from /proc/<pid>/mem
        has(r.out, "stp x29, x30, [sp, -0x10]!")
        has(r.out, "xom reads server /proc/<pid>/mem (")
        dumps = r.events("memdump")
        check(dumps and all(xom <= d["start"] < xom + 0x8000 for d in dumps),
              "memdump must only be used for execute-only pages: %r" % dumps)
        check(len(dumps) <= 3, "one request per stretch of pages expected: %r" % dumps)
        check("ffffffffffffffff" not in r.out, "execute-only bytes missing: " + r.out[-400:])
    else:
        has(r.out, "xom reads not available (legacy server)")
        has(r.out, "ffffffffffffffff")
        check(not r.events("memdump"), "legacy servers have no memdump")

    if mode == "framed":
        # a framed server without the command: found out once, then left alone
        r = session(mode, cmds, mock_args=["--no-memdump"])
        has(r.out, "xom reads not available (server has no memdump)")
        has(r.out, "ffffffffffffffff")
        has(r.out, '"crashed": false')
        asked = [e for e in r.events("cmd") if e["name"] == "memdump"]
        check(len(asked) == 1, "memdump should be probed once: %d" % len(asked))


def t_hooks_from_script(mode):
    # a hook set by a script is picked up from the agent's list
    r = session(mode, [':exec hook("libtarget.so", 0x4140, {onEnter=function(args) end})', ":hooks", "f~hook.", "CC"])
    has(r.out, "  [0] 0x%x libtarget.so+0x4140 set by a script hits=0" % (TARGET + 0x4140))
    has(r.out, "0x%x 1 hook.libtarget.so_0x4140" % (TARGET + 0x4140))
    has(r.out, '0x%x CCu "renef hook #0 libtarget.so+0x4140 (set by a script)"' % (TARGET + 0x4140))


def t_hook_custom_body(mode):
    r = session(mode, [
        ':hook 0x%x -e print("custom //", args[0] + args[1])' % (TARGET + 0x4100),
        ":mock.fire hook 0 40 2",
        ":watch 0.2",
    ])
    has(r.out, "hook #0 installed")
    has(r.out, "custom //\n42\n")


def t_strace(mode):
    r = session(mode, [
        ":strace",
        ":strace --list file",
        ":strace openat,read -f libtarget.so",
        ":strace nosuch",
        ":strace --active",
        ":mock.fire syscall openat /etc/hosts 3",
        ":mock.fire syscall close 3 0",              # not traced: no output
        ":watch 0.2",
        ":strace -u read",
        ":strace -c network",
        ":strace -a",
        ":strace --stop",
        ":strace --active",
        ":strace open;rm",
    ])
    has(r.out, "usage: :strace")
    has(r.out, "Available syscalls (4):")
    has(r.out, "    openat (4 args)")
    has(r.out, "Tracing 2 syscall(s)\ntrace output is asynchronous")
    has(r.out, "Warning: Failed to trace 'nosuch'")
    has(r.out, "Active traces: 2\n  openat [file] 3 call sites\n  read [file] 3 call sites")
    has(r.out, "[tid:4242] openat(/etc/hosts) = 3")
    lacks(r.out, "close(3)")
    has(r.out, "Removed 1 trace(s)")
    has(r.out, "Tracing 2 network syscalls")
    has(r.out, "Tracing all 7 syscalls")
    has(r.out, "Syscall tracing stopped\nActive traces: 0")
    sent = [c["text"] for c in r.cmds("exec") if "Syscall." in c["text"]]
    check("exec Syscall.trace('openat','read',{caller=\"libtarget.so\"})" in sent, "trace request: %r" % sent[:4])


def t_search(mode):
    r = session(mode, [
        ":/x 504b0304",
        "f~renef.hit",
        ":/x 50 .. 03 04",
        ":/ r2renef-secret",
        ":/ -m libc.so ELF",
        ":/x -m libtarget.so fd7bbfa9fd030091",
        ".:/x* 504b0304",
        "f~renef.hit~?",
        ":/x zz",
        ":/x -m nosuch 00",
    ])
    has(r.out, "0x%016x renef.hit0 0x%x\n0x%016x renef.hit1 0x%x\n2 hits" % (HEAP + 0x1000, HEAP + 0x1000,
                                                                              HEAP + 0x5000, HEAP + 0x5000))
    has(r.out, "0x%x 4 renef.hit0" % (HEAP + 0x1000))
    has(r.out, "0x%016x renef.hit0 0x%x\n1 hits" % (HEAP + 0x123, HEAP + 0x123))
    has(r.out, "0x%016x renef.hit0 libc.so+0x1\n1 hits" % (LIBC + 1))
    has(r.out, "0x%016x renef.hit0 libtarget.so+0x4100" % (TARGET + 0x4100))
    has(r.out, "usage: :/x")
    has(r.out, "0 hits")
    pats = [c["text"] for c in r.cmds("exec") if "Memory.search" in c["text"]]
    check(any('Memory.search("50 4B 03 04 ")' in p for p in pats), "pattern form: %r" % pats[:1])
    check(any('Memory.search("50 ?? 03 04 ")' in p for p in pats), "wildcard form")
    # text goes as bytes too
    check(any('Memory.search("72 32 72 65 6E 65 66 2D 73 65 63 72 65 74 ")' in p for p in pats), "text form")


def t_hookgen(mode):
    r = session(mode, ["s 0x%x" % (TARGET + 0x4140), ":hookgen", ":hookgen 0x%x" % (LIBC + 0x4100),
                       ":hookgen libc.so strlen", ":hookgen 0x%x" % (HEAP + 8)])
    has(r.out, 'hook("libtarget.so", 0x4140, {')
    has(r.out, 'hook("libc.so", 0x4100, {')
    has(r.out, 'hook("libc.so", 0x4240, {')
    has(r.out, "onLeave = function(retval)")
    sent = [c["text"] for c in r.cmds("hookgen")]
    check(sent[:3] == ["hookgen libtarget.so 0x4140", "hookgen libc.so 0x4100", "hookgen libc.so strlen"],
          "hookgen requests: %r" % sent)


def t_call(mode):
    r = session(mode, [
        ":call 0x%x string \"radare2\"" % (LIBC + 0x4240),   # strlen("radare2") -> 7
        ":call 0x%x int \"hi\"" % (LIBC + 0x4240),           # strlen("hi") -> 2
        ":call 0x%x long 7 35" % (TARGET + 0x4300),          # mock_sum(7, 35) -> 42
        ":call 0x%x string 7 35" % (TARGET + 0x4300),        # retType reaches the callee: "sum=42"
        ":call 0x%x" % (CRYPTO + 0x4000),                    # execute-only, no mock behavior -> default 0
        ":call 0x%x" % (LIBC + 0x10),                        # mapped, in libc.so, but not executable
        ":call 0x%x" % (HEAP + 8),                           # mapped, but not inside a loaded library
        ":call 0x1000",                                      # not mapped at all
        ":call 0x%x" % (TARGET + 0x4301),                    # not 4-byte aligned
        ":call",                                             # usage
    ])
    has(r.out, 'libc.so+0x4240("radare2") -> 7\n')
    has(r.out, 'libc.so+0x4240("hi") -> 2\n')
    has(r.out, "libtarget.so+0x4300(7, 35) -> 42\n")
    has(r.out, "libtarget.so+0x4300(7, 35) -> sum=42\n")
    has(r.out, "libcrypto.so+0x4000() -> 0\n")
    has(r.out, "not executable: nothing to call there\n")
    has(r.out, "is not inside a loaded library ([anon:scudo:primary])")
    has(r.out, "not mapped in the target\n")
    has(r.out, "not aligned to an AArch64 instruction\n")
    has(r.out, "usage: :call <addr>")


def t_patch(mode):
    r = session(mode, [
        ":patch 0x%x" % (TARGET + 0x4140),                              # 0: default -> 0, logs args
        ":patch 0x%x -r 99" % (TARGET + 0x4180),                         # 1: forced return
        ':patch 0x%x -e return args[0]+args[1]' % (TARGET + 0x41c0),    # 2: custom body
        ":mock.fire hook 0 11 22",
        ":mock.fire hook 1 11 22",
        ":mock.fire hook 2 11 22",
        ":watch 0.2",
        ':patch 0x%x -r 1 -e return 1' % (TARGET + 0x4140),             # -r/-e exclude each other
        ":patch 0x%x -i -g" % (TARGET + 0x4140),                        # -i/-g exclude each other
        ":patch 0x%x" % (CRYPTO + 0x4000),                              # execute-only: refused
        ":patch 0x%x -g=libtarget.so" % (LIBC + 0x4240),                # PLT/GOT on an export (strlen)
        ":patch 0x%x -g" % (LIBC + 0x4244),                             # not an export: refused
        ":patch 0x%x" % (LIBC + 0x10),                                  # mapped, not executable
        ":patch",                                                       # usage
    ])
    has(r.out, "installed at 0x%x (libtarget.so+0x4140, inline): the original never runs" % (TARGET + 0x4140))
    has(r.out, "installed at 0x%x (libtarget.so+0x4180, inline): the original never runs" % (TARGET + 0x4180))
    has(r.out, "installed at 0x%x (libtarget.so+0x41c0, inline): the original never runs" % (TARGET + 0x41c0))
    has(r.out, "x0=0xb x1=0x16 x2=0x0 x3=0x0 -> 0")                     # default body, args(11,22)
    has(r.out, "forced return=0x63")                                    # -r 99 (0x63)
    has(r.out, "[mock] replace @%d: original skipped, returned 0" % (TARGET + 0x4140))
    has(r.out, "[mock] replace @%d: original skipped, returned 99" % (TARGET + 0x4180))
    has(r.out, "[mock] replace @%d: original skipped, returned 33" % (TARGET + 0x41c0))  # 11+22
    has(r.out, "-r and -e exclude each other\n")
    has(r.out, "-i and -g exclude each other\n")
    has(r.out, "is in execute-only memory (--xp)")
    has(r.out, "installed at 0x%x (libc.so+0x4240, plt/got): the original never runs" % (LIBC + 0x4240))
    has(r.out, "PLT/GOT patch on the symbol 'strlen'")
    has(r.out, "no exported symbol starts at this address")
    has(r.out, "not executable: nothing to patch there\n")
    has(r.out, "usage: :patch <addr>")


def t_diff(mode):
    r = session(mode, [
        ":diff libc.so",                 # whole default-size (32768) compare, untouched -> identical
        ":diff libtarget.so 16",          # explicit, smaller size
        ":diff nosuchlib.so",             # not a loaded library
        "s 0x%x" % (HEAP + 8),            # mapped, but not inside a module
        ":diff",
        ":diff libcrypto.so",             # execute-only: live read goes through /proc/<pid>/mem
    ])
    has(r.out, "libc.so: comparing 32768 bytes of %s against the live process at 0x%x\n" % (mock.LIBC, LIBC + 0x4000))
    has(r.out, "identical")
    has(r.out, "libtarget.so: comparing 16 bytes of %s against the live process at 0x%x\n" % (mock.LIBTARGET, TARGET + 0x4000))
    has(r.out, "'nosuchlib.so' is not a loaded library\n")
    has(r.out, "is not a loaded library\n")
    if mode == "framed":
        has(r.out, "libcrypto.so: comparing 32768 bytes of %s against the live process at 0x%x\n" % (mock.LIBCRYPTO, CRYPTO + 0x4000))
    else:
        # no memdump command on a legacy connection: refuses rather than
        # faulting on execute-only memory
        has(r.out, "could not read live memory at 0x%x\n" % (CRYPTO + 0x4000))


def t_scripts(mode):
    script = ('-- a comment with // in it\n'
              'local base = Module.find("libc.so") -- trailing comment\n'
              'print(string.format("libc at 0x%x, 7//2=%d", base, 7//2))\n'
              'print([[long\nstring]], "http://example.org/x")\n'
              '--[[ block\ncomment ]] print("after block")\n'
              'error("boom")\n')
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".lua", mode="w")
    tmp.write(script)
    tmp.close()
    try:
        r = session(mode, [":l " + tmp.name, ":exec print(7//2)", ":raw exec print(7//2)", ":exec print(1+1)",
                           ":l /nonexistent/x.lua", ":exec error('x')", ":ping", ":la", ":md 0x%x 16" % LIBC,
                           ":nosuchcmd", ":?"])
    finally:
        os.unlink(tmp.name)
    has(r.out, "libc at 0x%x, 7//2=3\nlong\nstring\nhttp://example.org/x\nafter block\n" % LIBC)
    # the script is sent hex encoded, so its line numbers survive
    has(r.out, "ERROR: %s:8: boom\nOK\n" % os.path.basename(tmp.name))
    # "//" in exec is wrapped; :raw shows what the server does with it otherwise
    has(r.out, "3\nOK\nERROR: Unknown command. Type 'help' for available commands.\n2\nOK\n")
    has(r.out, "cannot read /nonexistent/x.lua")
    has(r.out, "ERROR: Lua execution failed")
    has(r.out, "pong\ncom.example.app\ncom.android.settings\nMemory at 0x%x (16 bytes):" % LIBC)
    has(r.out, "r2renef commands")
    has(r.out, ":strace <a,b,..> [-f lib]")

    # a script too long for one command is sent in pieces
    big = "local t = 0\n" + "".join("t = t + %d -- line %d\n" % (i, i) for i in range(4000)) + 'print("sum", t)\n'
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".lua", mode="w")
    tmp.write(big)
    tmp.close()
    try:
        r = session(mode, [":l " + tmp.name])
    finally:
        os.unlink(tmp.name)
    has(r.out, "sum\n%d\nOK\n" % sum(range(4000)))
    sizes = [c["size"] for c in r.cmds("exec")]
    check(len(big) > 60000 and max(sizes) < 60000, "script pieces: %r" % sorted(sizes)[-3:])
    # no command the plugin sent on its own may contain "//" or a newline in legacy mode
    for c in r.cmds():
        if c["name"] == "exec" and "print(7" not in c["text"]:
            check("//" not in c["text"], "command with //: " + c["text"][:80])


def t_stale_reply(mode):
    r = session(mode, [':exec __mock_sleep(1800) print("slow-done")', ":exec print(1+1)", ":exec print(2+2)"],
                env={"RENEF_TIMEOUT": "1"})
    has(r.out, "renef: timed out\n2\nOK\n4\nOK\n")
    # the late reply must never be taken for the answer of a later command
    lacks(r.out, "slow-done", "stdout")
    if mode == "legacy":
        has(r.err, "slow-done", "stderr")           # kept, as stray output
        check(len(r.cmds("ping")) == 1, "expected one resync ping, saw %d" % len(r.cmds("ping")))
    else:
        lacks(r.err, "slow-done", "stderr")         # dropped by request id


def t_unsolicited(mode):
    # later than the quiet window that ends the legacy reply of mock.late itself
    r = session(mode, [":mock.late 800 LATE-LINE", "!sleep 1.2", ":exec print(5)", "p8 4 @ 0x%x" % (HEAP + 0x123)])
    has(r.out, "mock ok\n5\nOK\n" + mock.SECRET[:4].hex())
    lacks(r.out, "LATE-LINE", "stdout")
    has(r.err, "LATE-LINE", "stderr")


def t_fragmented(mode):
    # tiny pieces back to back, and pieces with a pause so every one is its own read
    args = ["--chunk", "3"] if mode == "framed" else ["--chunk", "61", "--chunk-delay-ms", "1"]
    r = session(mode, ["p8 256 @ 0x%x" % (HEAP + 0x200), "p8 10 @ 0x%x" % (HEAP + 0x400), ":exec print(41+1)",
                       ":il~?"], mock_args=args)
    out = lines(r.out)
    check(out[0] == bytes(range(256)).hex(), "fragmented read")
    check(out[1] == (mock.DONE_MARK + b"7\n\x00").hex(), "fragmented read of marker look-alike")
    check(out[2:5] == ["42", "OK", "4"], "fragmented exec: %r" % out[2:5])


def t_forced_modes(mode):
    # RENEF_FRAMING=off against a framing server, and on without a probe
    if mode == "framed":
        r = session("framed", [":info", "p8 4 @ 0x%x" % (HEAP + 0x123)], env={"RENEF_FRAMING": "off"})
        has(r.out, "protocol  legacy")
        check(not r.cmds("ping"), "probe sent although framing was forced off")
        r = session("framed", [":info", "p8 4 @ 0x%x" % (HEAP + 0x123)], env={"RENEF_FRAMING": "on"})
        has(r.out, "protocol  framed")
        check(not r.cmds("ping"), "probe sent although framing was forced on")
        has(r.out, mock.SECRET[:4].hex())


def t_second_open(mode):
    r = session(mode, ["o renef://attach/5", ":info"])
    has(r.err, "already connected", "stderr")
    has(r.out, "target    spawn com.example.app")
    check(len(r.events("connect")) == 1, "a second connection was made")


def t_open_failures(mode):
    m = Mock(mode)
    try:
        out, err, rc = run_r2(m.port, ["s"], uri="renef://spawn/com.fail.app")
        has(err, "spawn com.fail.app failed: ERROR: Failed to launch app", "stderr")
        out, err, rc = run_r2(m.port, ["s"], uri="renef://attach/999")
        has(err, "attach 999 failed: FAIL", "stderr")
        out, err, rc = run_r2(m.port, ["s"], uri="renef://spawn/bad name")
        has(err, "invalid package name", "stderr")
        out, err, rc = run_r2(m.port, ["s"], uri="renef://frob/x")
        has(err, "invalid URI", "stderr")
        check(len([e for e in m.log() if e.get("ev") == "connect"]) == 2, "bad URIs must not connect")
        # the server is busy with another client: connect works, nobody answers
        hog = socket.create_connection(("127.0.0.1", m.port))
        time.sleep(0.1)
        t0 = time.time()
        out, err, rc = run_r2(m.port, ["s"], env={"RENEF_PROBE_TIMEOUT_MS": "400"})
        hog.close()
        has(err, "does not answer", "stderr")
        has(err, "one at a time", "stderr")
        check(time.time() - t0 < 5, "busy server detection took %.1fs" % (time.time() - t0))
    finally:
        m.stop()
    # nothing listening
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    out, err, rc = run_r2(port, ["s"])
    has(err, "cannot connect to 127.0.0.1:%d" % port, "stderr")


def t_env_host(mode):
    m = Mock(mode)
    try:
        out, err, rc = run_r2(0, [":info"], env={"RENEF_HOST": "localhost", "RENEF_PORT": str(m.port)})
    finally:
        m.stop()
    has(out, "server    localhost:%d (connected)" % m.port)


def t_cache(mode):
    r = session(mode, [":cache", ":cache 0", ":cache 5000", ":cache flush", ":cache x"])
    has(r.out, "cache lifetime 2000 ms\ncache lifetime 0 ms\ncache lifetime 5000 ms\ncache lifetime 5000 ms\nusage: :cache")
    # within the lifetime a page is fetched once however often it is read
    r = session(mode, ["p8 16 @ 0x%x" % (STACK + 0x3000)] * 6, env={"RENEF_CACHE_MS": "60000"})
    n = sum(1 for c in r.cmds("exec") if "local a,n=0x%x," % (STACK + 0x3000) in c["text"])
    check(n == 1, "page fetched %d times with a long cache lifetime" % n)
    r = session(mode, ["p8 16 @ 0x%x" % (STACK + 0x3000)] * 3, env={"RENEF_CACHE_MS": "0"})
    n = sum(1 for c in r.cmds("exec") if "local a,n=0x%x," % (STACK + 0x3000) in c["text"])
    check(n >= 3, "page fetched %d times with the cache off" % n)


def t_java_classes(mode):
    r = session(mode, [
        ":jc",
        ":jc pin",
        ":jc -n 2",
        ":jc nothinglikethis",
        ":jm PinManager",
        ":jm -s PinManager chec",
        ":jm -a PinManager label",
        ":jm Inner",
        ":jm Util",
        ":jm File",
        ":jm Nope",
        ":jm com.example.app.net.Checker",
        ":jm",
    ])
    has(r.out, "com.example.app.PinManager\n")
    has(r.out, "6 classes in the app's own dex files")
    has(r.out, "1 of the app's 6 classes match")
    has(r.out, "2 of 6 matching classes shown (6 in the app)")
    has(r.out, "0 of the app's 6 classes match")
    has(r.out, "class com.example.app.PinManager extends java.lang.Object implements com.example.app.net.Checker")
    has(r.out, "  new PinManager(String)\n")
    has(r.out, "  boolean check(String)\n")
    has(r.out, "  boolean check(String, int)\n")
    has(r.out, "  static native boolean verifyNative(byte[])\n")
    has(r.out, "  static int score(float, long, Object)\n")
    has(r.out, "7 listed, 1 compiler-made not shown (-a)")
    has(r.out, "(Ljava/lang/String;I)Z")
    has(r.out, "  Object label()\n")                        # only with -a
    has(r.out, "class com.example.app.Outer$Inner extends java.lang.Object")
    has(r.out, "2 classes are called Util, give the full name:\n  com.example.a.Util\n  com.example.b.Util\n")
    has(r.out, "class java.io.File extends java.lang.Object implements java.io.Serializable")
    has(r.out, "class not found: Nope (:jc nope searches the app's classes)")
    has(r.out, "interface com.example.app.net.Checker\n  abstract boolean verify(String)")
    has(r.out, "usage: :jm [-s] [-a] <class> [filter]")
    lacks(r.out, "@r2:")


def t_java_hooks(mode):
    r = session(mode, [
        ":sync libtarget.so",
        ":hook 0x%x" % (TARGET + 0x4100),                  # native hook #0, to be left alone
        ":jhook PinManager check",                          # both overloads: j0, j1
        ":jhook PinManager verifyNative -r true",           # j2
        ":jhook PinManager new",                            # j3
        ":jhook PinManager reset -k",                       # j4
        ":jhook PinManager label -n 1",                     # j5 (the compiler-made twin is left out)
        ":jhook PinManager score -s",                       # j6
        ":jhook PinManager check (String)",                 # already hooked
        ":jhook Checker verify",                            # interface
        ":jhook PinManager check (int)",                    # no such overload
        ":jhook PinManager nope",
        ":jhook Nope run",
        ":jhook PinManager check -r",                       # usage
        ":hooks",
        ":mock.fire jhook 0 n:0 o:com.example.app.PinManager s:1234",
        ":mock.fire jhook 1 n:1 o:com.example.app.PinManager s:a%20\"b\" n:7",
        ":mock.fire jhook 2 n:0 b:00ff10",
        ":mock.fire jhook 3 - o:com.example.app.PinManager s:seed",
        ":mock.fire jhook 4 - o:com.example.app.PinManager",
        ":mock.fire jhook 5 s:first o:com.example.app.PinManager",
        ":mock.fire jhook 5 s:second o:com.example.app.PinManager",
        ":mock.fire jhook 5 s:third o:com.example.app.PinManager",
        ":mock.fire jhook 6 n:42 n:9 o:java.io.File",
        ":mock.fire jhook 0 ! o:com.example.app.PinManager s:throws",
        ":mock.fire jhook 0 n:1 o:com.example.app.PinManager s:after",
        ":watch 0.3",
        ":unhook j0",
        ":mock.fire jhook 0 n:0 o:com.example.app.PinManager s:gone",
        ":watch 0.2",
        ":hooks",
        "f~hook.~?",
        ":jhook PinManager check (String) -e print('custom '..type(args[2]))",   # j7
        ":mock.fire jhook 7 n:0 o:com.example.app.PinManager s:x",
        ":watch 0.2",
        ":unhook all",
        "f~hook.~?",
    ])
    has(r.out, "hook j0 installed: boolean check(String)\nhook j1 installed: boolean check(String, int)")
    has(r.out, "hook j2 installed: static native boolean verifyNative(byte[])")
    has(r.out, "hook j3 installed: new PinManager(String)")
    has(r.out, "hook j5 installed: String label()")
    lacks(r.out, "installed: Object label()")
    has(r.out, "not hooked: boolean check(String)\n  com/example/app/PinManager.check(Ljava/lang/String;)Z is already hooked (j0)")
    has(r.out, "not hooked: abstract boolean verify(String)\n  abstract or interface method: it has no code.")
    has(r.out, "no check with these parameter types. There is:\n  boolean check(String)\n  boolean check(String, int)\n")
    has(r.out, "com.example.app.PinManager has no method nope (:jm PinManager lists them)")
    has(r.out, "class not found: Nope")
    has(r.out, "usage: :jhook <class> <method>")
    has(r.out, "  [j2] com/example/app/PinManager.verifyNative([B)Z hits=0")
    # the calls, as :watch shows them
    has(r.out, '[j0] PinManager.check("1234") -> false')
    has(r.out, '[j1] PinManager.check("a \\"b\\"", 7) -> true')
    has(r.out, "[j2] PinManager.verifyNative(byte[3] 00ff10) -> false  => true")
    has(r.out, "[mock] j2: result replaced by 1")
    has(r.out, '[j3] new PinManager("seed")')
    has(r.out, "[j4] PinManager.reset()  (not run)")
    has(r.out, "[mock] j4: original not run")
    has(r.out, '[j5] PinManager.label() -> "first"')
    has(r.out, "[j5] PinManager.label: further calls are not printed")
    lacks(r.out, '"second"')
    lacks(r.out, '"third"')
    has(r.out, '[j6] PinManager.score(<float>, 9, Object "mock java.io.File") -> 42')
    # a call that threw is still reported, by the next call on that thread
    has(r.out, '[j0] PinManager.check("throws")\n')
    has(r.out, '[j0] PinManager.check("after") -> true')
    # :unhook jN removes the Java hook and leaves the native hook #0 alone
    has(r.out, "Hook j0 removed")
    lacks(r.out, '"gone"')
    has(r.out, "  [j0] (removed)")
    has(r.out, "hook j7 installed: boolean check(String)")
    has(r.out, "custom number")
    counts = [l for l in lines(r.out) if l in ("0", "1", "2")]
    check(counts[-2:] == ["1", "0"], "native hook flag must survive :unhook j0 and go with :unhook all: %r" % counts)
    lacks(r.out, "@r2:")
    lacks(r.out, "[java]")


def t_java_native(mode):
    r = session(mode, [
        ":jni PinManager",
        ":jni MainActivity",
        ":jni Checker",
        "f~sym.jni",
        ":jni -n -a",
        ":jni -a pinman",
        ":jni",
        ":jni Nope",
        ":jcode PinManager verifyNative",
        "s",
        ":jcode PinManager check (String, int)",
        "s",
        ":jcode PinManager check",
        ":jcode PinManager check (int)",
        ":jcode PinManager nope",
        ":jcode",
        "f~sym.java",
    ])
    a_native, a_export = TARGET + 0x4200, TARGET + 0x4140
    has(r.out, "com.example.app.PinManager\n  0x%-12x libtarget.so+0x4200" % a_native)
    has(r.out, "static native boolean verifyNative(byte[])\n")
    has(r.out, "1 native method: 1 bound\n")
    # nothing is bound to these yet: one is found by the name libtarget.so exports
    has(r.out, "  0x%-12x libtarget.so+0x4140" % a_export)
    has(r.out, "native boolean check(String)   (not bound yet: by its export name)")
    has(r.out, "  not bound")
    has(r.out, "native void late_bound()")
    has(r.out, "2 native methods: 0 bound, 1 found by export name, 1 not bound yet")
    has(r.out, "the class declares no native methods")
    has(r.out, "0x%x 1 sym.jni.PinManager_verifyNative" % a_native)
    has(r.out, "0x%x 1 sym.jni.MainActivity_check" % a_export)
    has(r.out, "3 native methods in 6 classes: 1 bound, 1 found by export name, 1 not bound yet")
    has(r.out, "1 native method in 1 classes: 1 bound")
    has(r.out, "usage: :jni [-n] <class>")
    has(r.out, "class not found: Nope")
    # :jcode seeks when there is one answer
    has(r.out, "static native boolean verifyNative(byte[])   (com.example.app.PinManager)\n"
               "  native function at 0x%x (libtarget.so+0x4200)  sym.jni.PinManager_verifyNative" % a_native)
    has(r.out, "boolean check(String, int)   (com.example.app.PinManager)\n"
               "  compiled code at 0x%x (libtarget.so+0x4340)  sym.java.PinManager_check" % (TARGET + 0x4340))
    seeks = [l for l in lines(r.out) if l.startswith("0x") and len(l) <= 14]
    check(seeks[:2] == ["0x%x" % a_native, "0x%x" % (TARGET + 0x4340)], "seeks after :jcode: %r" % seeks)
    has(r.out, "several methods: seek to the one you want")
    has(r.out, "no check with these parameter types. There is:\n  boolean check(String)\n")
    has(r.out, "com.example.app.PinManager has no method nope")
    has(r.out, "usage: :jcode <class> <method> [(types)]")
    lacks(r.out, "@r2:")


def t_java_native_old_agent(mode):
    r = session(mode, [":jni PinManager", ":jcode PinManager check", ":jm PinManager"],
                mock_args=("--no-method-info",))
    has(r.out, "this renef has no Java.methodInfo (it came with 0.4.1)")
    has(r.out, "  boolean check(String)\n")                # the rest keeps working


def t_java_old_server(mode):
    # a server that does not list Java hooks: they work, their number is not known
    r = session(mode, [
        ":jhook PinManager check (String)",
        ":mock.fire jhook 0 n:1 o:com.example.app.PinManager s:1234",
        ":watch 0.3",
    ], mock_args=("--no-java-list",))
    has(r.out, "hook installed: boolean check(String)")
    has(r.out, '[java] PinManager.check("1234") -> true')


def t_java_helper_in_sync(mode):
    # the checked-in header must be the current Lua file
    src = os.path.join(os.path.dirname(HERE), "src")
    with open(os.path.join(src, "renef_java.lua"), "rb") as f:
        lua = f.read()
    with open(os.path.join(src, "renef_java_lua.h")) as f:
        data = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})", f.read()))
    check(data == lua + b"\0", "src/renef_java_lua.h is stale: run `make lua-header`")
    m = re.search(rb"local VERSION = (\d+)", lua)
    with open(os.path.join(src, "renef_java.c")) as f:
        c = re.search(r"#define RN_JAVA_VERSION (\d+)", f.read())
    check(m and c and int(m.group(1)) == int(c.group(1)), "RN_JAVA_VERSION differs from the Lua VERSION")


def interrupt_when(mode, cmds, wait_for, env=None):
    """runs r2, sends it SIGINT once the server has received a command containing `wait_for`"""
    import signal
    m = Mock(mode)
    try:
        p = subprocess.Popen(r2_argv(cmds, "renef://spawn/com.example.app"), env=r2_env(m.port, env),
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.time() + 20
        while time.time() < deadline and not any(wait_for in c.get("text", "") for c in m.log()):
            time.sleep(0.05)
        time.sleep(0.4)
        p.send_signal(signal.SIGINT)
        try:
            out, err = p.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()
            raise Failure("r2 did not come back after SIGINT")
        no_sanitizer_report(err.decode("utf-8", "replace"))
        return Result(out.decode("utf-8", "replace"), err.decode("utf-8", "replace"), p.returncode, m.log())
    finally:
        m.stop()


def t_interrupt(mode):
    # ^C ends :watch; the session stays usable and in sync
    # (with an event channel :watch is a loop of `events` requests)
    r = interrupt_when(mode, [":hook 0x%x" % (TARGET + 0x4100), ":mock.fire hook 0 7 7 7 7", ":watch",
                              ":mock.fire hook 0 8 8 8 8",
                              ':exec print("after-watch")', "p8 4 @ 0x%x" % (HEAP + 0x123)],
                       "events 4" if mode == "framed" else "watch")
    has(r.out, "Watching... (^C to stop)")
    has(r.out, "[hook libtarget.so+0x4100 @0x%x] tid=4242 x0=0x7" % (TARGET + 0x4100))
    has(r.out, "after-watch\nOK\n")
    has(r.out, mock.SECRET[:4].hex())
    stops = r.events("watch_stop")
    if mode == "framed":
        check(not stops, "stream watch used although the server has events")
        # the call made after the watch is not shown, only announced
        lacks(r.out, "x0=0x8")
        has(r.out, "(1 line of hook output waiting, :watch shows it)")
    else:
        check(len(stops) == 1 and stops[0]["got"] == "\n", "watch stop: %r" % stops)
    # ^C ends the wait for a slow command; its late reply does not leak into the next one
    r = interrupt_when(mode, [':exec __mock_sleep(2500) print("slow-done")', ':exec print("after-interrupt")',
                              "p8 4 @ 0x%x" % (HEAP + 0x123)], "__mock_sleep")
    has(r.out, "renef: interrupted\nafter-interrupt\nOK\n" + mock.SECRET[:4].hex())
    lacks(r.out, "slow-done", "stdout")


def t_output_queue(mode):
    # An agent with the bounded output queue, spoken to without framing:
    # the unpaged listing does not fit and has to be fetched again in pages.
    r = session("framed", ["om~?", ":il~?", ":sync libc.so", "f~sym.libc.so.~?"],
                mock_args=["--ranges", "3000", "--outq-bytes", "60000"], env={"RENEF_FRAMING": "off"})
    out = lines(r.out)
    check(out[0] == "3016" and out[1] == "4", "maps/modules: %r" % out[:2])
    has(r.out, "1506 exports of libc.so flagged")
    check(out[-1] == "1506", "export flags: " + out[-1])
    # the same when the drop notice only arrives with the first page: it
    # must neither spoil that page nor be shown as output of the target
    r = session("framed", ["om~?", ":il~?", ':exec print("[dropped by the app]")'],
                mock_args=["--ranges", "3000", "--outq-bytes", "60000", "--outq-late-notice"],
                env={"RENEF_FRAMING": "off"})
    out = lines(r.out)
    check(out[0] == "3016" and out[1] == "4", "maps/modules with a late notice: %r" % out[:2])
    lacks(r.out + r.err, "output queue full")
    has(r.out, "[dropped by the app]")
    # and with framing, pages are used from the start: nothing is ever dropped
    r = session("framed", ["om~?", ":sync libc.so", "f~sym.libc.so.~?"],
                mock_args=["--ranges", "3000", "--outq-bytes", "262144"])
    out = lines(r.out)
    check(out[0] == "3016" and out[-1] == "1506", "framed with a bounded queue: %r" % out)
    lacks(r.out + r.err, "dropped")


def t_exec_stall(mode):
    # A public server stays in its exec handler for seconds after the output
    # is out and reads nothing meanwhile: what follows an exec must wait
    # for it instead of timing out, and the listing must not cost a stall
    # per page.
    r = session(mode, [":sync libc.so", ":hook 0x%x" % (TARGET + 0x4100), ":hooks", "p8 4 @ 0x%x" % (HEAP + 0x123),
                       ":exec print(1+1)", ":la", ":info"],
                mock_args=["--exec-stall-ms", "1200"])
    has(r.out, "1506 exports of libc.so flagged")
    has(r.out, "hook #0 installed at 0x%x (libtarget.so+0x4100, inline)" % (TARGET + 0x4100))
    has(r.out, "  [0] 0x%x libtarget.so+0x4100 inline hits=0" % (TARGET + 0x4100))
    has(r.out, mock.SECRET[:4].hex() + "\n2\nOK\ncom.example.app\n")
    lacks(r.out, "timed out")
    has(r.out, "read path md")
    n_exec = len(r.cmds("exec"))
    check(n_exec <= 6, "%d execs on a server where each one costs seconds" % n_exec)


BOTH = ("framed", "legacy")
TESTS = [
    (t_open, BOTH), (t_attach_and_uri, BOTH), (t_env_host, ("framed",)),
    (t_read, BOTH), (t_read_md_path, BOTH), (t_read_verification, ("framed",)), (t_no_maps, BOTH),
    (t_write, BOTH), (t_write_unmapped, BOTH), (t_native_search_and_seek, BOTH),
    (t_maps_and_flags, BOTH), (t_maps_modes, BOTH), (t_many_ranges, BOTH),
    (t_hooks, BOTH), (t_hook_safety, BOTH), (t_hooks_from_script, BOTH), (t_hook_custom_body, BOTH),
    (t_strace, BOTH), (t_search, BOTH), (t_hookgen, BOTH), (t_call, BOTH), (t_patch, BOTH), (t_diff, BOTH), (t_scripts, BOTH),
    (t_stale_reply, BOTH), (t_unsolicited, BOTH), (t_fragmented, BOTH), (t_forced_modes, ("framed",)),
    (t_exec_stall, ("legacy",)), (t_output_queue, ("framed",)),
    (t_java_classes, BOTH), (t_java_hooks, BOTH), (t_java_native, BOTH), (t_java_native_old_agent, ("framed",)),
    (t_java_old_server, BOTH), (t_java_helper_in_sync, ("framed",)),
    (t_interrupt, BOTH), (t_second_open, BOTH), (t_open_failures, BOTH), (t_cache, ("framed",)),
    (t_xom_read, BOTH), (t_event_channel, ("framed",)),
]


def main():
    global ARGS, VERBOSE
    ap = argparse.ArgumentParser()
    ap.add_argument("--plugin", required=True, help="path to the built io_renef plugin")
    ap.add_argument("--r2", default="r2")
    ap.add_argument("--lua", default=os.environ.get("LUA") or "lua")
    ap.add_argument("--sanitizer-runtime", help="preload this library into r2 (ASan runtime, for a "
                    "plugin built with -fsanitize=address); any sanitizer report fails the test")
    ap.add_argument("-k", default="", help="only run tests whose name contains this")
    ap.add_argument("-v", action="store_true")
    ARGS = ap.parse_args()
    VERBOSE = ARGS.v
    ARGS.plugin = os.path.abspath(ARGS.plugin)
    if not os.path.exists(ARGS.plugin):
        sys.exit("plugin not found: " + ARGS.plugin)
    if not shutil.which(ARGS.r2):
        print("SKIP: r2 not found")
        sys.exit(77)
    if not shutil.which(ARGS.lua):
        print("SKIP: no Lua interpreter (%s); the mock server needs one, set $LUA" % ARGS.lua)
        sys.exit(77)
    ver = subprocess.run([ARGS.lua, "-v"], capture_output=True, text=True)
    print("r2: %s" % subprocess.run([ARGS.r2, "-v"], capture_output=True, text=True).stdout.split("\n")[0])
    print("lua: %s" % (ver.stdout or ver.stderr).strip())

    failed, ran = [], 0
    t_all = time.time()
    for fn, modes in TESTS:
        if ARGS.k not in fn.__name__:
            continue
        for mode in modes:
            name = "%s[%s]" % (fn.__name__[2:], mode)
            t0 = time.time()
            ran += 1
            try:
                fn(mode)
                print("ok    %-34s %5.1fs" % (name, time.time() - t0))
            except Failure as e:
                failed.append(name)
                print("FAIL  %-34s %5.1fs\n%s" % (name, time.time() - t0, e))
            except Exception:
                failed.append(name)
                print("ERROR %-34s\n%s" % (name, traceback.format_exc()))
            sys.stdout.flush()
    print("%d run, %d failed, %.1fs" % (ran, len(failed), time.time() - t_all))
    if failed:
        print("failed: " + ", ".join(failed))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
