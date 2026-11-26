#!/usr/bin/env python3
"""A stand-in for renef_server, for testing r2renef without a device.

It speaks the renef wire protocol on a TCP port:

  --mode framed   like current renef builds: "@req <id> <len>\\n<payload>"
                  is answered with the output followed by "\\x1e@done <id>\\n";
                  unframed commands still work ("a chunk ended in \\n and
                  50ms passed")
  --mode legacy   like public renef <= 0.3.7: no framing at all, a frame
                  header is just an unknown command

`exec` really runs its Lua: tests/mock_agent.lua emulates the agent's Lua
API on top of a small fake process (a few libraries, an execute-only one,
a heap), so the scripts r2renef generates are executed, not pattern
matched. Reading or writing memory that is not mapped kills the fake
target, exactly as it would kill the real one.

Extra commands for tests (never sent by r2renef itself):
  mock.fire hook <index> [x0 .. x7 [retval]]   run a hook's callbacks
  mock.fire jhook <index> <result|-|!> [args]  run a Java hook's callbacks; values are
                                               s:text n:5 b:0aff o:a.b.Class null, the
                                               result "-" is none and "!" an exception
  mock.fire syscall <name> <args> <ret>        emit a syscall trace line
  mock.fire_in <ms> <same as mock.fire>        ... after a delay
  mock.late <ms> <text>                        write <text> to the client later
  mock.state                                   one line of counters

Needs a Lua 5.4+ interpreter: --lua, $LUA or `lua` on PATH.
"""

import argparse
import json
import os
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

DONE_MARK = b"\x1e@done "
REQ_PREFIX = b"@req "
MAX_CMD = 8 * 1024 * 1024

LIBC = "/apex/com.android.runtime/lib64/bionic/libc.so"
LIBTARGET = "/data/app/~~Qm9ndXM=/com.example.app-c2FsdA==/lib/arm64/libtarget.so"
LIBCRYPTO = "/system/lib64/libcrypto.so"
LIBAGENT = "/data/local/tmp/.r/libagent.so"
APK = "/data/app/~~Qm9ndXM=/com.example.app-c2FsdA==/base.apk"

LIBC_BASE = 0x7000000000
LIBTARGET_BASE = 0x7100000000
LIBCRYPTO_BASE = 0x7200000000
HEAP_BASE = 0x7400000000
LIBAGENT_BASE = 0x7600000000

SECRET = b"r2renef-secret-token"
SECRET_OFF = 0x123

PROLOGUE = bytes.fromhex("fd7bbfa9" "fd030091" "e00300aa" "fd7bc1a8" "c0035fd6")
NOP = bytes.fromhex("1f2003d5")


def lua_str(s):
    out = ['"']
    for ch in s.encode():
        if ch in (0x22, 0x5c):
            out.append("\\" + chr(ch))
        elif ch < 0x20 or ch >= 0x7f:
            out.append("\\%03d" % ch)
        else:
            out.append(chr(ch))
    out.append('"')
    return "".join(out)


class FakeProcess:
    """Memory layout and contents of the pretend target."""

    def __init__(self, statedir, extra_ranges=0, no_maps=False, xom_safe=True):
        self.dir = statedir
        self.ranges = []     # dicts: start, stop, perms, offset, path, file
        self.exports = {}
        self.symbols = {}
        self._build(extra_ranges)
        self._write_state(no_maps, xom_safe)

    def _add(self, start, size, perms, path="", offset=0, data=None, file=None):
        r = {"start": start, "stop": start + size, "perms": perms, "offset": offset,
             "path": path, "file": file or ("mem_%x.bin" % start)}
        if file is None:
            if data is None:
                data = bytes(size)
            assert len(data) == size
            with open(os.path.join(self.dir, r["file"]), "wb") as f:
                f.write(data)
        self.ranges.append(r)
        return r

    @staticmethod
    def _pattern(size, seed):
        # every byte value shows up, including 0x00, 0x0a and 0x1e
        return bytes(((i * 7 + seed) ^ (i >> 8)) & 0xff for i in range(size))

    @staticmethod
    def _code(size, entries):
        buf = bytearray(NOP * (size // 4))
        for off in entries:
            buf[off:off + len(PROLOGUE)] = PROLOGUE
        return bytes(buf)

    def _lib(self, path, base, text_perms, exports, symbols=None, text_size=0x8000):
        hdr = bytearray(self._pattern(0x4000, base & 0xff))
        hdr[0:8] = b"\x7fELF\x02\x01\x01\x00"
        self._add(base, 0x4000, "r--p", path, 0, bytes(hdr))
        entries = [off - 0x4000 for _, off in exports + (symbols or []) if 0x4000 <= off < 0x4000 + text_size]
        self._add(base + 0x4000, text_size, text_perms, path, 0x4000, self._code(text_size, entries))
        data_start = base + 0x4000 + text_size
        self._add(data_start, 0x2000, "rw-p", path, 0x4000 + text_size, self._pattern(0x2000, 0x55))
        self.exports[path] = [{"name": n, "offset": o} for n, o in exports]
        self.symbols[path] = [{"name": n, "offset": o} for n, o in exports + (symbols or [])]

    def _build(self, extra_ranges):
        libc_exports = [("open", 0x4100), ("read", 0x4140), ("write", 0x4180), ("malloc", 0x41c0),
                        ("free", 0x4200), ("strlen", 0x4240)]
        # enough exports to need several pages of output
        libc_exports += [("fn_%04d" % i, 0x5000 + i * 16) for i in range(1500)]
        self._lib(LIBC, LIBC_BASE, "r-xp", libc_exports, text_size=0xc000)
        self._add(LIBC_BASE + 0x12000, 0x2000, "rw-p", "[anon:.bss]")

        self._lib(LIBTARGET, LIBTARGET_BASE, "r-xp",
                  [("JNI_OnLoad", 0x4100), ("Java_com_example_app_MainActivity_check", 0x4140),
                   ("mock_sum", 0x4300)],
                  symbols=[("secret_check", 0x4200)])
        # execute-only text, as on devices that enforce XOM for system libraries
        self._lib(LIBCRYPTO, LIBCRYPTO_BASE, "--xp",
                  [("SHA256_Init", 0x4000), ("SHA256_Update", 0x4040)])

        self._add(0x7300000000, 0x1000, "---p", "[anon:stack_and_tls:main]", file="-")
        heap = bytearray(self._pattern(0x8000, 0x11))
        heap[SECRET_OFF:SECRET_OFF + len(SECRET)] = SECRET
        heap[0x200:0x300] = bytes(range(256))
        # bytes that look like a completion marker, sitting in memory
        heap[0x400:0x400 + 10] = DONE_MARK + b"7\n\x00"
        heap[0x1000:0x1004] = bytes.fromhex("504b0304")
        heap[0x5000:0x5004] = bytes.fromhex("504b0304")
        self._add(HEAP_BASE, 0x8000, "rw-p", "[anon:scudo:primary]", data=bytes(heap))
        self._add(0x7500000000, 0x4000, "r--p", APK, 0x1000, self._pattern(0x4000, 0x77))
        self._lib(LIBAGENT, LIBAGENT_BASE, "r-xp", [("agent_main", 0x4000)])
        if extra_ranges:
            with open(os.path.join(self.dir, "mem_filler.bin"), "wb") as f:
                f.write(bytes(0x1000))
            for i in range(extra_ranges):
                # a gap after each one, so they are not merged
                self._add(0x7700000000 + i * 0x2000, 0x1000, "rw-p", "[anon:filler%d]" % (i % 7),
                          file="mem_filler.bin")
        self._add(0x7ff0000000, 0x21000, "rw-p", "[stack]", data=self._pattern(0x21000, 0x33))
        self.ranges.sort(key=lambda r: r["start"])

    def maps_text(self):
        lines = []
        for r in self.ranges:
            dev, inode = ("fd:00", 1234) if r["path"].startswith("/") else ("00:00", 0)
            line = "%x-%x %s %08x %s %d" % (r["start"], r["stop"], r["perms"], r["offset"], dev, inode)
            if r["path"]:
                line = line.ljust(72) + " " + r["path"]
            lines.append(line)
        return "\n".join(lines) + "\n"

    def _write_state(self, no_maps, xom_safe):
        maps = self.maps_text()
        with open(os.path.join(self.dir, "maps.txt"), "w") as f:
            f.write(maps)

        def symtab(d):
            parts = []
            for path, lst in d.items():
                ents = ",".join("{name=%s,offset=%d}" % (lua_str(e["name"]), e["offset"]) for e in lst)
                parts.append("[%s]={%s}" % (lua_str(path), ents))
            return "{" + ",".join(parts) + "}"

        ranges = ",".join(
            "{start=%d,stop=%d,perms=%s,path=%s,file=%s}"
            % (r["start"], r["stop"], lua_str(r["perms"]), lua_str(r["path"]), lua_str(r["file"]))
            for r in self.ranges)
        syscalls = [("openat", "file", 4), ("read", "file", 3), ("write", "file", 3), ("close", "file", 1),
                    ("connect", "network", 3), ("sendto", "network", 6), ("mmap", "memory", 6),
                    ("getpid", "process", 0), ("getuid", "process", 0)]
        sys_lua = ",".join("{name=%s,category=%s,args=%d}" % (lua_str(n), lua_str(c), a) for n, c, a in syscalls)
        bt = [(LIBTARGET_BASE + 0x4150, "libtarget.so", "Java_com_example_app_MainActivity_check"),
              (LIBTARGET_BASE + 0x4110, "libtarget.so", "JNI_OnLoad"),
              (LIBC_BASE + 0x4190, "libc.so", None)]
        abt = [(LIBAGENT_BASE + 0x4010, "libagent.so", "agent_main")]

        def frames(lst):
            return ",".join("{pc=%d,module=%s%s}" % (pc, lua_str(m), (",symbol=" + lua_str(s)) if s else "")
                            for pc, m, s in lst)

        with open(os.path.join(self.dir, "state.lua"), "w") as f:
            f.write("return {\n maps=%s,\n ranges={%s},\n exports=%s,\n symbols=%s,\n syscalls={%s},\n"
                    " backtrace={%s},\n agent_backtrace={%s},\n no_maps=%s,\n xom_safe=%s\n}\n"
                    % (lua_str(maps), ranges, symtab(self.exports), symtab(self.symbols), sys_lua,
                       frames(bt), frames(abt), "true" if no_maps else "false", "true" if xom_safe else "false"))

    def range_at(self, addr):
        for r in self.ranges:
            if r["start"] <= addr < r["stop"]:
                return r
        return None

    def read(self, addr, size):
        """bytes, or None if any part is unmapped or unreadable (md's guard)"""
        out = b""
        while size > 0:
            r = self.range_at(addr)
            if not r or r["perms"][0] != "r":
                return None
            take = min(size, r["stop"] - addr)
            with open(os.path.join(self.dir, r["file"]), "rb") as f:
                f.seek(addr - r["start"])
                out += f.read(take)
            addr += take
            size -= take
        return out


    def read_raw(self, addr, size):
        """what /proc/<pid>/mem gives a privileged reader: permissions do not
        matter, only whether something is mapped. -> bytes (possibly short)"""
        out = b""
        while size > 0:
            r = self.range_at(addr)
            if not r or r["file"] == "-":
                break
            take = min(size, r["stop"] - addr)
            with open(os.path.join(self.dir, r["file"]), "rb") as f:
                f.seek(addr - r["start"])
                out += f.read(take)
            addr += take
            size -= take
        return out


class Agent:
    """The Lua VM "inside the target"."""

    def __init__(self, lua, statedir, log):
        here = os.path.dirname(os.path.abspath(__file__))
        self.proc = subprocess.Popen([lua, os.path.join(here, "mock_agent.lua"), statedir],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.lock = threading.Lock()
        self.crashed = False
        self.hooks = []      # dicts: addr, caller, removed
        self.jhooks = []     # dicts: key, removed, hits
        self.log = log

    def _request(self, kind, body):
        """-> (lines, ok); raises RuntimeError once the target is gone"""
        with self.lock:
            if self.crashed:
                raise RuntimeError("agent gone")
            try:
                self.proc.stdin.write(b"%s %d\n" % (kind, len(body)) + body)
                self.proc.stdin.flush()
            except (BrokenPipeError, OSError):
                self.crashed = True
                raise RuntimeError("agent gone")
            lines = []
            while True:
                hdr = self.proc.stdout.readline()
                if not hdr:
                    self.crashed = True
                    self.log("crash", why="agent exited")
                    raise RuntimeError("agent gone")
                tag, _, rest = hdr.rstrip(b"\n").partition(b" ")
                if tag == b"P":
                    lines.append(self.proc.stdout.read(int(rest)))
                elif tag == b"E":
                    self.log("luaerr", msg=self.proc.stdout.read(int(rest)).decode("utf-8", "replace"))
                elif tag == b"H":
                    idx, addr, caller = rest.split(b" ", 2)
                    self.hooks.append({"addr": int(addr), "caller": caller.decode(), "removed": False})
                    self.log("hook", index=int(idx), addr="0x%x" % int(addr), caller=caller.decode())
                elif tag == b"J":
                    idx, key = rest.split(b" ", 1)
                    self.jhooks.append({"key": key.decode(), "removed": False, "hits": 0})
                    self.log("jhook", index=int(idx), key=key.decode())
                elif tag == b"C":
                    self.crashed = True
                    self.log("crash", why=rest.decode("utf-8", "replace"))
                    raise RuntimeError("agent gone")
                elif tag == b"D":
                    return lines, rest == b"1"

    def exec(self, code):
        return self._request(b"X", code)

    def fire(self, spec):
        return self._request(b"F", spec)

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=2)
        except Exception:
            self.proc.kill()


class Session:
    """One client connection."""

    def __init__(self, server, conn):
        self.srv = server
        self.conn = conn
        self.wlock = threading.Lock()
        self.agent = None
        self.pid = 0
        self.agent_buf = b""         # output the agent produced between commands
        self.hook_hits = {}          # hook index -> calls
        self.buf_lock = threading.Lock()
        self.alive = True
        self.statedir = None
        self.proc = None

    # -- output ---------------------------------------------------------

    def send(self, data):
        if not data:
            return
        with self.wlock:
            try:
                chunk = self.srv.args.chunk
                if chunk > 0:
                    for i in range(0, len(data), chunk):
                        self.conn.sendall(data[i:i + chunk])
                        if self.srv.args.chunk_delay_ms:
                            time.sleep(self.srv.args.chunk_delay_ms / 1000.0)
                else:
                    self.conn.sendall(data)
            except OSError:
                self.alive = False

    # -- target ---------------------------------------------------------

    def start_target(self):
        if self.agent:
            self.agent.close()
        if self.statedir:
            shutil.rmtree(self.statedir, ignore_errors=True)
        self.statedir = tempfile.mkdtemp(prefix="mock_renef_")
        self.proc = FakeProcess(self.statedir, self.srv.args.ranges, self.srv.args.no_maps,
                                not self.srv.args.xom_crash)
        self.agent = Agent(self.srv.args.lua, self.statedir, self.srv.log)
        self.pid = 4242
        self.agent_buf = b""

    def agent_exec(self, code):
        """-> output bytes, or None if the agent is gone"""
        try:
            lines, ok = self.agent.exec(code)
        except RuntimeError:
            return None
        limit = self.srv.args.outq_bytes
        if limit:
            # the agent's bounded output queue: a message that cannot fit is
            # dropped whole, otherwise the oldest ones go
            kept, dropped = [], 0
            for l in lines:
                if len(l) + 1 > limit:
                    dropped += 1
                else:
                    kept.append(l)
            while sum(len(l) + 1 for l in kept) > limit:
                kept.pop(0)
                dropped += 1
            lines = kept
            late = getattr(self, "late_notice", None)
            self.late_notice = None
            if late:
                lines.insert(0, late)
            if dropped:
                notice = b"[dropped %d messages, output queue full]" % dropped
                if self.srv.args.outq_late_notice:
                    # as seen on a device without framing: the notice only
                    # leaves the agent together with its next output
                    self.late_notice = notice
                else:
                    lines.append(notice)
        out = b"".join(l + b"\n" for l in lines)
        return out + (b"OK\n" if ok else b"ERROR: Lua execution failed\n")

    def fire(self, spec):
        if not self.agent:
            return
        try:
            lines, _ = self.agent.fire(spec)
        except RuntimeError:
            return
        parts = spec.split()
        if len(parts) >= 2 and parts[0] == b"hook" and parts[1].isdigit():
            self.hook_hits[int(parts[1])] = self.hook_hits.get(int(parts[1]), 0) + 1
        if len(parts) >= 2 and parts[0] == b"jhook" and parts[1].isdigit() \
                and int(parts[1]) < len(self.agent.jhooks):
            self.agent.jhooks[int(parts[1])]["hits"] += 1
        with self.buf_lock:
            self.agent_buf += b"".join(l + b"\n" for l in lines)

    @property
    def event_channel(self):
        """Hook output travels apart from replies (renef builds whose agent
        opens a second connection for it): it is never part of a reply, the
        completion marker says how many lines wait, `events` hands them out."""
        return self.srv.args.mode == "framed" and not self.srv.args.no_event_channel

    def pending_lines(self):
        with self.buf_lock:
            return self.agent_buf.count(b"\n") if self.event_channel else 0

    # -- commands -------------------------------------------------------

    def handle(self, raw):
        full = raw.rstrip(b"\n\r \x00")
        if full.startswith(b"renef://"):
            full = full[8:]
        # same splitting as CommandRegistry::dispatch_fixed, including its
        # habit of taking everything before a "//" for the command name
        d = full.find(b"//")
        if d != -1:
            name = full[:d]
        else:
            cut = [i for i in (full.find(b" "), full.find(b"~")) if i != -1]
            name = full[:min(cut)] if cut else full
        args = full[len(name):].lstrip(b" ")
        self.srv.log("cmd", name=name.decode("utf-8", "replace"), size=len(full),
                     text=full[:300].decode("utf-8", "replace"))
        fn = getattr(self, "cmd_" + name.decode("ascii", "replace").replace(".", "_").replace("-", "_"), None) \
            if name.replace(b".", b"").replace(b"-", b"").replace(b"_", b"").isalnum() else None
        if not fn:
            self.send(b"ERROR: Unknown command. Type 'help' for available commands.\n")
            return
        if self.agent and name != b"watch" and not name.startswith(b"mock.") and not self.event_channel:
            with self.buf_lock:
                self.agent_buf = b""    # drain_buffer(): stale agent output is dropped
        fn(args, full)

    def need_target(self):
        if not self.pid:
            self.send(b"ERROR: No target PID set. Please attach/spawn first.\n")
            return False
        if self.agent.crashed:
            self.send(b"ERROR: Failed to connect to agent\n")
            return False
        return True

    def cmd_ping(self, args, full):
        self.send(b"pong\n")

    def cmd_la(self, args, full):
        self.send(b"com.example.app\ncom.android.settings\n")

    def cmd_spawn(self, args, full):
        pkg = args.split(b" ")[0]
        if not pkg:
            self.send(b"ERROR: Invalid package name\n")
            return
        if pkg == b"com.fail.app":
            self.send(b"ERROR: Failed to launch app\n")
            return
        time.sleep(self.srv.args.spawn_delay_ms / 1000.0)
        self.start_target()
        self.send(b"OK %d\n" % self.pid)

    def cmd_attach(self, args, full):
        if not args.isdigit():
            self.send(b"ERROR: Invalid PID\n")
            return
        if args == b"999":
            self.send(b"FAIL\n")
            return
        self.start_target()
        self.pid = int(args)
        self.send(b"OK\n")

    def cmd_exec(self, args, full):
        if not self.need_target():
            return
        code = full[5:] if len(full) > 5 else b""
        for _ in range(2):
            if code.startswith(b"--json "):
                code = code[7:]
            if code.startswith(b"--timeout "):
                rest = code[10:].split(b" ", 1)
                code = rest[1] if len(rest) > 1 else b""
        if not code:
            self.send(b"ERROR: Usage: exec <lua_code>\n")
            return
        out = self.agent_exec(code)
        if out is None:
            self.send(b"ERROR: exec got no completion from target (agent connection closed)\n")
        else:
            self.send(out)
        # public renef: the exec handler only returns after seconds of silence
        # from the agent, and the server reads no further command until then
        if self.srv.args.exec_stall_ms:
            time.sleep(self.srv.args.exec_stall_ms / 1000.0)

    def cmd_memdump(self, args, full):
        # renef_server reads /proc/<pid>/mem itself; only builds that also
        # have framing know the command
        if self.srv.args.mode != "framed" or self.srv.args.no_memdump:
            self.send(b"ERROR: Unknown command. Type 'help' for available commands.\n")
            return
        parts = args.split()
        if len(parts) != 2 or not parts[0].isdigit() or b"-" not in parts[1]:
            self.send(b"MEMDUMP_ERROR reason=usage_memdump_<pid>_--maps_or_<start>-<end>\n")
            return
        try:
            start, end = (int(x, 16) for x in parts[1].split(b"-", 1))
        except ValueError:
            self.send(b"MEMDUMP_ERROR reason=invalid_range_hex_parse_failed\n")
            return
        if end <= start:
            self.send(b"MEMDUMP_ERROR reason=end_must_be_greater_than_start\n")
            return
        self.srv.log("memdump", pid=int(parts[0]), start=start, size=end - start)
        out = [b"MEMDUMP_MANIFEST pid=%s starttime=1 comm=mock start=0x%x end=0x%x requested=%d"
               % (parts[0], start, end, end - start)]
        addr, total, ok, bad = start, 0, 0, 0
        while addr < end:
            data = self.proc.read_raw(addr, min(end - addr, 65536))
            if data:
                out.append(b"SEG OK start=0x%x len=%d hex=%s" % (addr, len(data), data.hex().encode()))
                addr += len(data)
                total += len(data)
                ok += 1
            else:
                skip = min(end - addr, 4096)
                out.append(b"SEG ERR start=0x%x len=%d errno=5 msg=Input/output error" % (addr, skip))
                addr += skip
                bad += 1
        out.append(b"MEMDUMP_SUMMARY total_requested=%d total_read=%d segments_ok=%d segments_err=%d hash=0"
                   % (end - start, total, ok, bad))
        out.append(b"MEMDUMP_END")
        self.send(b"\n".join(out) + b"\n")

    def cmd_md(self, args, full):
        parts = args.split()
        if len(parts) < 2:
            self.send(b"Usage: md <address> <size> [-d for disassemble]\n")
            return
        try:
            addr = int(parts[0], 16) if parts[0].lower().startswith(b"0x") else int(parts[0])
            size = int(parts[1])
        except ValueError:
            self.send(b"ERROR: Invalid address format. Use hex (0x...) or decimal.\n")
            return
        if size == 0 or size > 4096:
            self.send(b"Size must be between 1 and 4096 bytes\n")
            return
        if not self.need_target():
            return
        data = self.proc.read(addr, size)
        if data is None:
            self.send(b"ERROR: Invalid memory address or access violation\n")
            return
        out = ["Memory at 0x%x (%d bytes):\n" % (addr, len(data))]
        for i in range(0, len(data), 16):
            row = data[i:i + 16]
            line = "0x%08x:  " % (addr + i)
            line += "".join("%02x " % b for b in row)
            line += "   " * (16 - len(row))
            line += " |" + "".join(chr(b) if 32 <= b <= 126 else "." for b in row) + "|\n"
            out.append(line)
        self.send("".join(out).encode("latin-1"))

    def cmd_hooks(self, args, full):
        if not self.need_target():
            return
        hooks = self.agent.hooks
        out = "Active hooks: %d\n" % len(hooks)
        for i, h in enumerate(hooks):
            if h["removed"]:
                out += "  [%d] (removed)\n" % i
            elif h["caller"] != "-":
                # the agent prints the first patched GOT slot for these
                out += "  [%d] target=0x%x\n" % (i, LIBTARGET_BASE + 0xc000 + 0x100 + i * 8)
            elif self.event_channel:
                # agents with the event channel also count the calls
                out += "  [%d] target=0x%x hits=%d\n" % (i, h["addr"], self.hook_hits.get(i, 0))
            else:
                out += "  [%d] target=0x%x\n" % (i, h["addr"])
        # agents since 0.4.0 list Java hooks too, once there is one
        jhooks = self.agent.jhooks
        if jhooks and not self.srv.args.no_java_list:
            out += "Java hooks: %d\n" % len(jhooks)
            for i, h in enumerate(jhooks):
                if h["removed"]:
                    out += "  [j%d] (removed)\n" % i
                else:
                    out += "  [j%d] %s hits=%d\n" % (i, h["key"], h["hits"])
        self.send(out.encode())

    def cmd_events(self, args, full):
        if not self.event_channel:
            self.send(b"ERROR: Unknown command. Type 'help' for available commands.\n")
            return
        if not self.need_target():
            return
        try:
            wait_ms = int(args or b"0")
        except ValueError:
            wait_ms = 0
        deadline = time.time() + wait_ms / 1000.0
        while True:
            with self.buf_lock:
                pending, self.agent_buf = self.agent_buf, b""
            if pending or time.time() >= deadline:
                break
            time.sleep(0.01)
        self.srv.log("events", wait=wait_ms, size=len(pending))
        self.send(pending)

    def cmd_unhook(self, args, full):
        if not self.need_target():
            return
        spec = args.decode() or "all"
        try:
            lines, _ = self.agent.fire(("unhook " + spec).encode())
        except RuntimeError:
            self.send(b"ERROR: No response from agent\n")
            return
        n = int(lines[0]) if lines else 0
        if spec == "all":
            for h in self.agent.hooks + self.agent.jhooks:
                h["removed"] = True
            self.send(b"Removed %d hook(s)\n" % n)
        elif n and spec.startswith("j"):
            self.agent.jhooks[int(spec[1:])]["removed"] = True
            self.send(b"Hook %s removed\n" % spec.encode())
        elif n:
            self.agent.hooks[int(spec)]["removed"] = True
            self.send(b"Hook %d removed\n" % int(spec))
        else:
            self.send(b"ERROR: Failed to remove hook\n")

    def cmd_hookgen(self, args, full):
        parts = args.split()
        if not parts:
            self.send(b"Usage:\n  hookgen <lib_name> <offset_hex>  - Generate hook for specific offset\n")
            return
        lib = parts[0].decode()
        off = None
        if len(parts) >= 2:
            try:
                off = int(parts[1], 16)
            except ValueError:
                for path, lst in self.proc.exports.items():
                    if lib in path:
                        for e in lst:
                            if e["name"] == parts[1].decode():
                                off = e["offset"]
        if off is None:
            self.send(("ERROR:Symbol not found in %s\n" % lib).encode())
            return
        o = "0x%x" % off
        self.send(('hook("%s", %s, {\n'
                   '    onEnter = function(args)\n'
                   '        print("[+] %s+%s called")\n'
                   '        print("    arg0: " .. string.format("0x%%x", args[0]))\n'
                   '        print("    arg1: " .. string.format("0x%%x", args[1]))\n'
                   '    end,\n'
                   '    onLeave = function(retval)\n'
                   '        print("[-] Returning: " .. string.format("0x%%x", retval))\n'
                   '        return retval\n'
                   '    end\n'
                   '})\n' % (lib, o, lib, o)).encode())

    def cmd_watch(self, args, full):
        if not self.need_target():
            return
        with self.buf_lock:
            pending, self.agent_buf = self.agent_buf, b""
        self.send(pending)
        self.send(b"Watching hook output... (waiting for hooks to trigger)\n")
        while self.alive:
            r, _, _ = select.select([self.conn], [], [], 0.02)
            if r:
                try:
                    got = self.conn.recv(31)    # any byte from the client ends watch
                except OSError:
                    got = b""
                self.srv.log("watch_stop", got=got.decode("latin-1"))
                if not got:
                    self.alive = False
                break
            with self.buf_lock:
                pending, self.agent_buf = self.agent_buf, b""
            self.send(pending)

    # -- test controls --------------------------------------------------

    def cmd_mock_fire(self, args, full):
        self.fire(args)
        self.send(b"mock ok\n")

    def cmd_mock_fire_in(self, args, full):
        ms, _, spec = args.partition(b" ")
        threading.Timer(int(ms) / 1000.0, self.fire, [spec]).start()
        self.send(b"mock ok\n")

    def cmd_mock_late(self, args, full):
        ms, _, text = args.partition(b" ")
        threading.Timer(int(ms) / 1000.0, self.send, [text + b"\n"]).start()
        self.send(b"mock ok\n")

    def cmd_mock_state(self, args, full):
        st = {"crashed": bool(self.agent and self.agent.crashed),
              "hooks": len(self.agent.hooks) if self.agent else 0}
        self.send((json.dumps(st) + "\n").encode())

    # -- the receive loop (TransportServer::handle_client) ---------------

    def readable(self, timeout):
        r, _, _ = select.select([self.conn], [], [], timeout)
        return bool(r)

    @staticmethod
    def take_request(buf):
        """-> (state, id, payload, rest): 1 complete, 0 need more, -1 not a frame, -2 malformed"""
        if len(buf) < len(REQ_PREFIX):
            return (0 if buf and REQ_PREFIX.startswith(buf) else -1), 0, b"", buf
        if not buf.startswith(REQ_PREFIX):
            return -1, 0, b"", buf
        nl = buf.find(b"\n")
        if nl == -1:
            return (-2 if len(buf) > 64 else 0), 0, b"", buf
        parts = buf[len(REQ_PREFIX):nl].split(b" ")
        if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit() or int(parts[0]) == 0:
            return -2, 0, b"", buf
        rid, ln = int(parts[0]), int(parts[1])
        if ln > MAX_CMD:
            return -2, 0, b"", buf
        if len(buf) < nl + 1 + ln:
            return 0, 0, b"", buf
        return 1, rid, buf[nl + 1:nl + 1 + ln], buf[nl + 1 + ln:]

    def run(self):
        framed = self.srv.args.mode == "framed"
        inbuf = b""
        while self.alive:
            command, req_id = None, 0
            while True:
                state = -1
                if framed and inbuf:
                    state, rid, payload, rest = self.take_request(inbuf)
                    if state == 1:
                        command, req_id, inbuf = payload, rid, rest
                        break
                    if state == -2:
                        self.send(b"ERROR: Malformed request frame\n")
                        return
                if framed and state == -1 and inbuf:
                    q = inbuf.find(b"\n" + REQ_PREFIX)
                    if q != -1:
                        command, inbuf = inbuf[:q], inbuf[q + 1:]
                        break
                if state == -1 and inbuf.endswith(b"\n"):
                    if not self.readable(0.05):
                        command, inbuf = inbuf, b""
                        break
                try:
                    data = self.conn.recv(65536)
                except OSError:
                    data = b""
                if not data:
                    return
                inbuf += data
                if len(inbuf) > MAX_CMD:
                    self.send(b"ERROR: Command too large\n")
                    return
            if command.endswith(b"\n"):
                command = command[:-1]
            if command:
                self.handle(command)
            if req_id:
                pending = self.pending_lines()
                self.send(DONE_MARK + b"%d%s\n" % (req_id, b" ev=%d" % pending if pending else b""))

    def close(self):
        self.alive = False
        if self.agent:
            self.agent.close()
        if self.statedir:
            shutil.rmtree(self.statedir, ignore_errors=True)
        try:
            self.conn.close()
        except OSError:
            pass


class Server:
    def __init__(self, args):
        self.args = args
        self.logf = open(args.log, "a") if args.log else None
        self.loglock = threading.Lock()

    def log(self, ev, **kw):
        if not self.logf:
            return
        with self.loglock:
            kw.update(ev=ev, t=round(time.time(), 3))
            self.logf.write(json.dumps(kw) + "\n")
            self.logf.flush()

    def serve(self):
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind((self.args.host, self.args.port))
        ls.listen(4)
        print("LISTENING %d" % ls.getsockname()[1], flush=True)
        while True:
            conn, peer = ls.accept()    # one client at a time, like renef_server
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.log("connect", peer="%s:%d" % peer)
            sess = Session(self, conn)
            try:
                sess.run()
            finally:
                sess.close()
                self.log("disconnect")
            if self.args.once:
                return


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0, help="0 picks a free port (printed as LISTENING <port>)")
    ap.add_argument("--mode", choices=["framed", "legacy"], default="framed")
    ap.add_argument("--lua", default=os.environ.get("LUA") or "lua")
    ap.add_argument("--log", help="append one JSON line per event to this file")
    ap.add_argument("--chunk", type=int, default=0, help="send replies in pieces of this many bytes")
    ap.add_argument("--chunk-delay-ms", type=int, default=0)
    ap.add_argument("--spawn-delay-ms", type=int, default=0)
    ap.add_argument("--ranges", type=int, default=0, help="extra anonymous ranges in the fake process")
    ap.add_argument("--no-maps", action="store_true", help="/proc/self/maps cannot be opened in the target")
    ap.add_argument("--xom-crash", action="store_true",
                    help="an inline hook on execute-only code kills the target (hook engine without the fixes)")
    ap.add_argument("--no-event-channel", action="store_true",
                    help="framed server whose agent mixes hook output into replies (no event channel, no events command)")
    ap.add_argument("--no-memdump", action="store_true",
                    help="framed server without the memdump command (cannot read execute-only code)")
    ap.add_argument("--outq-bytes", type=int, default=0,
                    help="bound on the output of one exec (renef builds with the agent output queue: 262144)")
    ap.add_argument("--outq-late-notice", action="store_true",
                    help="the queue's drop notice arrives with the output of the next exec")
    ap.add_argument("--exec-stall-ms", type=int, default=0,
                    help="stay busy this long after every exec (public renef <= 0.3.7 does so for 5000 ms)")
    ap.add_argument("--no-method-info", action="store_true",
                    help="the agent has no Java.methodInfo (renef 0.4.0)")
    ap.add_argument("--no-java-list", action="store_true",
                    help="`hooks` does not list Java hooks (renef before 0.4.0)")
    ap.add_argument("--once", action="store_true", help="exit after the first client disconnects")
    args = ap.parse_args()
    if args.no_method_info:
        os.environ["MOCK_NO_METHOD_INFO"] = "1"   # read by mock_agent.lua
    if args.port == 1907:
        sys.exit("refusing to listen on 1907: that is the real renef_server port")
    if not shutil.which(args.lua):
        sys.exit("no Lua interpreter found (%s); set --lua or $LUA" % args.lua)
    try:
        Server(args).serve()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
