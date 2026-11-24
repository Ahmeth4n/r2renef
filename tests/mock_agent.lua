-- Fake renef agent for tests/mock_renef_server.py.
--
-- One long-lived Lua interpreter stands in for the Lua VM that lives inside
-- the target process: scripts sent with `exec` really run here, against an
-- emulation of the parts of the renef API that r2renef uses, backed by the
-- fake process the server wrote to <statedir> (maps.txt, state.lua and one
-- mem_<start>.bin per backed range).
--
-- Deliberately unforgiving where the real agent is: Memory.read/write
-- dereference raw pointers on the device, so touching an address that is
-- not mapped (or not readable/writable) "crashes the target" - this
-- process exits with status 139 and the server reports the agent as gone.
--
-- Protocol with the server (stdin/stdout):
--   request:  "<kind> <len>\n" + <len> bytes      kind X = exec, F = fire hook
--   reply:    "P <len>\n" + bytes   for every line printed
--             "H <index> <addr> <caller|->\n"   a hook was installed
--             "E <len>\n" + bytes   Lua error text (the real agent only logs it)
--             "C <reason>\n"        the target crashed (the process exits)
--             "D <0|1>\n"           done, 1 = chunk ran without error

local statedir = assert(arg[1], "usage: mock_agent.lua <statedir>")
local real_open = io.open
local stdin, stdout = io.stdin, io.stdout
local S = dofile(statedir .. "/state.lua")

local function emit(line)
	line = tostring(line)
	stdout:write("P ", #line, "\n", line)
end

local function crash(why)
	stdout:write("C ", why, "\n")
	stdout:flush()
	os.exit(139)
end

local function note_error(msg)
	msg = tostring(msg)
	stdout:write("E ", #msg, "\n", msg)
end

local function find_range(addr)
	for _, r in ipairs(S.ranges) do
		if addr >= r.start and addr < r.stop then
			return r
		end
	end
	return nil
end

local function mem_read(addr, n)
	local out, a = {}, addr
	while n > 0 do
		local r = find_range(a)
		if not r or r.perms:sub(1, 1) ~= "r" then
			crash(string.format("read of 0x%x", a))
		end
		local take = math.min(n, r.stop - a)
		local f = assert(real_open(statedir .. "/" .. r.file, "rb"))
		f:seek("set", a - r.start)
		out[#out + 1] = f:read(take)
		f:close()
		a = a + take
		n = n - take
	end
	return table.concat(out)
end

local function mem_write(addr, data, need_w)
	local a, pos = addr, 1
	while pos <= #data do
		local r = find_range(a)
		if not r or (need_w and r.perms:sub(2, 2) ~= "w") then
			crash(string.format("write to 0x%x", a))
		end
		local take = math.min(#data - pos + 1, r.stop - a)
		local f = assert(real_open(statedir .. "/" .. r.file, "r+b"))
		f:seek("set", a - r.start)
		f:write(data:sub(pos, pos + take - 1))
		f:close()
		a = a + take
		pos = pos + take
	end
end

-- print(): one line per argument, like the agent's lua_print
function print(...)
	local n = select("#", ...)
	for i = 1, n do
		emit(tostring((select(i, ...))))
	end
end

console = { log = function(msg) emit(msg) end }

-- /proc/self/maps is the fake one; everything else behaves normally
io.open = function(path, mode)
	if path == "/proc/self/maps" then
		if S.no_maps then
			return nil, "/proc/self/maps: Permission denied"
		end
		return real_open(statedir .. "/maps.txt", mode or "r")
	end
	return real_open(path, mode)
end

local function lib_range_lines(name)
	local t = {}
	for _, r in ipairs(S.ranges) do
		if r.path:find(name, 1, true) then
			t[#t + 1] = r
		end
	end
	return t
end

Module = {}

-- first r--p / r-xp line of every .so path, as raw maps lines
function Module.list()
	local seen, out = {}, {}
	for line in S.maps:gmatch("[^\n]+") do
		local perms, path = line:match("^%x+%-%x+ (%S+) %S+ %S+ %S+%s+(.+)$")
		if path and path:find(".so", 1, true) and (perms == "r-xp" or perms == "r--p") and not seen[path] then
			seen[path] = true
			out[#out + 1] = line .. "\n"
		end
	end
	return table.concat(out)
end

function Module.find(name)
	local t = lib_range_lines(name)
	if #t == 0 then
		return nil
	end
	return t[1].start
end

local function sym_table(which, name)
	for path, list in pairs(S[which]) do
		if path:find(name, 1, true) then
			local t = {}
			for i, e in ipairs(list) do
				t[i] = { name = e.name, offset = e.offset }
			end
			return t
		end
	end
	return nil
end

function Module.exports(name) return sym_table("exports", name) end
function Module.symbols(name) return sym_table("symbols", name) end

Memory = {}

function Memory.read(addr, size)
	if size > 0x100000 then size = 0x100000 end
	return mem_read(addr, size)
end

function Memory.write(addr, data)
	mem_write(addr, data, true)
	return true
end

function Memory.patch(addr, data)
	local a, left = addr, #data
	while left > 0 do
		local r = find_range(a)
		if not r then
			emit(string.format("ERROR: mprotect failed at 0x%x", addr))
			return false, "mprotect failed"
		end
		local take = math.min(left, r.stop - a)
		a = a + take
		left = left - take
	end
	mem_write(addr, data, false)
	emit(string.format("\226\156\147 Patched %d bytes at 0x%x", #data, addr))
	return true
end

function Memory.readStr(addr, max)
	local s = mem_read(addr, max or 256)
	local z = s:find("\0", 1, true)
	return z and s:sub(1, z - 1) or s
end

-- Same dispatch as lua_mem_search: a blank or "??" makes it a byte
-- pattern, anything else is searched as a literal string.
local function parse_pattern(str)
	local pat, p = {}, 1
	while p <= #str and #pat < 256 do
		local c = str:sub(p, p)
		if c == " " then
			p = p + 1
		elseif str:sub(p, p + 1) == "??" then
			pat[#pat + 1] = -1
			p = p + 2
		elseif c:match("%x") then
			pat[#pat + 1] = tonumber(str:sub(p, p + 1), 16) or 0
			p = p + 2
		else
			p = p + 1
		end
	end
	return pat
end

function Memory.search(input, lib)
	local pat
	if input:find(" ", 1, true) or input:find("??", 1, true) then
		pat = parse_pattern(input)
	else
		pat = { input:byte(1, -1) }
	end
	local res = {}
	for _, r in ipairs(S.ranges) do
		local skip = r.perms:sub(1, 1) ~= "r" or (lib and not r.path:find(lib, 1, true))
			or (not lib and r.path:find("/dev/", 1, true))
		if not skip and r.stop - r.start >= #pat then
			local data = mem_read(r.start, r.stop - r.start)
			for i = 1, #data - #pat + 1 do
				local ok = true
				for j = 1, #pat do
					if pat[j] >= 0 and data:byte(i + j - 1) ~= pat[j] then
						ok = false
						break
					end
				end
				if ok then
					res[#res + 1] = { library = r.path, addr = r.start + i - 1, offset = i - 1, hex = "", ascii = "" }
					if #res >= 1000 then
						return res
					end
				end
			end
		end
	end
	return res
end

-- hooks ---------------------------------------------------------------

local hooks = {}        -- [index] = { addr, lib, off, caller, onEnter, onLeave, removed }
local in_hook = nil     -- set while a callback runs

function hook(lib, off, cbs)
	if type(off) ~= "number" then
		error("Java hooks are not emulated")
	end
	if type(cbs) ~= "table" then
		error("Callbacks must be a table")
	end
	local base = Module.find(lib)
	if not base then
		error("Failed to install native hook")   -- (the agent would defer it)
	end
	local caller = cbs.caller
	local h = { addr = base + off, lib = lib, off = off, onEnter = cbs.onEnter, onLeave = cbs.onLeave }
	if caller then
		-- PLT/GOT: resolved by the name of the exported symbol at that address
		local name
		for _, e in ipairs(Module.exports(lib) or {}) do
			if e.offset == off then name = e.name end
		end
		if not name then
			error("Failed to install native hook")
		end
		h.caller = type(caller) == "table" and table.concat(caller, ",") or caller
		h.symbol = name
	else
		local r = find_range(h.addr)
		if not r or r.perms:sub(3, 3) ~= "x" then
			error("Failed to install native hook")
		end
		if r.perms:sub(1, 1) ~= "r" and not S.xom_safe then
			-- an engine without the execute-only fixes reads the prologue
			crash(string.format("inline hook on execute-only 0x%x", h.addr))
		end
	end
	hooks[#hooks + 1] = h
	stdout:write(string.format("H %d %d %s\n", #hooks - 1, h.addr, h.caller or "-"))
end

Thread = {}
function Thread.id() return 4242 end

function Thread.backtrace()
	local frames = in_hook and S.backtrace or S.agent_backtrace
	local t = {}
	for i, f in ipairs(frames) do
		t[i] = { index = i, pc = f.pc, module = f.module, symbol = f.symbol, offset = f.offset }
	end
	return setmetatable(t, { __tostring = function(self)
		local lines = {}
		for i, f in ipairs(self) do
			lines[i] = string.format("  #%02d  %s  %s", f.index, f.module or "???", f.symbol or "")
		end
		return table.concat(lines, "\n")
	end })
end

-- syscalls ------------------------------------------------------------

local traced = {}
Syscall = {}

local function sys_def(name)
	for _, d in ipairs(S.syscalls) do
		if d.name == name then return d end
	end
end

function Syscall.trace(...)
	local args = { ... }
	if #args == 0 then error("Syscall.trace requires at least one argument") end
	if #args == 1 and type(args[1]) == "table" and args[1].category then
		local n = 0
		for _, d in ipairs(S.syscalls) do
			if d.category == args[1].category then traced[d.name] = true n = n + 1 end
		end
		if n == 0 then error("No syscalls found for category: " .. args[1].category) end
		emit(string.format("Tracing %d %s syscalls", n, args[1].category))
		return n
	end
	local n = 0
	for _, a in ipairs(args) do
		if type(a) == "string" then
			if sys_def(a) then
				traced[a] = true
				n = n + 1
			else
				emit("Warning: Failed to trace '" .. a .. "'")
			end
		end
	end
	if n > 0 then emit(string.format("Tracing %d syscall(s)", n)) end
	return n
end

function Syscall.traceAll()
	local n = 0
	for _, d in ipairs(S.syscalls) do
		if d.name ~= "getpid" and d.name ~= "getuid" then traced[d.name] = true n = n + 1 end
	end
	emit(string.format("Tracing all %d syscalls", n))
	return n
end

function Syscall.untrace(...)
	local n = 0
	for _, a in ipairs({ ... }) do
		if traced[a] then traced[a] = nil n = n + 1 end
	end
	emit(string.format("Removed %d trace(s)", n))
	return n
end

function Syscall.stop()
	traced = {}
	emit("Syscall tracing stopped")
end

function Syscall.list(category)
	local t = {}
	for _, d in ipairs(S.syscalls) do
		if not category or d.category == category then t[#t + 1] = d end
	end
	emit(string.format("Available syscalls (%d):", #t))
	local cur
	for _, d in ipairs(t) do
		if d.category ~= cur then
			cur = d.category
			emit("\n  [" .. cur .. "]")
		end
		emit(string.format("    %s (%d args)", d.name, d.args))
	end
	return t
end

function Syscall.active()
	local t = {}
	for _, d in ipairs(S.syscalls) do
		if traced[d.name] then t[#t + 1] = { name = d.name, category = d.category, hooks = 3 } end
	end
	emit(string.format("Active traces: %d", #t))
	return t
end

-- test helpers (not part of renef) -----------------------------------

function __mock_sleep(ms)
	local t = os.clock()
	os.execute(string.format("sleep %.3f", ms / 1000))
	return os.clock() - t
end

-- request loop --------------------------------------------------------

local function fire(spec)
	local words = {}
	for w in spec:gmatch("%S+") do words[#words + 1] = w end
	local kind = words[1]
	if kind == "hook" then
		local h = hooks[tonumber(words[2]) + 1]
		if not h or h.removed then return end
		local args = {}
		for i = 0, 7 do args[i] = tonumber(words[3 + i] or "0") or 0 end
		in_hook = h
		if h.onEnter then h.onEnter(args) end
		if h.onLeave then h.onLeave(tonumber(words[11] or "0") or 0) end
		in_hook = nil
	elseif kind == "unhook" then
		if words[2] == "all" then
			local n = 0
			for _, h in ipairs(hooks) do
				if not h.removed then h.removed = true n = n + 1 end
			end
			emit(tostring(n))
		else
			local h = hooks[tonumber(words[2]) + 1]
			if h and not h.removed then
				h.removed = true
				emit("1")
			else
				emit("0")
			end
		end
	elseif kind == "syscall" then
		if traced[words[2]] then
			emit(string.format("[tid:4242] %s(%s) = %s", words[2], words[3] or "", words[4] or "0"))
		end
	end
end

while true do
	local hdr = stdin:read("l")
	if not hdr then break end
	local kind, n = hdr:match("^(%a) (%d+)$")
	local body = stdin:read(tonumber(n))
	if tonumber(n) == 0 then body = "" end
	local ok = true
	if kind == "X" then
		local f, err = load(body, "=exec")
		if not f then
			ok = false
			note_error(err)
		else
			local okk, e = pcall(f)
			if not okk then
				ok = false
				note_error(e)
			end
		end
	else
		local okk, e = pcall(fire, body)
		if not okk then
			ok = false
			note_error(e)
		end
	end
	stdout:write("D ", ok and "1" or "0", "\n")
	stdout:flush()
end
