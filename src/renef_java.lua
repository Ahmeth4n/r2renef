-- r2renef - MIT - Copyright 2025-2026
--
-- Java side of r2renef. This file runs inside the target: the plugin sends
-- it once per session (see renef_java.c) and then calls the functions of
-- __r2j from its :jc / :jm / :jhook commands. Every line meant for the
-- plugin starts with "@r2:"; everything else is ordinary hook output.
--
-- It only uses renef's public Lua API (Java.*, hook, Jni.*, JNI.*, Thread.*).

local VERSION = 2
if __r2j and __r2j.version == VERSION then
	print("@r2:L " .. VERSION)
	return
end

local M = { version = VERSION, hooks = {} }
local TAG = "@r2:"

local function out(kind, ...)
	print(TAG .. kind .. " " .. table.concat({ ... }, "\t"))
end

-- java classes this file needs ------------------------------------------

local J = {}
local function need(key, path)
	if J[key] == nil then
		local ok, c = pcall(Java.use, path)
		J[key] = (ok and c) or false
	end
	return J[key] or nil
end
local function Class_() return need("class", "java/lang/Class") end
local function Array_() return need("array", "java/lang/reflect/Array") end
local function System_() return need("system", "java/lang/System") end
local function String_() return need("string", "java/lang/String") end
local function Log_() return need("log", "android/util/Log") end

local function app_loader()
	local ok, loader = pcall(function()
		local at = need("at", "android/app/ActivityThread")
		local app = at and at:call("currentApplication", "()Landroid/app/Application;")
		return app and app:call("getClassLoader", "()Ljava/lang/ClassLoader;")
	end)
	return ok and loader or nil
end

-- Class object for a dotted name, without running its static initialiser.
local function for_name(name)
	local C = Class_()
	if not C then return nil end
	local loader = app_loader()
	if loader then
		local ok, c = pcall(function()
			return C:call("forName", "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;", name, false, loader)
		end)
		if ok and c then return c end
	end
	local ok, c = pcall(function()
		return C:call("forName", "(Ljava/lang/String;)Ljava/lang/Class;", name)
	end)
	return ok and c or nil
end

local function each(arr, fn)
	local A = Array_()
	if not arr or not A then return 0 end
	local n = A:call("getLength", "(Ljava/lang/Object;)I", arr) or 0
	for i = 0, n - 1 do
		fn(A:call("get", "(Ljava/lang/Object;I)Ljava/lang/Object;", arr, i), i)
	end
	return n
end

-- type names -------------------------------------------------------------

local PRIM = { boolean = "Z", byte = "B", char = "C", short = "S", int = "I",
	long = "J", float = "F", double = "D", void = "V" }
local PRIM_NAME = {}
for k, v in pairs(PRIM) do PRIM_NAME[v] = k end

-- Class.getName() -> JNI type: "int" -> I, "a.b.C" -> La/b/C;, "[La.b.C;" -> [La/b/C;
local function jni_type(name)
	if PRIM[name] then return PRIM[name] end
	if name:sub(1, 1) == "[" then return (name:gsub("%.", "/")) end
	return "L" .. name:gsub("%.", "/") .. ";"
end

-- JNI type -> what a person reads: Ljava/lang/String; -> String, [B -> byte[]
local function pretty_type(t)
	local dims = 0
	while t:sub(1, 1) == "[" do dims = dims + 1 t = t:sub(2) end
	local base = PRIM_NAME[t]
	if not base then
		base = t:gsub("^L", ""):gsub(";$", ""):gsub("/", ".")
		base = base:match("[^.]+$") or base
	end
	return base .. string.rep("[]", dims)
end

local function short_name(class)
	return class:match("[^.]+$") or class
end

-- classes ----------------------------------------------------------------

local class_cache
local function app_classes()
	if not class_cache then
		local ok, t = pcall(Java.enumerateLoadedClasses)
		class_cache = (ok and type(t) == "table") and t or {}
	end
	return class_cache
end

function M.classes(filter, limit)
	local all = app_classes()
	local want = filter and filter ~= "" and filter:lower() or nil
	local shown, hits = 0, 0
	for i = 1, #all do
		local name = all[i]
		if not want or name:lower():find(want, 1, true) then
			hits = hits + 1
			if shown < limit then
				shown = shown + 1
				out("C", name)
			end
		end
	end
	out("N", tostring(hits), tostring(#all))
end

-- Packages tried for a bare name that is not one of the app's classes.
local COMMON = { "java.lang.", "java.io.", "java.util.", "java.net.", "java.security.",
	"javax.crypto.", "javax.net.ssl.", "android.app.", "android.content.", "android.os.",
	"android.util.", "android.webkit." }

-- name as typed -> full dotted class name, or nil after reporting why not.
local function resolve(name)
	name = name:gsub("/", ".")
	if name:find(".", 1, true) then
		if for_name(name) then return name end
		out("E", "class not found: " .. name)
		return nil
	end
	local found = {}
	local all = app_classes()
	for i = 1, #all do
		local c = all[i]
		local last = c:match("[^.]+$") or c
		if last == name or last:match("%$([^$]+)$") == name then found[#found + 1] = c end
	end
	if #found == 1 then return found[1] end
	if #found > 1 then
		for i = 1, math.min(#found, 40) do out("A", found[i]) end
		out("E", string.format("%d classes are called %s, give the full name:", #found, name))
		return nil
	end
	for i = 1, #COMMON do
		if for_name(COMMON[i] .. name) then return COMMON[i] .. name end
	end
	out("E", "class not found: " .. name .. " (:jc " .. name:lower() .. " searches the app's classes)")
	return nil
end

-- members ----------------------------------------------------------------

local ACC_STATIC, ACC_NATIVE, ACC_ABSTRACT = 0x8, 0x100, 0x400
local ACC_BRIDGE, ACC_SYNTHETIC = 0x40, 0x1000

local function params_of(m)
	local types = {}
	each(m:call("getParameterTypes", "()[Ljava/lang/Class;"), function(pt)
		types[#types + 1] = jni_type(pt:call("getName", "()Ljava/lang/String;"))
	end)
	return types
end

-- Every method and constructor of a class as a plain table. With `keep`
-- each entry also holds its reflection object (m.obj).
local function members(cls, keep)
	local list = {}
	each(cls:call("getDeclaredConstructors", "()[Ljava/lang/reflect/Constructor;"), function(c)
		list[#list + 1] = { name = "<init>", mods = c:call("getModifiers", "()I") or 0,
			params = params_of(c), ret = "V", ctor = true, obj = keep and c or nil }
	end)
	each(cls:call("getDeclaredMethods", "()[Ljava/lang/reflect/Method;"), function(m)
		local rt = m:call("getReturnType", "()Ljava/lang/Class;")
		list[#list + 1] = { name = m:call("getName", "()Ljava/lang/String;"),
			mods = m:call("getModifiers", "()I") or 0, params = params_of(m),
			ret = jni_type(rt:call("getName", "()Ljava/lang/String;")), obj = keep and m or nil }
	end)
	for _, m in ipairs(list) do
		m.sig = "(" .. table.concat(m.params) .. ")" .. m.ret
		m.static = (m.mods & ACC_STATIC) ~= 0
		m.native = (m.mods & ACC_NATIVE) ~= 0
		m.abstract = (m.mods & ACC_ABSTRACT) ~= 0
		-- made by the compiler (covariant returns, lambdas, accessors)
		m.synthetic = not m.ctor and (m.mods & (ACC_BRIDGE | ACC_SYNTHETIC)) ~= 0
	end
	table.sort(list, function(a, b)
		if a.ctor ~= b.ctor then return a.ctor == true end
		if a.name ~= b.name then return a.name < b.name end
		return a.sig < b.sig
	end)
	collectgarbage()            -- drop the reflection objects (and their references) now
	return list
end

local function pretty_params(m)
	local p = {}
	for i, t in ipairs(m.params) do p[i] = pretty_type(t) end
	return table.concat(p, ", ")
end

local function pretty_member(class, m)
	if m.ctor then
		return "new " .. short_name(class) .. "(" .. pretty_params(m) .. ")"
	end
	local words = {}
	if m.static then words[#words + 1] = "static" end
	if m.abstract then words[#words + 1] = "abstract" end
	if m.native then words[#words + 1] = "native" end
	words[#words + 1] = pretty_type(m.ret)
	words[#words + 1] = m.name .. "(" .. pretty_params(m) .. ")"
	return table.concat(words, " ")
end

function M.members(name, filter, all)
	local class = resolve(name)
	if not class then return end
	local cls = for_name(class)
	local ok, err = pcall(function()
		local parts = { class }
		local sup = cls:call("getSuperclass", "()Ljava/lang/Class;")
		if sup then parts[#parts + 1] = "extends " .. sup:call("getName", "()Ljava/lang/String;") end
		local ifs = {}
		each(cls:call("getInterfaces", "()[Ljava/lang/Class;"), function(i)
			ifs[#ifs + 1] = i:call("getName", "()Ljava/lang/String;")
		end)
		if #ifs > 0 then
			parts[#parts + 1] = (cls:call("isInterface", "()Z") and "extends " or "implements ") .. table.concat(ifs, ", ")
		end
		out("H", (cls:call("isInterface", "()Z") and "interface " or "class ") .. table.concat(parts, " "))
		local want = filter and filter ~= "" and filter:lower() or nil
		local n, hidden = 0, 0
		for _, m in ipairs(members(cls)) do
			local text = pretty_member(class, m)
			if not want or text:lower():find(want, 1, true) then
				if m.synthetic and not all then
					hidden = hidden + 1
				else
					n = n + 1
					out("M", text, m.sig)
				end
			end
		end
		out("N", tostring(n), tostring(hidden))
	end)
	if not ok then out("E", "cannot list " .. class .. ": " .. tostring(err)) end
end

-- where the code is ------------------------------------------------------

local function type_matches(t, typed)
	local p = pretty_type(t)
	if typed == p then return true end
	local full = t:gsub("^L", ""):gsub(";$", ""):gsub("/", ".")
	return typed == full
end

local function no_method_info()
	if Java.methodInfo then return false end
	out("E", "this renef has no Java.methodInfo (it came with 0.4.1): update renef_server and libagent.so")
	return true
end

-- The name ART looks for when a native method is called for the first time
-- and nothing was registered for it: Java_<class>_<method>, with the JNI
-- escapes (_1 for "_", _00024 for "$" and so on).
local function jni_symbol(class, method)
	local function mangle(text)
		return (text:gsub("[^%w/.]", function(c)
			if c == "_" then return "_1" end
			if c == ";" then return "_2" end
			if c == "[" then return "_3" end
			return string.format("_0%04x", c:byte())
		end):gsub("[/.]", "_"))
	end
	return "Java_" .. mangle(class) .. "_" .. mangle(method)
end

-- Where a method that is not bound yet will be bound: the library of the
-- app that exports its JNI name.
local function by_export(class, method, libs)
	if not libs or not Module.findExportByName then return nil end
	local sym = jni_symbol(class, method)
	for _, lib in ipairs(libs) do
		local ok, hits = pcall(Module.findExportByName, lib, sym)
		if ok and type(hits) == "table" then
			for _, e in ipairs(hits) do
				if e.name == sym then
					local base = Module.find(lib)
					if base then return base + e.offset end
				end
			end
		end
	end
	return nil
end

-- native methods of one class:
-- "J <address> <1 bound|0 not bound|e by export name|? unknown> <class> <name> <text>"
local function natives_of(class, libs)
	local cls = for_name(class)
	if not cls then return 0 end
	local n = 0
	local ok, list = pcall(members, cls, true)
	if not ok then return 0 end
	for _, m in ipairs(list) do
		if m.native then
			local info = Java.methodInfo(m.obj)
			if info and info.jni then
				n = n + 1
				local addr = info.jni
				local bound = (info.bound == nil) and "?" or (info.bound and "1" or "0")
				if bound == "0" then
					local there = by_export(class, m.name, libs)
					if there then addr, bound = there, "e" end
				end
				out("J", string.format("%x", addr), bound, class, m.name, pretty_member(class, m))
			end
		end
	end
	list = nil
	collectgarbage()            -- the reflection objects hold references in the target
	return n
end

-- name: one class, or with `all` a filter over the app's classes.
-- libs: the app's own libraries, for methods that are not bound yet.
function M.natives(name, all, libs)
	if no_method_info() then return end
	if not all then
		local class = resolve(name)
		if not class then return end
		out("N", tostring(natives_of(class, libs)), "1")
		return
	end
	local want = name ~= "" and name:lower() or nil
	local classes, found = 0, 0
	for _, class in ipairs(app_classes()) do
		if not want or class:lower():find(want, 1, true) then
			classes = classes + 1
			found = found + natives_of(class, libs)
		end
	end
	out("N", tostring(found), tostring(classes))
end

-- compiled code of the methods called `method`: "X <entry> <jni|0> <hooked> <class> <name> <text>"
function M.code(name, method, types)
	if no_method_info() then return end
	local class = resolve(name)
	if not class then return end
	if method == "new" or method == short_name(class) then method = "<init>" end
	local ok, list = pcall(members, for_name(class), true)
	if not ok then
		out("E", "cannot list " .. class .. ": " .. tostring(list))
		return
	end
	local n, same = 0, 0
	for _, m in ipairs(list) do
		if m.name == method then
			same = same + 1
			local fits = true
			if types then
				fits = #types == #m.params
				for i = 1, #m.params do
					if fits and not type_matches(m.params[i], types[i]) then fits = false end
				end
			end
			if fits and (not m.synthetic or types) then
				local info = Java.methodInfo(m.obj)
				if info then
					n = n + 1
					out("X", string.format("%x", info.entry), string.format("%x", info.jni or 0),
						info.hooked and "1" or "0", class, m.name, pretty_member(class, m))
				end
			end
		end
	end
	if same == 0 then
		out("E", class .. " has no method " .. method .. " (:jm " .. short_name(class) .. " lists them)")
	elseif n == 0 then
		for _, m in ipairs(list) do
			if m.name == method then out("A", pretty_member(class, m)) end
		end
		out("E", "no " .. method .. " with these parameter types. There is:")
	end
end

-- values in hook output --------------------------------------------------

-- First bytes of a byte[] as hex, and its length. java.util.Arrays does
-- the reading: a pentester's own hooks sit on Base64 far more often.
local function bytes_hex(ref, max)
	local A, Ar = Array_(), need("arrays", "java/util/Arrays")
	local n = A:call("getLength", "(Ljava/lang/Object;)I", ref)
	local head = ref
	if n > max then head = Ar:call("copyOf", "([BI)[B", ref, max) end
	local text = Ar:call("toString", "([B)Ljava/lang/String;", head)
	local hex = {}
	for num in text:gmatch("-?%d+") do hex[#hex + 1] = string.format("%02x", tonumber(num) & 0xFF) end
	return table.concat(hex), n
end

local function quoted(s)
	if #s > 200 then s = s:sub(1, 200) .. "…" end
	return '"' .. s:gsub('[%c"\\]', function(c)
		if c == '"' or c == "\\" then return "\\" .. c end
		if c == "\n" then return "\\n" end
		return string.format("\\x%02x", c:byte())
	end) .. '"'
end

local BOXED = { ["Ljava/lang/Integer;"] = true, ["Ljava/lang/Long;"] = true, ["Ljava/lang/Boolean;"] = true,
	["Ljava/lang/Short;"] = true, ["Ljava/lang/Byte;"] = true, ["Ljava/lang/Character;"] = true,
	["Ljava/lang/Double;"] = true, ["Ljava/lang/Float;"] = true }
-- declared types whose value is often really a String
local MAYBE_STRING = { ["Ljava/lang/Object;"] = true, ["Ljava/lang/CharSequence;"] = true,
	["Ljava/io/Serializable;"] = true, ["Ljava/lang/Comparable;"] = true }

local string_class
local function is_string(ref)
	if string_class == nil then string_class = for_name("java.lang.String") or false end
	if not string_class then return false end
	local ok, yes = pcall(function() return string_class:call("isInstance", "(Ljava/lang/Object;)Z", ref) end)
	return ok and yes == true
end

local function to_string(ref)
	local S = String_()
	local ok, s = pcall(function() return S:call("valueOf", "(Ljava/lang/Object;)Ljava/lang/String;", ref) end)
	return ok and type(s) == "string" and s or nil
end

-- One argument or return value as text. `t` is its declared JNI type, `v`
-- what the hook engine hands over: the number, or a reference for objects.
local function fmt(t, v, deep)
	if t == "Z" then return (v ~= 0 and v ~= false) and "true" or "false" end
	if t == "C" then
		local ok, ch = pcall(utf8.char, v)
		return ok and ("'" .. ch .. "'") or tostring(v)
	end
	if t == "I" or t == "S" or t == "B" or t == "J" then return tostring(v) end
	if t == "F" or t == "D" then return "<" .. PRIM_NAME[t] .. ">" end
	if v == nil or v == 0 then return "null" end
	if t == "Ljava/lang/String;" or (MAYBE_STRING[t] and is_string(v)) then
		local ok, s = pcall(Jni.getStringUTF, v)
		return ok and type(s) == "string" and quoted(s) or "<String>"
	end
	if t == "[B" then
		local ok, hex, total = pcall(bytes_hex, v, 32)
		if ok and hex then
			return string.format("byte[%d] %s%s", total, hex, total > 32 and "…" or "")
		end
		return "byte[]"
	end
	if t:sub(1, 1) == "[" then
		local A = Array_()
		local ok, n = pcall(function() return A:call("getLength", "(Ljava/lang/Object;)I", v) end)
		local p = pretty_type(t)
		return ok and n and (p:sub(1, -3) .. "[" .. n .. "]") or p
	end
	if deep or BOXED[t] then
		local s = to_string(v)
		if s then return BOXED[t] and s or (pretty_type(t) .. " " .. quoted(s)) end
	end
	local Sy = System_()
	local ok, h = pcall(function() return Sy:call("identityHashCode", "(Ljava/lang/Object;)I", v) end)
	return pretty_type(t) .. "@" .. (ok and h and string.format("%x", h & 0xFFFFFFFF) or "?")
end
M.fmt = fmt

local function stack_lines(label)
	local ok, text = pcall(function()
		local T = need("throwable", "java/lang/Throwable")
		return Log_():call("getStackTraceString", "(Ljava/lang/Throwable;)Ljava/lang/String;", T:new("()V"))
	end)
	if not ok or type(text) ~= "string" then return end
	local n = 0
	for raw in text:gmatch("[^\n]+") do
		local line = raw:gsub("^%s+", "")
		if line:sub(1, 3) == "at " then
			n = n + 1
			if n <= 16 then print(label .. "     " .. line) end
		end
	end
end

-- hooks ------------------------------------------------------------------

-- The value -r asked for, in the form onLeave has to return for type `t`.
local function forced(t, text)
	if text == "null" then return true, 0 end
	if t == "Z" then
		if text == "true" or text == "1" then return true, 1 end
		if text == "false" or text == "0" then return true, 0 end
		return false, "a boolean is true or false"
	end
	if t == "I" or t == "S" or t == "B" or t == "C" or t == "J" then
		local n = math.tointeger(tonumber(text))
		if not n then return false, "expected a whole number" end
		return true, (t == "J") and JNI.long(n) or n
	end
	if t == "Ljava/lang/String;" or MAYBE_STRING[t] then return true, JNI.string(text) end
	if t == "V" then return false, "the method returns nothing" end
	return false, "cannot build a " .. pretty_type(t) .. " from text (only null)"
end

local function callbacks(h, opts)
	local m = h.member
	local pending = {}          -- [tid] = call text waiting for its return
	local calls = 0
	local function tag() return "[" .. (h.id or "java") .. "]" end
	local function quiet() return opts.limit and calls > opts.limit end
	local head = m.ctor and ("new " .. short_name(h.class)) or (short_name(h.class) .. "." .. m.name)
	-- call and result on one line, printed when the call returns
	local one_line = m.ret ~= "V" and not m.ctor and not opts.skip

	local cb = {}
	cb.onEnter = function(args)
		calls = calls + 1
		if opts.skip then args.skip = true end
		if opts.body then return opts.body(args) end
		if quiet() then
			if calls == opts.limit + 1 then print(tag() .. " " .. head .. ": further calls are not printed") end
			return
		end
		local parts, idx = {}, m.static and 1 or 2
		for i, t in ipairs(m.params) do
			if t == "F" or t == "D" then
				parts[i] = fmt(t)
			elseif idx > 7 then
				parts[i] = "…"
			else
				parts[i] = fmt(t, args[idx], opts.deep)
				idx = idx + 1
			end
		end
		local text = head .. "(" .. table.concat(parts, ", ") .. ")"
		if opts.deep and not m.static and not m.ctor then
			text = text .. " on " .. fmt("L" .. h.class:gsub("%.", "/") .. ";", args[1], true)
		end
		local tid = Thread.id()
		if pending[tid] then
			-- the previous call on this thread never came back here: it
			-- threw, or this is a call from inside it
			print(tag() .. " " .. pending[tid])
			pending[tid] = nil
		end
		if one_line then
			pending[tid] = text
		elseif opts.skip then
			print(tag() .. " " .. text .. "  (not run" .. (opts.ret and (", returns " .. opts.ret_text) or "") .. ")")
		else
			print(tag() .. " " .. text)
		end
		if opts.bt then stack_lines(tag()) end
	end
	if one_line or opts.ret then
		cb.onLeave = function(retval)
			if not one_line or opts.body or quiet() then return opts.ret end
			local tid = Thread.id()
			local text = pending[tid]
			pending[tid] = nil
			local shown
			if m.ret == "Ljava/lang/String;" and type(retval.value) == "string" then
				shown = quoted(retval.value)
			else
				shown = fmt(m.ret, retval.raw, opts.deep)
			end
			if opts.ret then shown = shown .. "  => " .. opts.ret_text end
			print(tag() .. " " .. (text and (text .. " -> ") or "  -> ") .. shown)
			return opts.ret
		end
	end
	return cb
end

-- opts: types (list or nil), ret (text or nil), skip, bt, limit, deep, all,
-- body (lua source or nil), first (number the agent gives its next Java hook)
function M.hook(name, method, opts)
	local class = resolve(name)
	if not class then return end
	local cls = for_name(class)
	if method == "new" or method == short_name(class) then method = "<init>" end
	local ok_list, list = pcall(members, cls)
	if not ok_list then
		out("E", "cannot list " .. class .. ": " .. tostring(list))
		return
	end
	local picked, same_name = {}, 0
	for _, m in ipairs(list) do
		if m.name == method then
			same_name = same_name + 1
			local fits = true
			if opts.types then
				fits = #opts.types == #m.params
				for i = 1, #m.params do
					if fits and not type_matches(m.params[i], opts.types[i]) then fits = false end
				end
			end
			-- a compiler-made twin is only taken when its types were typed out
			if fits and (not m.synthetic or opts.types or opts.all) then picked[#picked + 1] = m end
		end
	end
	if same_name == 0 then
		out("E", class .. " has no method " .. method .. " (:jm " .. short_name(class) .. " lists them)")
		return
	end
	if #picked == 0 then
		for _, m in ipairs(list) do
			if m.name == method then out("A", pretty_member(class, m)) end
		end
		out("E", "no " .. method .. " with these parameter types. There is:")
		return
	end
	local body
	if opts.body then
		local f, err = load("local args = ... " .. opts.body, "=jhook")
		if not f then
			out("E", "-e: " .. tostring(err))
			return
		end
		body = f
	end
	local path = class:gsub("%.", "/")
	local installed = 0
	for _, m in ipairs(picked) do
		local text = pretty_member(class, m)
		local o = { skip = opts.skip, bt = opts.bt, limit = opts.limit, deep = opts.deep, body = body }
		local reason
		if m.abstract then
			reason = "abstract or interface method: it has no code. Hook the class that implements it"
		elseif opts.ret then
			local ok, val = forced(m.ret, opts.ret)
			if ok then
				o.ret, o.ret_text = val, opts.ret
			else
				reason = "-r " .. opts.ret .. ": " .. val
			end
		end
		if not reason then
			local key = path .. "." .. m.name .. m.sig
			-- The agent numbers its Java hooks in the order they are made
			-- and hook() does not return the number: it is predicted here,
			-- so that the very first call already prints it, and the
			-- plugin corrects it from the `hooks` listing if need be.
			local h = { class = class, member = m,
				id = opts.first and ("j" .. (opts.first + installed)) or nil }
			local ok, err = pcall(hook, path, m.name, m.sig, callbacks(h, o))
			if ok then
				installed = installed + 1
				M.hooks[key] = h
				out("K", key, text, h.id or "")
			else
				reason = tostring(err):gsub("^.-Failed to install Java hook:%s*", "")
			end
		end
		if reason then out("F", text, reason) end
	end
end

-- The plugin learns the hook numbers from the `hooks` listing and passes
-- them on, so that callback output carries the same [jN] as that listing.
function M.bind(key, id)
	local h = M.hooks[key]
	if h then h.id = (id ~= "") and id or nil end
end

__r2j = M
out("L", tostring(VERSION))
