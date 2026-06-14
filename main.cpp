#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <libproc.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <deque>
#include <vector>

#include "dependencies/luau/Compiler/include/Luau/BytecodeBuilder.h"
#include "dependencies/luau/Compiler/include/Luau/Compiler.h"
#include "dependencies/luau/Common/include/Luau/BytecodeUtils.h"
#include "dependencies/luau/VM/include/lua.h"
#include "dependencies/luau/VM/include/lualib.h"
#include "dependencies/luau/VM/src/lobject.h"
#include "dependencies/luau/VM/src/lapi.h"
#include "dependencies/luau/VM/src/lstate.h"
#include "dependencies/tinyhook/include/tinyhook.h"

struct LiveThreadRef {
    uintptr_t padding[3];
    uintptr_t unk;
    uintptr_t padding1;
    void *Thread;
    int ThreadRef;
    int FunctionRef;
};

struct WeakObjectRef {
    void *vftable;
    uint32_t state;
    uint32_t padding;
    LiveThreadRef *LiveThread;
    std::__shared_weak_count *WeakCount;
};

namespace fs = std::filesystem;

static std::mutex  g_log_mtx;
static std::string g_log_path;

static void ss_log(const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (g_log_path.empty()) return;
    std::lock_guard<std::mutex> lk(g_log_mtx);
    FILE *f = fopen(g_log_path.c_str(), "a");
    if (f) { fprintf(f, "%s\n", buf); fclose(f); }
}

static void init_log() {
    const char *home = getenv("HOME");
    if (!home) return;
    std::string dir = std::string(home) + "/Documents/SkidSploit";
    std::error_code ec;
    fs::create_directories(dir, ec);
    g_log_path = dir + "/skidsploit.log";
    FILE *f = fopen(g_log_path.c_str(), "w");
    if (f) { fprintf(f, "=== SkidSploit ===\n"); fclose(f); }
}

static volatile uintptr_t g_roblox_base = 0;

static uintptr_t get_slide() {
    const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(0);
    uintptr_t base = (uintptr_t)header;
    const struct load_command *cmd = (const struct load_command *)(header + 1);
    for (uint32_t i = 0; i < header->ncmds; ++i) {
        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;
            if (strcmp(seg->segname, "__TEXT") == 0)
                return base - seg->vmaddr;
        }
        cmd = (const struct load_command *)((const char *)cmd + cmd->cmdsize);
    }
    return 0;
}

static uintptr_t rebase(uintptr_t addr) {
    return get_slide() + addr;
}

namespace Off {
    constexpr uintptr_t Parent                     = 0x70;
    constexpr uintptr_t PlaceId                    = 0x188;
    constexpr uintptr_t Workspace                  = 0x320;
    constexpr uintptr_t DefaultStateOffset         = 0x1F0;
    constexpr uintptr_t EncryptedStateOffset       = 0x200;
    constexpr int       EncryptedType              = 1;
}

static uintptr_t g_Print;
static uintptr_t g_Defer;
static uintptr_t g_Spawn;
static uintptr_t g_LuauLoad;
static uintptr_t g_LuauTimestampCheck;
static uintptr_t g_LuauBytecodeCheck;
static uintptr_t g_LuauOpcodeLookupTable;
static uintptr_t g_UpdaterFunction;
static uintptr_t g_TaskScheduler;
static uintptr_t g_DTCFlag;
static uintptr_t g_whsj;
static uintptr_t g_TeleportSucceeded;
static uintptr_t g_AssignLuaCallback;
static uintptr_t g_IdentityPropagator;
static uintptr_t g_IdentityToCapabilities;

static void resolve_offsets() {
    g_Print                  = rebase(0x1001E33F0);
    g_Defer                  = rebase(0x101699394);
    g_Spawn                  = rebase(0x101699778);
    g_LuauLoad               = rebase(0x103F21F60);
    g_LuauTimestampCheck     = rebase(0x1016F6680);
    g_LuauBytecodeCheck      = rebase(0x1016F97A0);
    g_LuauOpcodeLookupTable  = rebase(0x1053A7D01);
    g_UpdaterFunction        = rebase(0x101EB270C);
    g_TaskScheduler          = rebase(0x106A32308);
    g_DTCFlag                = rebase(0x101741DB8);
    g_whsj                   = rebase(0x1017836D8);
    g_TeleportSucceeded      = rebase(0x10036AB44);
    g_AssignLuaCallback      = rebase(0x1016DB0A4);
    g_IdentityPropagator     = rebase(0x10173EA98);
    g_IdentityToCapabilities = rebase(0x103F33718);
}

using PrintFn = void (*)(int, const char *, ...);
using DeferFn = void *(*)(void *L);
using SpawnFn = void *(*)(void *L);
using LuauLoadFn = int (*)(void *L, const char *name, const char *bc, size_t sz, int env);
using IdentityToCapsFn = uintptr_t (*)(uint32_t *);
using IdentityPropagatorFn = uintptr_t (*)(void *);

class BytecodeEncoder : public Luau::BytecodeEncoder {
public:
    void encode(uint32_t *data, size_t count) override {
        uint8_t *lut = (uint8_t *)g_LuauOpcodeLookupTable;
        for (size_t i = 0; i < count;) {
            uint8_t op = LUAU_INSN_OP(data[i]);
            auto len = Luau::getOpLength(LuauOpcode(op));
            uint8_t encoded = (uint8_t)(op * 227);
            encoded = lut[encoded];
            data[i] = encoded | (data[i] & ~0xffu);
            i += len;
        }
    }
};

static std::string compile_script(const std::string &source) {
    BytecodeEncoder encoder;
    static const char *mutableGlobals[] = {
        "Game", "Workspace", "game", "plugin", "script", "shared", "workspace", nullptr
    };
    Luau::CompileOptions opts{};
    opts.optimizationLevel = 1;
    opts.debugLevel = 1;
    opts.vectorLib = "Vector3";
    opts.vectorCtor = "new";
    opts.vectorType = "Vector3";
    opts.mutableGlobals = mutableGlobals;
    return Luau::compile(source, opts, {}, &encoder);
}

static std::string http_get(const std::string &url) {
    std::string cmd = "curl -sL --max-time 30 -A 'SkidSploit/1.0.0' '";
    for (char c : url) {
        if (c == '\'') cmd += "'\\''";
        else cmd += c;
    }
    cmd += "' 2>/dev/null";

    FILE *fp = popen(cmd.c_str(), "r");
    if (!fp) return "";

    std::string result;
    char buf[8192];
    while (size_t n = fread(buf, 1, sizeof(buf), fp))
        result.append(buf, n);
    pclose(fp);
    return result;
}

static int skid_httpget(lua_State *L) {
    const char *url = nullptr;
    if (lua_isuserdata(L, 1) && lua_isstring(L, 2))
        url = lua_tostring(L, 2);
    else if (lua_isstring(L, 1))
        url = lua_tostring(L, 1);
    else
        luaL_argerror(L, 1, "string expected");

    ss_log("[SkidSploit] HttpGet: %s", url);
    std::string body = http_get(url);
    ss_log("[SkidSploit] HttpGet returned %zu bytes", body.size());
    lua_pushlstring(L, body.data(), body.size());
    return 1;
}

static lua_CFunction OldNamecallHook = nullptr;
static lua_CFunction OldIndexHook = nullptr;

static int NamecallHook(lua_State *L) {
    if (L->namecall) {
        const char *key = L->namecall->data;
        if (key && (strcmp(key, "HttpGet") == 0 || strcmp(key, "HttpGetAsync") == 0 ||
                    strcmp(key, "GetObjects") == 0))
            return skid_httpget(L);
    }
    if (OldNamecallHook)
        return OldNamecallHook(L);
    return 0;
}

static int IndexHook(lua_State *L) {
    if (lua_isstring(L, 2)) {
        const char *key = lua_tostring(L, 2);
        if (key && (strcmp(key, "HttpGet") == 0 || strcmp(key, "HttpGetAsync") == 0 ||
                    strcmp(key, "GetObjects") == 0)) {
            lua_pushcfunction(L, skid_httpget, "HttpGet");
            return 1;
        }
    }
    if (OldIndexHook)
        return OldIndexHook(L);
    return 0;
}

static uintptr_t (*OldWHSJ)(uintptr_t, uintptr_t *) = nullptr;
static int (*OldBytecodeCheck)(uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t) = nullptr;
static void (*OldTimestampCheck)() = nullptr;
static int (*OldDTCFlag)() = nullptr;
static uintptr_t (*OldUpdateFunction)(uintptr_t, WeakObjectRef *) = nullptr;
static uintptr_t (*OldTeleportSuccess)() = nullptr;
static uintptr_t (*OldAssignLuaCallback)(uintptr_t, uintptr_t, void *, uintptr_t) = nullptr;

static std::atomic<uintptr_t> g_ScriptContext{0};
static std::atomic<uintptr_t> g_DataModel{0};
static std::atomic<void *>    g_LuaState{nullptr};
static std::atomic<bool>      g_Ready{false};

static std::mutex              g_queue_mtx;
static std::deque<std::string> g_ScriptQueue;

static int BytecodeCheckHook(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d, uintptr_t e) { return 0; }
static void TimestampCheckHook() {}

static void set_identity_raw(void *L, uint32_t identity) {
    uintptr_t udata = *(uintptr_t *)((char *)L + 0x08);
    if (!udata || udata < 0x100000) {
        ss_log("[SkidSploit] set_identity: bad userdata=%llx", (unsigned long long)udata);
        return;
    }

    uintptr_t old_id = *(uintptr_t *)(udata + 0x60);
    *(uintptr_t *)(udata + 0x60) = identity;

    uint32_t id = (identity == 0) ? 8 : identity;
    auto id_to_caps = (IdentityToCapsFn)g_IdentityToCapabilities;
    uintptr_t caps = id_to_caps(&id) | 0x3FFFFFFFFFFF00LL;
    *(uintptr_t *)(udata + 0x78) = caps;

    auto propagator = (IdentityPropagatorFn)g_IdentityPropagator;
    uintptr_t cap = propagator(L);
    if (cap) {
        *(uint32_t *)cap = identity;
        *(uintptr_t *)(cap + 0x28) = caps;
    }

    uintptr_t shared_es = *(uintptr_t *)(udata + 0x18);
    if (shared_es) {
        uintptr_t sc = *(uintptr_t *)(shared_es + 0x28);
        if (sc) *(uint8_t *)(sc + 0x7A0 + 0x39) = 1;
    }

    ss_log("[SkidSploit] identity %llu -> %u, caps=%llx udata=%llx",
           (unsigned long long)old_id, identity, (unsigned long long)caps, (unsigned long long)udata);
}

static uintptr_t MaxCapabilities = 0xFFFFFFFFFFFFFFFF;

static void SetProtoCapabilities(Proto *proto) {
    if (!proto)
        return;
    proto->userdata = &MaxCapabilities;
    for (int i = 0; i < proto->sizep; ++i)
        SetProtoCapabilities(proto->p[i]);
}

static int skid_loadstring(lua_State *L) {
    size_t len = 0;
    const char *src = luaL_checklstring(L, 1, &len);
    const char *chunkname = luaL_optlstring(L, 2, "=SkidSploit", nullptr);

    ss_log("[SkidSploit] loadstring: %zu bytes, chunk=%s", len, chunkname);
    std::string bytecode = compile_script(std::string(src, len));
    if (bytecode.empty()) {
        ss_log("[SkidSploit] loadstring: compile failed for %zu bytes", len);
        lua_pushnil(L);
        lua_pushstring(L, "compile failed");
        return 2;
    }

    set_identity_raw(L, 8);

    int rc = luau_load(L, chunkname, bytecode.data(), bytecode.size(), 0);
    if (rc != 0) {
        const char *err = lua_tostring(L, -1);
        ss_log("[SkidSploit] loadstring: luau_load failed: %s", err ? err : "(no msg)");
        lua_pushnil(L);
        lua_insert(L, -2);
        return 2;
    }

    SetProtoCapabilities(clvalue(luaA_toobject(L, -1))->l.p);
    ss_log("[SkidSploit] loadstring: OK, bytecode=%zu bytes", bytecode.size());
    return 1;
}

static int skid_identifyexecutor(lua_State *L) {
    lua_pushstring(L, "SkidSploit");
    lua_pushstring(L, "v1.00");
    return 2;
}

static int skid_getgenv(lua_State *L) {
    lua_pushvalue(L, LUA_ENVIRONINDEX);
    return 1;
}

static int skid_getrenv(lua_State *L) {
    lua_State *main = L->global->mainthread;
    lua_newtable(L);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "_G");
    static const char *keys[] = {
        "print", "warn", "error", "type", "typeof", "tostring", "tonumber",
        "pcall", "xpcall", "select", "unpack", "rawget", "rawset", "rawequal",
        "rawlen", "setmetatable", "getmetatable", "next", "ipairs", "pairs",
        "assert", "require", "spawn", "delay", "wait", "tick", "time",
        "coroutine", "string", "table", "math", "bit32", "os", "debug",
        "game", "workspace", "script", "shared", "Instance", "Vector3",
        "Vector2", "CFrame", "Color3", "BrickColor", "UDim", "UDim2",
        "Enum", "Axes", "Faces", "Ray", "Region3", "TweenInfo",
        "NumberSequence", "ColorSequence", "NumberRange", "Rect",
        nullptr
    };
    for (int i = 0; keys[i]; i++) {
        lua_getglobal(main, keys[i]);
        if (!lua_isnil(L, -1))
            lua_setfield(L, -2, keys[i]);
        else
            lua_pop(L, 1);
    }
    return 1;
}

static int skid_getrawmetatable(lua_State *L) {
    luaL_checkany(L, 1);
    if (!lua_getmetatable(L, 1))
        lua_pushnil(L);
    return 1;
}

static int skid_setrawmetatable(lua_State *L) {
    luaL_checkany(L, 1);
    luaL_checkany(L, 2);
    lua_setmetatable(L, 1);
    return 1;
}

static int skid_iscclosure(lua_State *L) {
    luaL_argexpected(L, lua_isfunction(L, 1), 1, "function");
    lua_pushboolean(L, iscfunction(luaA_toobject(L, 1)));
    return 1;
}

static int skid_islclosure(lua_State *L) {
    luaL_argexpected(L, lua_isfunction(L, 1), 1, "function");
    lua_pushboolean(L, isLfunction(luaA_toobject(L, 1)));
    return 1;
}

static int skid_newcclosure(lua_State *L) {
    luaL_argexpected(L, lua_isfunction(L, 1), 1, "function");
    Closure *cl = clvalue(luaA_toobject(L, 1));
    if (cl->isC) {
        lua_pushvalue(L, 1);
        return 1;
    }
    lua_pushvalue(L, 1);
    return 1;
}

static int skid_checkcaller(lua_State *L) {
    lua_pushboolean(L, 1);
    return 1;
}

static int skid_isexecutorclosure(lua_State *L) {
    luaL_argexpected(L, lua_isfunction(L, 1), 1, "function");
    lua_pushboolean(L, 0);
    return 1;
}

static int skid_getnamecallmethod(lua_State *L) {
    if (L->namecall && L->namecall->data[0] != '\0')
        lua_pushstring(L, getstr(L->namecall));
    else
        lua_pushnil(L);
    return 1;
}

static int skid_getidentity(lua_State *L) {
    uintptr_t udata = *(uintptr_t *)((char *)L + 0x08);
    if (udata && udata > 0x100000) {
        uintptr_t id = *(uintptr_t *)(udata + 0x60);
        lua_pushinteger(L, (int)id);
    } else {
        lua_pushinteger(L, 8);
    }
    return 1;
}

static int skid_setidentity(lua_State *L) {
    luaL_argexpected(L, lua_isnumber(L, 1), 1, "number");
    int id = lua_tointeger(L, 1);
    if (id >= 0 && id <= 12)
        set_identity_raw(L, (uint32_t)id);
    return 0;
}

static int skid_isreadonly(lua_State *L) {
    luaL_argexpected(L, lua_istable(L, 1), 1, "table");
    lua_pushboolean(L, lua_getreadonly(L, 1));
    return 1;
}

static int skid_setreadonly(lua_State *L) {
    luaL_argexpected(L, lua_istable(L, 1), 1, "table");
    luaL_argexpected(L, lua_isboolean(L, 2), 2, "boolean");
    lua_setreadonly(L, 1, lua_toboolean(L, 2));
    return 0;
}

static int skid_hookfunction(lua_State *L) {
    luaL_argexpected(L, lua_isfunction(L, 1), 1, "function");
    luaL_argexpected(L, lua_isfunction(L, 2), 2, "function");
    Closure *orig = clvalue(luaA_toobject(L, 1));
    Closure *hook = clvalue(luaA_toobject(L, 2));
    lua_pushvalue(L, 1);
    if (orig->isC && hook->isC) {
        lua_CFunction old = orig->c.f;
        orig->c.f = hook->c.f;
        (void)old;
    } else if (!orig->isC && !hook->isC) {
        Proto *tmp = orig->l.p;
        orig->l.p = hook->l.p;
        hook->l.p = tmp;
    }
    return 1;
}

static int skid_hookmetamethod(lua_State *L) {
    luaL_checkany(L, 1);
    luaL_checkany(L, 2);
    luaL_argexpected(L, lua_isfunction(L, 3), 3, "function");
    if (!lua_getmetatable(L, 1)) {
        lua_pushnil(L);
        return 1;
    }
    const char *metamethod = luaL_checkstring(L, 2);
    lua_getfield(L, -1, metamethod);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 2);
        lua_pushnil(L);
        return 1;
    }
    lua_pushvalue(L, 3);
    lua_setfield(L, -3, metamethod);
    return 1;
}

static int skid_noop(lua_State *L) { return 0; }

static int skid_getregistry(lua_State *L) {
    lua_pushvalue(L, LUA_REGISTRYINDEX);
    return 1;
}

static int skid_request(lua_State *L) {
    luaL_argexpected(L, lua_istable(L, 1), 1, "table");
    lua_getfield(L, 1, "Url");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_getfield(L, 1, "url");
    }
    const char *url = luaL_checkstring(L, -1);
    std::string body = http_get(url);

    lua_newtable(L);
    lua_pushboolean(L, 1);
    lua_setfield(L, -2, "Success");
    lua_pushinteger(L, 200);
    lua_setfield(L, -2, "StatusCode");
    lua_pushlstring(L, body.data(), body.size());
    lua_setfield(L, -2, "Body");
    lua_newtable(L);
    lua_pushstring(L, "application/json");
    lua_setfield(L, -2, "Content-Type");
    lua_pushstring(L, "SkidSploit/1.0.0");
    lua_setfield(L, -2, "User-Agent");
    lua_setfield(L, -2, "Headers");
    return 1;
}

static int skid_readfile(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    std::string home = getenv("HOME") ? getenv("HOME") : "";
    std::string full = home + "/Documents/SkidSploit/workspace/" + path;
    std::ifstream f(full, std::ios::binary);
    if (!f) luaL_error(L, "file not found: %s", path);
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    lua_pushlstring(L, content.data(), content.size());
    return 1;
}

static int skid_writefile(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    size_t len;
    const char *data = luaL_checklstring(L, 2, &len);
    std::string home = getenv("HOME") ? getenv("HOME") : "";
    std::string dir = home + "/Documents/SkidSploit/workspace";
    std::error_code ec;
    fs::create_directories(dir, ec);
    std::string full = dir + "/" + path;
    std::ofstream f(full, std::ios::binary);
    if (!f) luaL_error(L, "cannot write: %s", path);
    f.write(data, len);
    return 0;
}

static int skid_isfile(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    std::string home = getenv("HOME") ? getenv("HOME") : "";
    std::string full = home + "/Documents/SkidSploit/workspace/" + path;
    lua_pushboolean(L, fs::exists(full));
    return 1;
}

static int skid_makefolder(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    std::string home = getenv("HOME") ? getenv("HOME") : "";
    std::string full = home + "/Documents/SkidSploit/workspace/" + path;
    std::error_code ec;
    fs::create_directories(full, ec);
    return 0;
}

static int skid_getinfo(lua_State *L) {
    luaL_argexpected(L, lua_isfunction(L, 1) || lua_isnumber(L, 1), 1, "function or number");
    lua_newtable(L);
    if (lua_isfunction(L, 1)) {
        Closure *cl = clvalue(luaA_toobject(L, 1));
        lua_pushstring(L, cl->isC ? "C" : "Lua");
        lua_setfield(L, -2, "what");
        if (!cl->isC && cl->l.p) {
            lua_pushinteger(L, cl->l.p->linedefined);
            lua_setfield(L, -2, "linedefined");
            lua_pushinteger(L, cl->l.p->numparams);
            lua_setfield(L, -2, "numparams");
            lua_pushboolean(L, cl->l.p->is_vararg);
            lua_setfield(L, -2, "is_vararg");
        }
    }
    return 1;
}

static int skid_cloneref(lua_State *L) {
    luaL_argexpected(L, lua_isuserdata(L, 1), 1, "userdata");
    lua_pushvalue(L, 1);
    return 1;
}

static int skid_compareinstances(lua_State *L) {
    luaL_argexpected(L, lua_isuserdata(L, 1), 1, "userdata");
    luaL_argexpected(L, lua_isuserdata(L, 2), 2, "userdata");
    uintptr_t a = *(uintptr_t *)lua_touserdata(L, 1);
    uintptr_t b = *(uintptr_t *)lua_touserdata(L, 2);
    lua_pushboolean(L, a == b);
    return 1;
}

static int skid_base64encode(lua_State *L) {
    size_t len;
    const char *s = luaL_checklstring(L, 1, &len);
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string r;
    r.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = (uint8_t)s[i] << 16;
        if (i + 1 < len) n |= (uint8_t)s[i + 1] << 8;
        if (i + 2 < len) n |= (uint8_t)s[i + 2];
        r += t[(n >> 18) & 63];
        r += t[(n >> 12) & 63];
        r += (i + 1 < len) ? t[(n >> 6) & 63] : '=';
        r += (i + 2 < len) ? t[n & 63] : '=';
    }
    lua_pushlstring(L, r.data(), r.size());
    return 1;
}

static int skid_base64decode(lua_State *L) {
    size_t len;
    const char *s = luaL_checklstring(L, 1, &len);
    static const int d[128] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };
    std::string r;
    uint32_t n = 0;
    int bits = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = (uint8_t)s[i];
        if (c > 127 || d[c] == -1) continue;
        n = (n << 6) | d[c];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            r += (char)((n >> bits) & 0xFF);
        }
    }
    lua_pushlstring(L, r.data(), r.size());
    return 1;
}

static void register_globals(lua_State *LS) {
    lua_pushcfunction(LS, skid_loadstring, "loadstring");
    lua_setglobal(LS, "loadstring");

    lua_pushcfunction(LS, skid_httpget, "HttpGet");
    lua_setglobal(LS, "HttpGet");
    lua_pushcfunction(LS, skid_httpget, "httpget");
    lua_setglobal(LS, "httpget");

    lua_pushcfunction(LS, skid_identifyexecutor, "identifyexecutor");
    lua_setglobal(LS, "identifyexecutor");
    lua_pushcfunction(LS, skid_identifyexecutor, "getexecutorname");
    lua_setglobal(LS, "getexecutorname");

    lua_pushcfunction(LS, skid_getgenv, "getgenv");
    lua_setglobal(LS, "getgenv");
    lua_pushcfunction(LS, skid_getrenv, "getrenv");
    lua_setglobal(LS, "getrenv");
    lua_pushcfunction(LS, skid_getregistry, "getregistry");
    lua_setglobal(LS, "getregistry");

    lua_pushcfunction(LS, skid_getrawmetatable, "getrawmetatable");
    lua_setglobal(LS, "getrawmetatable");
    lua_pushcfunction(LS, skid_setrawmetatable, "setrawmetatable");
    lua_setglobal(LS, "setrawmetatable");

    lua_pushcfunction(LS, skid_isreadonly, "isreadonly");
    lua_setglobal(LS, "isreadonly");
    lua_pushcfunction(LS, skid_setreadonly, "setreadonly");
    lua_setglobal(LS, "setreadonly");
    lua_pushcfunction(LS, skid_setreadonly, "makewritable");
    lua_setglobal(LS, "makewritable");

    lua_pushcfunction(LS, skid_iscclosure, "iscclosure");
    lua_setglobal(LS, "iscclosure");
    lua_pushcfunction(LS, skid_islclosure, "islclosure");
    lua_setglobal(LS, "islclosure");
    lua_pushcfunction(LS, skid_newcclosure, "newcclosure");
    lua_setglobal(LS, "newcclosure");
    lua_pushcfunction(LS, skid_isexecutorclosure, "isexecutorclosure");
    lua_setglobal(LS, "isexecutorclosure");
    lua_pushcfunction(LS, skid_isexecutorclosure, "checkclosure");
    lua_setglobal(LS, "checkclosure");
    lua_pushcfunction(LS, skid_isexecutorclosure, "isourclosure");
    lua_setglobal(LS, "isourclosure");

    lua_pushcfunction(LS, skid_checkcaller, "checkcaller");
    lua_setglobal(LS, "checkcaller");
    lua_pushcfunction(LS, skid_getnamecallmethod, "getnamecallmethod");
    lua_setglobal(LS, "getnamecallmethod");

    lua_pushcfunction(LS, skid_getidentity, "getidentity");
    lua_setglobal(LS, "getidentity");
    lua_pushcfunction(LS, skid_getidentity, "getthreadidentity");
    lua_setglobal(LS, "getthreadidentity");
    lua_pushcfunction(LS, skid_getidentity, "getthreadcontext");
    lua_setglobal(LS, "getthreadcontext");
    lua_pushcfunction(LS, skid_setidentity, "setidentity");
    lua_setglobal(LS, "setidentity");
    lua_pushcfunction(LS, skid_setidentity, "setthreadidentity");
    lua_setglobal(LS, "setthreadidentity");
    lua_pushcfunction(LS, skid_setidentity, "setthreadcontext");
    lua_setglobal(LS, "setthreadcontext");

    lua_pushcfunction(LS, skid_hookfunction, "hookfunction");
    lua_setglobal(LS, "hookfunction");
    lua_pushcfunction(LS, skid_hookfunction, "detourfunction");
    lua_setglobal(LS, "detourfunction");
    lua_pushcfunction(LS, skid_hookfunction, "replaceclosure");
    lua_setglobal(LS, "replaceclosure");
    lua_pushcfunction(LS, skid_hookmetamethod, "hookmetamethod");
    lua_setglobal(LS, "hookmetamethod");

    lua_pushcfunction(LS, skid_request, "request");
    lua_setglobal(LS, "request");
    lua_pushcfunction(LS, skid_request, "http_request");
    lua_setglobal(LS, "http_request");

    lua_pushcfunction(LS, skid_readfile, "readfile");
    lua_setglobal(LS, "readfile");
    lua_pushcfunction(LS, skid_writefile, "writefile");
    lua_setglobal(LS, "writefile");
    lua_pushcfunction(LS, skid_isfile, "isfile");
    lua_setglobal(LS, "isfile");
    lua_pushcfunction(LS, skid_makefolder, "makefolder");
    lua_setglobal(LS, "makefolder");

    lua_pushcfunction(LS, skid_getinfo, "getinfo");
    lua_setglobal(LS, "getinfo");
    lua_pushcfunction(LS, skid_getinfo, "getfuncinfo");
    lua_setglobal(LS, "getfuncinfo");
    lua_pushcfunction(LS, skid_cloneref, "cloneref");
    lua_setglobal(LS, "cloneref");
    lua_pushcfunction(LS, skid_cloneref, "clonereference");
    lua_setglobal(LS, "clonereference");
    lua_pushcfunction(LS, skid_compareinstances, "compareinstances");
    lua_setglobal(LS, "compareinstances");

    lua_pushcfunction(LS, skid_noop, "rconsoleshow");
    lua_setglobal(LS, "rconsoleshow");
    lua_pushcfunction(LS, skid_noop, "rconsolehide");
    lua_setglobal(LS, "rconsolehide");
    lua_pushcfunction(LS, skid_noop, "rconsolename");
    lua_setglobal(LS, "rconsolename");
    lua_pushcfunction(LS, skid_noop, "rconsoleclear");
    lua_setglobal(LS, "rconsoleclear");
    lua_pushcfunction(LS, skid_noop, "setclipboard");
    lua_setglobal(LS, "setclipboard");
    lua_pushcfunction(LS, skid_noop, "setfpscap");
    lua_setglobal(LS, "setfpscap");

    lua_newtable(LS);
    lua_pushcfunction(LS, skid_base64encode, "base64encode");
    lua_setfield(LS, -2, "base64encode");
    lua_pushcfunction(LS, skid_base64decode, "base64decode");
    lua_setfield(LS, -2, "base64decode");
    lua_setglobal(LS, "crypt");

    lua_pushcfunction(LS, skid_base64encode, "base64encode");
    lua_setglobal(LS, "base64encode");
    lua_pushcfunction(LS, skid_base64encode, "base64_encode");
    lua_setglobal(LS, "base64_encode");

    lua_getglobal(LS, "game");
    if (lua_isuserdata(LS, -1)) {
        luaL_getmetafield(LS, -1, "__namecall");
        if (lua_isfunction(LS, -1)) {
            const TValue *obj = luaA_toobject(LS, -1);
            Closure *cl = clvalue(obj);
            OldNamecallHook = cl->c.f;
            cl->c.f = NamecallHook;
            ss_log("[SkidSploit] hooked __namecall");
        }
        lua_pop(LS, 1);

        luaL_getmetafield(LS, -1, "__index");
        if (lua_isfunction(LS, -1)) {
            const TValue *obj = luaA_toobject(LS, -1);
            Closure *cl = clvalue(obj);
            OldIndexHook = cl->c.f;
            cl->c.f = IndexHook;
            ss_log("[SkidSploit] hooked __index");
        }
        lua_pop(LS, 1);
    }
    lua_pop(LS, 1);

    ss_log("[SkidSploit] registered %d+ globals", 70);
}

static void execute_script(const std::string &source) {
    void *L = g_LuaState.load();
    if (!L || source.empty()) return;

    std::string bytecode = compile_script(source);
    if (bytecode.empty()) {
        ss_log("[SkidSploit] compile failed (%zu bytes src)", source.size());
        return;
    }

    ss_log("[SkidSploit] loading bytecode %zu bytes on L=%p", bytecode.size(), L);

    try {
        lua_State *LS = (lua_State *)L;

        lua_State *thread = lua_newthread(LS);
        int ref = lua_ref(LS, -1);
        lua_pop(LS, 1);

        set_identity_raw(thread, 8);
        luaL_sandboxthread(thread);

        int rc = luau_load(thread, "=SkidSploit", bytecode.data(), bytecode.size(), 0);
        if (rc != 0) {
            const char *err = lua_tostring(thread, -1);
            ss_log("[SkidSploit] luau_load error: %d — %s", rc, err ? err : "(no msg)");
            lua_unref(LS, ref);
            return;
        }

        SetProtoCapabilities(clvalue(luaA_toobject(thread, -1))->l.p);

        auto roblox_spawn = (SpawnFn)g_Spawn;
        roblox_spawn(thread);

        lua_unref(LS, ref);
        lua_settop(thread, 0);

        ss_log("[SkidSploit] executed %zu bytes", source.size());
    } catch (...) {
        ss_log("[SkidSploit] execute_script exception caught");
    }
}

static std::atomic<int> g_dtc_count{0};

static int DTCFlagHook() {
    int flags = OldDTCFlag();

    if (g_Ready.load()) {
        int n = g_dtc_count.fetch_add(1);
        if (n < 3) ss_log("[DTC] tick=%d", n);

        std::string script;
        {
            std::lock_guard<std::mutex> lk(g_queue_mtx);
            if (!g_ScriptQueue.empty()) {
                script = std::move(g_ScriptQueue.front());
                g_ScriptQueue.pop_front();
            }
        }
        if (!script.empty()) {
            execute_script(script);
        }
    }

    return (flags != 7) ? 7 : flags;
}

static uintptr_t UpdateFunctionHook(uintptr_t a1, WeakObjectRef *a2) {
    ss_log("[SkidSploit] update check intercepted");
    if (!a2) return 0;

    lua_State *L = nullptr;
    if (a2->LiveThread && a2->LiveThread->Thread)
        L = (lua_State *)a2->LiveThread->Thread;

    if (L && lua_gettop(L) >= 2 && lua_isfunction(L, 2)) {
        try {
            lua_pushvalue(L, 2);
            lua_getglobal(L, "Enum");
            if (lua_isnil(L, -1)) {
                lua_pop(L, 2);
                ss_log("[SkidSploit] Enum not available yet, skipping callback");
                return 0;
            }
            lua_getfield(L, -1, "AppUpdateStatus");
            if (lua_isnil(L, -1)) {
                lua_pop(L, 3);
                ss_log("[SkidSploit] AppUpdateStatus not available, skipping");
                return 0;
            }
            lua_getfield(L, -1, "NotAvailable");
            lua_remove(L, -2);
            lua_remove(L, -2);
            lua_pcall(L, 1, 0, 0);
            ss_log("[SkidSploit] pushed NotAvailable to updater callback");
        } catch (...) {
            ss_log("[SkidSploit] updater callback exception caught, ignoring");
        }
    }

    return 0;
}

static uintptr_t TeleportSuccessHook() {
    g_LuaState.store(nullptr);
    g_DataModel.store(0);
    g_ScriptContext.store(0);
    g_Ready.store(false);
    {
        std::lock_guard<std::mutex> lk(g_queue_mtx);
        g_ScriptQueue.clear();
    }
    return OldTeleportSuccess();
}

static uintptr_t AssignLuaCallbackHook(uintptr_t prop, uintptr_t inst, void *L, uintptr_t sc) {
    return OldAssignLuaCallback(prop, inst, L, sc);
}

static void *decrypt_lua_state(uintptr_t encrypted_state) {
    uintptr_t A = encrypted_state + Off::DefaultStateOffset;
    uint32_t low = 0, high = 0;
    switch (Off::EncryptedType) {
        case 1: low = (uint32_t)(*(uint32_t *)A - A); high = (uint32_t)(*(uint32_t *)(A + 4) - A); break;
        case 2: low = (uint32_t)(A - *(uint32_t *)A); high = (uint32_t)(A - *(uint32_t *)(A + 4)); break;
        case 3: low = (uint32_t)(*(uint32_t *)A ^ A); high = (uint32_t)(*(uint32_t *)(A + 4) ^ A); break;
        case 4: low = (uint32_t)(*(uint32_t *)A + A); high = (uint32_t)(*(uint32_t *)(A + 4) + A); break;
    }
    uint64_t result = ((uint64_t)high << 32) | low;
    return (void *)result;
}

static std::atomic<int> g_whsj_dbg{0};

static uintptr_t WHSJHook(uintptr_t a1, uintptr_t *a2) {
    uintptr_t sc = *a2;
    g_ScriptContext.store(sc);

    uintptr_t result = OldWHSJ(a1, a2);

    if (g_Ready.load()) return result;

    uintptr_t dm = *(uintptr_t *)(sc + Off::Parent);
    if (!dm) return result;
    g_DataModel.store(dm);

    int placeId = *(int *)(dm + Off::PlaceId);
    uintptr_t ws = *(uintptr_t *)(dm + Off::Workspace);

    int n = g_whsj_dbg.fetch_add(1);
    if (n < 5 || n % 1000 == 0)
        ss_log("[WHSJ] sc=%llx placeId=%d ws=%llx n=%d",
               (unsigned long long)sc, placeId, (unsigned long long)ws, n);

    if (!placeId || ws == 0) return result;

    void *gs = decrypt_lua_state(sc + Off::EncryptedStateOffset);
    if (!gs) {
        ss_log("[SkidSploit] decrypt failed");
        return result;
    }

    g_LuaState.store(gs);
    g_Ready.store(true);
    ss_log("[SkidSploit] ready — L=%p placeId=%d", gs, placeId);

    try {
        register_globals((lua_State *)gs);
    } catch (...) {
        ss_log("[SkidSploit] register_globals exception");
    }

    auto print_fn = (PrintFn)g_Print;
    print_fn(0, "SkidSploit loaded");

    return result;
}

static void install_hooks() {
    int rc;

    rc = tiny_hook((void *)g_UpdaterFunction, (void *)&UpdateFunctionHook, (void **)&OldUpdateFunction);
    ss_log("[SkidSploit] hook UpdaterFunction: %d", rc);

    rc = tiny_hook((void *)g_whsj, (void *)&WHSJHook, (void **)&OldWHSJ);
    ss_log("[SkidSploit] hook WHSJ: %d", rc);

    rc = tiny_hook((void *)g_TeleportSucceeded, (void *)&TeleportSuccessHook, (void **)&OldTeleportSuccess);
    ss_log("[SkidSploit] hook TeleportSucceeded: %d", rc);

    rc = tiny_hook((void *)g_LuauBytecodeCheck, (void *)&BytecodeCheckHook, (void **)&OldBytecodeCheck);
    ss_log("[SkidSploit] hook BytecodeCheck: %d", rc);

    rc = tiny_hook((void *)g_LuauTimestampCheck, (void *)&TimestampCheckHook, (void **)&OldTimestampCheck);
    ss_log("[SkidSploit] hook TimestampCheck: %d", rc);

    rc = tiny_hook((void *)g_DTCFlag, (void *)&DTCFlagHook, (void **)&OldDTCFlag);
    ss_log("[SkidSploit] hook DTCFlag: %d", rc);

    rc = tiny_hook((void *)g_AssignLuaCallback, (void *)&AssignLuaCallbackHook, (void **)&OldAssignLuaCallback);
    ss_log("[SkidSploit] hook AssignLuaCallback: %d", rc);
}

static std::string g_uds_path;

static bool recv_all(int fd, void *buf, size_t n) {
    char *p = (char *)buf;
    while (n) { ssize_t r = recv(fd, p, n, 0); if (r <= 0) return false; p += r; n -= r; }
    return true;
}

static bool send_all(int fd, const void *buf, size_t n) {
    const char *p = (const char *)buf;
    while (n) { ssize_t r = send(fd, p, n, 0); if (r <= 0) return false; p += r; n -= r; }
    return true;
}

static void handle_client(int fd) {
    uint64_t net_len = 0;
    if (!recv_all(fd, &net_len, 8)) { close(fd); return; }
    uint64_t len = __builtin_bswap64(net_len);
    if (len == 0 || len > 4 * 1024 * 1024) { close(fd); return; }

    std::string payload(len, '\0');
    if (!recv_all(fd, payload.data(), len)) { close(fd); return; }

    std::string result;
    uint8_t cmd = (uint8_t)payload[0];

    if (cmd == 0x00) {
        uintptr_t sc = g_ScriptContext.load();
        void *L = g_LuaState.load();
        result = "base=0x" + std::to_string((uintptr_t)g_roblox_base) +
                 " sc=0x" + std::to_string(sc) +
                 " L=" + std::to_string((uintptr_t)L) +
                 " ready=" + (g_Ready.load() ? "true" : "false");
    } else if (cmd == 0x02) {
        std::string source(payload.begin() + 1, payload.end());
        if (!g_Ready.load()) {
            result = "not ready — wait for game to load";
        } else {
            std::lock_guard<std::mutex> lk(g_queue_mtx);
            g_ScriptQueue.push_back(std::move(source));
            result = "ok";
        }
    } else {
        std::string source(payload.begin(), payload.end());
        if (!g_Ready.load()) {
            result = "not ready — wait for game to load";
        } else {
            std::lock_guard<std::mutex> lk(g_queue_mtx);
            g_ScriptQueue.push_back(std::move(source));
            result = "ok";
        }
    }

    uint64_t rlen = __builtin_bswap64((uint64_t)result.size());
    send_all(fd, &rlen, 8);
    send_all(fd, result.data(), result.size());
    close(fd);
}

static void uds_server() {
    unlink(g_uds_path.c_str());
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) return;

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_uds_path.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(srv, (sockaddr *)&addr, sizeof(addr)) < 0) { close(srv); return; }
    listen(srv, 8);
    ss_log("[SkidSploit] UDS listening: %s", g_uds_path.c_str());

    while (true) {
        int client = accept(srv, nullptr, nullptr);
        if (client < 0) continue;
        std::thread(handle_client, client).detach();
    }
}

__attribute__((constructor)) static void entry() {
    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(getpid(), pathbuf, sizeof(pathbuf)) > 0) {
        if (!strstr(pathbuf, "RobloxPlayer"))
            return;
    }

    init_log();
    ss_log("[SkidSploit] loading...");

    g_roblox_base = (uintptr_t)_dyld_get_image_header(0);
    resolve_offsets();
    ss_log("[SkidSploit] base=%llx slide=%llx", (unsigned long long)g_roblox_base, (unsigned long long)get_slide());

    install_hooks();
    ss_log("[SkidSploit] hooks installed");

    std::error_code ec;
    fs::create_directories("/tmp/skidsploit", ec);
    g_uds_path = "/tmp/skidsploit/" + std::to_string(getpid()) + ".sock";

    std::thread(uds_server).detach();
    ss_log("[SkidSploit] init complete");
}
