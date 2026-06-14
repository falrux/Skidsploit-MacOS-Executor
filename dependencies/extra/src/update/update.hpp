#pragma once
#include <string>
#include <regex>
#include <unordered_set>
#include <mach-o/dyld.h>
#include "../decl/structs.hpp"
#include "obfuscation/ObfuscateV1.h"
#include "obfuscation/ObfuscateV2.h"

#ifndef ARM64V
#define ARM64V
#endif

#if defined(ARM64V)
#pragma message("offsets are compiling for ARM64")
#else
#pragma message("offsets are compiling for x86")
#endif

template <typename T>
struct VMValue0
{
private:
  T storage;

public:
  operator const T() const { return storage; }
  void operator=(const T &value) { storage = value; }
  const T operator->() const { return operator const T(); }
  T get() { return operator const T(); }
  void set(const T &value) { operator=(value); }
};

template <typename T>
struct VMValue1
{
private:
  T Storage;

public:
  operator const T() const { return (T)((uintptr_t)this->Storage - (uintptr_t)this); }
  void operator=(const T &Value) { this->Storage = (T)((uintptr_t)Value + (uintptr_t)this); }
  const T operator->() const { return operator const T(); }
  T Get() { return operator const T(); }
  void Set(const T &Value) { operator=(Value); }
};

template <typename T>
struct VMValue2
{
private:
  T Storage;

public:
  operator const T() const { return (T)((uintptr_t)this - (uintptr_t)this->Storage); }
  void operator=(const T &Value) { this->Storage = (T)((uintptr_t)this - (uintptr_t)Value); }
  const T operator->() const { return operator const T(); }
  T Get() { return operator const T(); }
  void Set(const T &Value) { operator=(Value); }
};

template <typename T>
struct VMValue3
{
private:
  T Storage;

public:
  operator const T() const { return (T)((uintptr_t)this ^ (uintptr_t)this->Storage); }
  void operator=(const T &Value) { this->Storage = (T)((uintptr_t)Value ^ (uintptr_t)this); }
  const T operator->() const { return operator const T(); }
  T Get() { return operator const T(); }
  void Set(const T &Value) { operator=(Value); }
};

template <typename T>
struct VMValue4
{
private:
  T Storage;

public:
  operator const T() const { return (T)((uintptr_t)this + (uintptr_t)this->Storage); }
  void operator=(const T &Value) { this->Storage = (T)((uintptr_t)Value - (uintptr_t)this); }
  const T operator->() const { return operator const T(); }
  T Get() { return operator const T(); }
  void Set(const T &Value) { operator=(Value); }
};

static std::string StripError(const std::string &message)
{
  static const std::regex Callstack(OBF(R"(^[^:]+:\d+:\s*)"), std::regex::optimize | std::regex::icase);
  return std::regex_replace(message, Callstack, "");
}

struct RegistryFree
{
private:
  int _value = 0;

public:
  RegistryFree &operator=(const RegistryFree &value) { _value = value._value; return *this; }

  RegistryFree &operator=(int value)
  {
    int high = _value & 0xF0000000;
    _value = (value & 0x0FFFFFFF) | high;
    return *this;
  }

  operator int() const { return _value & 0x0FFFFFFF; }
  bool operator==(int value) const { return (_value & 0x0FFFFFFF) == (value & 0x0FFFFFFF); }
  bool operator!=(int value) const { return !(*this == value); }
};

// clang-format off
typedef struct SharedES {
    uintptr_t padding0a[5];
    uintptr_t ScriptContext; // 0x28
} SharedES;

typedef struct ExtraSpace
{
    ExtraSpace* next;             // 0x0
    uintptr_t padding0a;          // 0x8
    ExtraSpace* prev;             // 0x10
    struct SharedES *SharedExtraSpace; // 0x18
    uintptr_t padding0b[8];       // 0x20..0x58
    uintptr_t identity;           // 0x60
    uintptr_t padding0c[2];       // 0x68, 0x70
    uintptr_t capabilities;       // 0x78
    std::weak_ptr<uintptr_t> script;
    uintptr_t actor;
} ExtraSpace;
// clang-format on

#define LSTATE_STACKSIZE_ENC  VMValue2
#define CLOSURE_CONT_ENC      VMValue3
#define CLOSURE_DEBUGNAME_ENC VMValue1
#define UDATA_META_ENC        VMValue3
#define PROTO_USERDATA_ENC    VMValue4
#define TSTRING_HASH_ENC      VMValue3
#define PROTO_SOURCE_ENC      VMValue3
#define PROTO_TYPEINFO_ENC    VMValue1
#define PROTO_DEBUGISN_ENC    VMValue2
#define PROTO_DEBUGNAME_ENC   VMValue3
#define PROTO_LINEINFO_ENC    VMValue2
#define PROTO_ABSLINEINFO_ENC VMValue1
#define PROTO_LOCVAR_ENC      VMValue4
#define PROTO_UPVALUES_ENC    VMValue3

inline uintptr_t GetSlide()
{
  const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(0);
  uintptr_t base = (uintptr_t)header;

  const struct load_command *cmd = (const struct load_command *)(header + 1);
  for (uint32_t i = 0; i < header->ncmds; ++i)
  {
    if (cmd->cmd == LC_SEGMENT_64)
    {
      const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;
      if (inline_strcmp(seg->segname, OBFUSCATE("__TEXT")) == 0)
        return base - seg->vmaddr;
    }
    cmd = (const struct load_command *)((const char *)cmd + cmd->cmdsize);
  }
  return 0;
}

inline uintptr_t REBASE(uintptr_t x)
{
  return (uintptr_t)(GetSlide() + x);
}

namespace Offsets
{
  inline uintptr_t FPS                         = OBFC(0xB8);
  inline uintptr_t RenderSteppedCallbacksStart = OBFC(0x150);
  inline uintptr_t RenderSteppedCallbacksEnd   = OBFC(0x158);
  inline uintptr_t RetInstr                    = OBFC(65556);
  inline uintptr_t LocalScriptBytecode         = OBFC(0x198);
  inline uintptr_t ModuleScriptBytecode        = OBFC(0x140);
  inline uintptr_t ReflectionTypeBinaryString  = OBFC(0x1E);
  inline uintptr_t ReflectionTypeSharedString  = OBFC(0x3F);
  inline uintptr_t ReflectionTypeSystemAddress = OBFC(0x1D);
  inline uintptr_t PropertyType                = OBFC(8);
  inline uintptr_t Primitive                   = OBFC(0x138);
  inline uintptr_t Overlap                     = OBFC(488);
  inline uintptr_t ObjectDescriptor            = OBFC(0x60);
  inline uintptr_t ReflectionType              = OBFC(0x30);
  inline uintptr_t PropertyDescriptorOffset    = OBFC(0x88);
  inline uintptr_t GetImpl                     = OBFC(0x20);
  inline uintptr_t SetImpl                     = OBFC(0x28);
  inline uintptr_t Scriptable                  = OBFC(0x87);
  inline uintptr_t IsScriptableBit             = OBFC(0x10);
  inline uintptr_t DescriptorSignature         = OBFC(0x40);
  inline uintptr_t DescriptorIterator          = OBFC(0x70);
  inline uintptr_t ClassName                   = OBFC(0x8);
  inline uintptr_t ClassDescriptor             = OBFC(0x18);
  inline uintptr_t Parent                      = OBFC(0x70);
  inline uintptr_t Workspace                   = OBFC(0x320);
  inline uintptr_t PlaceId                     = OBFC(0x188);
  inline uintptr_t Name                        = OBFC(0xB0);
  inline uintptr_t StateOffset                 = OBFC(0x140);
  inline uintptr_t DefaultStateOffset          = OBFC(0x1F0);
  inline uintptr_t EncryptedStateOffset        = OBFC(0x200);
  inline uintptr_t ActorContainerStartOffset   = OBFC(0);
  inline uintptr_t ActorContainerEndOffset     = OBFC(8);
  inline uintptr_t ActorMapOffset              = OBFC(0x18);
  inline uintptr_t ScriptContextHelperOffset   = OBFC(0x7A0);
  inline uintptr_t RequireBypass               = OBFC(0x39);
  inline int EncryptedType = 1;

#ifdef ARM64V
  inline uintptr_t ActorLookup_            = REBASE(OBFC(0x1004C6604));
  inline uintptr_t luaO_nilobject          = REBASE(OBFC(0x1053A7AC8));
  inline uintptr_t Print_                  = REBASE(OBFC(0x1001E33F0));
  inline uintptr_t IdentityPropagator_     = REBASE(OBFC(0x10173EA98));
  inline uintptr_t IdentityToCapabilities_ = REBASE(OBFC(0x103F33718));
  inline uintptr_t Defer_                  = REBASE(OBFC(0x101699394));
  inline uintptr_t Spawn_                  = REBASE(OBFC(0x101699778));
  inline uintptr_t GetObject_              = REBASE(OBFC(0x1000FE7E0));
  inline uintptr_t LuauLoad_              = REBASE(OBFC(0x103F21F60));
  inline uintptr_t LuauTimestampCheck      = REBASE(OBFC(0x1016F6680));
  inline uintptr_t LuauBytecodeCheck       = REBASE(OBFC(0x1016F97A0));
  inline uintptr_t LuauOpcodeLookupTable   = REBASE(OBFC(0x1053A7D01));
  inline uintptr_t UpdaterFunction         = REBASE(OBFC(0x101EB270C));
  inline uintptr_t TaskScheduler           = REBASE(OBFC(0x106A32308));
  inline uintptr_t dummynode               = REBASE(OBFC(0x1053A7C88));
  inline uintptr_t luaC_stepfunc_          = REBASE(OBFC(0x103F09ADC));
  inline uintptr_t luau_executefunc_       = REBASE(OBFC(0x103F18FE0));
  inline uintptr_t GetProperty_            = REBASE(OBFC(0x1042D5FCC));
  inline uintptr_t PropertyList_           = REBASE(OBFC(0x100726F94));
  inline uintptr_t PropertyDescriptor      = OBFC(0x248);
  inline uintptr_t SharedStringInitializer_ = REBASE(OBFC(0x10437606C));
  inline uintptr_t IsLegalSendEvent_       = REBASE(OBFC(0x100512A88));
  inline uintptr_t Filter                  = OBFC(0x2D10);
  inline uintptr_t AssignLuaCallback       = REBASE(OBFC(0x1016DB0A4));
  inline uintptr_t ToFunction_             = REBASE(OBFC(0x1017A5608));
  inline uintptr_t RaknetSend              = REBASE(OBFC(0x102C162E4));
  inline uintptr_t RaknetSendShared        = REBASE(OBFC(0x102C1691C));
  inline uintptr_t RaknetSendSharedPtr     = REBASE(OBFC(0x102C16AE8));
  inline uintptr_t DTCFlag                 = REBASE(OBFC(0x101741DB8));
  inline uintptr_t HackFlag                = REBASE(OBFC(0x0));
  inline uintptr_t whsj                    = REBASE(OBFC(0x1017836D8));
  inline uintptr_t TeleportSucceeded       = REBASE(OBFC(0x10036AB44));
  inline uintptr_t GetVMStateMap_          = REBASE(OBFC(0x1016FBEF8));
  inline uintptr_t GetFFlag_               = REBASE(OBFC(0x104346C3C));
  inline uintptr_t SetFFlag_               = REBASE(OBFC(0x104346B9C));
  inline uintptr_t PushInstanceAddr_       = OBFC(0x1016DC83C);
  inline uintptr_t PushInstance_           = REBASE(PushInstanceAddr_);
  inline uintptr_t FTI_                    = REBASE(OBFC(0x102523F9C));
  inline uintptr_t FPP_                    = REBASE(OBFC(0x101E91CBC));
  inline uintptr_t GetArguments_           = REBASE(OBFC(0x10169C234));
  inline uintptr_t CastInt_                = REBASE(OBFC(0x1001FA9BC));
  inline uintptr_t CastInt64_              = REBASE(OBFC(0x100081490));
  inline uintptr_t CastFloat_              = REBASE(OBFC(0x1001FAA84));
  inline uintptr_t FCD_                    = REBASE(OBFC(0x101E8E4E4));
  inline uintptr_t FCD3_                   = REBASE(OBFC(0x101E8E674));
  inline uintptr_t FCD1_                   = REBASE(OBFC(0x101E8F1B8));
  inline uintptr_t FCD2_                   = REBASE(OBFC(0x101E8F2BC));
#else
  inline uintptr_t ActorLookup_            = REBASE(OBFC(0x10049A5E0));
  inline uintptr_t luaO_nilobject          = REBASE(OBFC(0x10532A820));
  inline uintptr_t Print_                  = REBASE(OBFC(0x1001CDC08));
  inline uintptr_t IdentityPropagator_     = REBASE(OBFC(0x1017C3791));
  inline uintptr_t IdentityToCapabilities_ = REBASE(OBFC(0x10408A730));
  inline uintptr_t Defer_                  = REBASE(OBFC(0x101721924));
  inline uintptr_t Spawn_                  = REBASE(OBFC(0x101721CF2));
  inline uintptr_t GetObject_              = REBASE(OBFC(0x1017FC740));
  inline uintptr_t LuauLoad_              = REBASE(OBFC(0x104077DBB));
  inline uintptr_t LuauTimestampCheck      = REBASE(OBFC(0x10177AB92));
  inline uintptr_t LuauBytecodeCheck       = REBASE(OBFC(0x10177D86B));
  inline uintptr_t LuauOpcodeLookupTable   = REBASE(OBFC(0x10532A980));
  inline uintptr_t UpdaterFunction         = REBASE(OBFC(0x101F113D0));
  inline uintptr_t TaskScheduler           = REBASE(OBFC(0x106CCE5C8));
  inline uintptr_t dummynode               = REBASE(OBFC(0x10532A940));
  inline uintptr_t luaC_stepfunc_          = REBASE(OBFC(0x10405F8C6));
  inline uintptr_t luau_executefunc_       = REBASE(OBFC(0x10406E502));
  inline uintptr_t GetProperty_            = REBASE(OBFC(0x10445895A));
  inline uintptr_t PropertyList_           = REBASE(OBFC(0x1016C1D58));
  inline uintptr_t PropertyDescriptor      = OBFC(0x248);
  inline uintptr_t SharedStringInitializer_ = REBASE(OBFC(0x1044FBE7C));
  inline uintptr_t Filter                  = OBFC(0x2D40);
  inline uintptr_t IsLegalSendEvent_       = REBASE(OBFC(0x1004E6110));
  inline uintptr_t AssignLuaCallback       = REBASE(OBFC(0x101760A0A));
  inline uintptr_t ToFunction_             = REBASE(OBFC(0x10182E03F));
  inline uintptr_t Raknet_                 = REBASE(OBFC(0x0));
  inline uintptr_t DTCFlag                 = REBASE(OBFC(0x1017C6824));
  inline uintptr_t HackFlag                = REBASE(OBFC(0x0));
  inline uintptr_t whsj                    = REBASE(OBFC(0x10180C882));
  inline uintptr_t TeleportSucceeded       = REBASE(OBFC(0x1003467AC));
  inline uintptr_t GetVMStateMap_          = REBASE(OBFC(0x1017803C6));
  inline uintptr_t GetFFlag_               = REBASE(OBFC(0x1044CBD97));
  inline uintptr_t SetFFlag_               = REBASE(OBFC(0x1044CBCF6));
  inline uintptr_t PushInstanceAddr_       = OBFC(0x10176217A);
  inline uintptr_t PushInstance_           = REBASE(PushInstanceAddr_);
  inline uintptr_t FTI_                    = REBASE(OBFC(0x1025C8416));
  inline uintptr_t FPP_                    = REBASE(OBFC(0x101EF0D90));
  inline uintptr_t GetArguments_           = REBASE(OBFC(0x101724464));
  inline uintptr_t CastInt_                = REBASE(OBFC(0x1001E5150));
  inline uintptr_t CastInt64_              = REBASE(OBFC(0x1001E50F4));
  inline uintptr_t CastFloat_              = REBASE(OBFC(0x1001E5208));
  inline uintptr_t FCD_                    = REBASE(OBFC(0x101EED2A4));
  inline uintptr_t FCD3_                   = REBASE(OBFC(0x101EED404));
  inline uintptr_t FCD1_                   = REBASE(OBFC(0x101EEDFE6));
  inline uintptr_t FCD2_                   = REBASE(OBFC(0x101EEE0CA));
#endif

  inline bool (*SetFFlag)(const std::string &, std::string &, int, int, int) =
      reinterpret_cast<bool (*)(const std::string &, std::string &, int, int, int)>(SetFFlag_);
  inline bool (*GetFFlag)(const std::string &, std::string &, bool) =
      reinterpret_cast<bool (*)(const std::string &, std::string &, bool)>(GetFFlag_);
  inline void (*PushInstance)(lua_State *, uintptr_t *) =
      reinterpret_cast<void (*)(lua_State *, uintptr_t *)>(PushInstance_);
  inline void (*PushInstance2)(lua_State *, void *) =
      reinterpret_cast<void (*)(lua_State *, void *)>(PushInstance_);
  inline void (*PushInstance3)(lua_State *, std::shared_ptr<uintptr_t>) =
      reinterpret_cast<void (*)(lua_State *, std::shared_ptr<uintptr_t>)>(PushInstance_);
  inline void (*luau_executefunc)(lua_State *) =
      reinterpret_cast<void (*)(lua_State *)>(luau_executefunc_);
  inline size_t (*luaC_stepfunc)(lua_State *, bool) =
      reinterpret_cast<size_t (*)(lua_State *, bool)>(luaC_stepfunc_);
  inline uintptr_t (*IdentityToCapabilities)(uint32_t *) =
      reinterpret_cast<uintptr_t (*)(uint32_t *)>(IdentityToCapabilities_);
  inline uintptr_t (*IdentityPropagator)(lua_State *) =
      reinterpret_cast<uintptr_t (*)(lua_State *)>(IdentityPropagator_);
  inline uintptr_t (*GetVMStateMap)(uintptr_t, lua_State *) =
      reinterpret_cast<uintptr_t (*)(uintptr_t, lua_State *)>(GetVMStateMap_);
  inline void (*SharedStringInitializer)(Structures::SharedString *, std::string *) =
      reinterpret_cast<void (*)(Structures::SharedString *, std::string *)>(SharedStringInitializer_);
  inline bool (*IsLegalSendEvent)(uintptr_t, uintptr_t, uintptr_t) =
      reinterpret_cast<bool (*)(uintptr_t, uintptr_t, uintptr_t)>(IsLegalSendEvent_);
  inline uintptr_t (*GetProperty)(const char *) =
      reinterpret_cast<uintptr_t (*)(const char *)>(GetProperty_);
  inline std::__shared_weak_count *(*GetObject)(Structures::ObjectRef *, Structures::WeakObjectRef *) =
      reinterpret_cast<std::__shared_weak_count *(*)(Structures::ObjectRef *, Structures::WeakObjectRef *)>(GetObject_);
  inline int (*LuauLoad)(lua_State *, const char *, const char *, size_t, int) =
      reinterpret_cast<int (*)(lua_State *, const char *, const char *, size_t, int)>(LuauLoad_);
  inline void (*Print)(int, const char *, ...) =
      reinterpret_cast<void (*)(int, const char *, ...)>(Print_);
  inline lua_State *(*Defer)(lua_State *) =
      reinterpret_cast<lua_State *(*)(lua_State *)>(Defer_);
  inline lua_State *(*Spawn)(lua_State *) =
      reinterpret_cast<lua_State *(*)(lua_State *)>(Spawn_);
  inline void (*GetArguments)(lua_State *, unsigned int, Structures::Variant *, bool, int) =
      reinterpret_cast<void (*)(lua_State *, unsigned int, Structures::Variant *, bool, int)>(GetArguments_);
  inline void (*FTI)(uintptr_t, uintptr_t, uintptr_t, char) =
      reinterpret_cast<void (*)(uintptr_t, uintptr_t, uintptr_t, char)>(FTI_);
  inline void (*FCD)(uintptr_t, uintptr_t, float) =
      reinterpret_cast<void (*)(uintptr_t, uintptr_t, float)>(FCD_);
  inline void (*FCD1)(uintptr_t, uintptr_t) =
      reinterpret_cast<void (*)(uintptr_t, uintptr_t)>(FCD1_);
  inline void (*FCD2)(uintptr_t, uintptr_t) =
      reinterpret_cast<void (*)(uintptr_t, uintptr_t)>(FCD2_);
  inline void (*FCD3)(uintptr_t, uintptr_t, float) =
      reinterpret_cast<void (*)(uintptr_t, uintptr_t, float)>(FCD3_);
  inline void (*FPP)(uintptr_t) =
      reinterpret_cast<void (*)(uintptr_t)>(FPP_);
  inline uintptr_t *(*ActorLookup)(uintptr_t *, uintptr_t *) =
      reinterpret_cast<uintptr_t *(*)(uintptr_t *, uintptr_t *)>(ActorLookup_);
  inline uintptr_t (*PropertyList)(uintptr_t, uintptr_t *) =
      reinterpret_cast<uintptr_t (*)(uintptr_t, uintptr_t *)>(PropertyList_);
}

static lua_State *DecryptLuaState(uintptr_t EncryptedState)
{
  uintptr_t A = EncryptedState + Offsets::DefaultStateOffset;
  uint32_t low = 0;
  uint32_t high = 0;
  switch (Offsets::EncryptedType) {
    case 1:
      low  = (uint32_t)(*(uint32_t *)A - A);
      high = (uint32_t)(*(uint32_t *)(A + 4) - A);
      break;
    case 2:
      low  = (uint32_t)(A - *(uint32_t *)A);
      high = (uint32_t)(A - *(uint32_t *)(A + 4));
      break;
    case 3:
      low  = (uint32_t)(*(uint32_t *)A ^ A);
      high = (uint32_t)(*(uint32_t *)(A + 4) ^ A);
      break;
    case 4:
      low  = (uint32_t)(*(uint32_t *)A + A);
      high = (uint32_t)(*(uint32_t *)(A + 4) + A);
      break;
    default:
      break;
  }
  uint64_t result = ((uint64_t)high << 32) | low;
  return (lua_State *)result;
}
