// =============================================================================
//  dllmain.cpp  –  Steam Proxy DLL  (AppID Spoofing / License Bypass)
//  Method: Dynamic Hooking over Proxy DLL (MinHook + VTable Patching)
//
//  Proxy chain:
//    game.exe  →  steam_api64.dll  (this file, compiled)
//                    ↓ .def forwarder records (all exports)
//                 steam_api64_o.dll  (original, renamed)
//                    ↑ MinHook patches applied here at DLL_PROCESS_ATTACH
//
//  Target AppID : 480  (Spacewar – publicly accessible Steam testing app)
//
//  Build (MSVC x64):
//    cl /LD /EHsc /std:c++17 dllmain.cpp /Fe:steam_api64.dll
//       /link /DEF:steam_api64.def MinHook.x64.lib kernel32.lib
//
//  Required files alongside the compiled DLL:
//    steam_api64_o.dll  – renamed original Steam API DLL
//    vtable.txt         – method-index map (see end of this file for format)
//    MinHook.x64.lib    – MinHook import library
//    MinHook.h          – MinHook public header
// =============================================================================

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <cstring>

// MinHook – https://github.com/TsudaKageyu/minhook
// Place MinHook.h and MinHook.x64.lib in your project.
#include "MinHook.h"

// =============================================================================
//  Build-time constants
// =============================================================================
static constexpr DWORD  TARGET_APPID  = 480;
static constexpr char   ORIG_DLL[]    = "steam_api64_o.dll";
static constexpr char   APPID_STR[]   = "480";
static constexpr char   VTABLE_FILE[] = "vtable.txt";

// =============================================================================
//  Minimal Steam type aliases  (no SDK dependency)
// =============================================================================
using AppId_t = unsigned int;
using uint32  = unsigned int;
using uint8   = unsigned char;

// =============================================================================
//  VTable index storage
//  Populated by LoadVTableIndexes() from vtable.txt.
//  Key format: "InterfaceName.MethodName"  e.g. "ISteamUtils.GetAppID"
// =============================================================================
static std::unordered_map<std::string, int> g_vtableIdx;

// =============================================================================
//  Handle to the renamed original DLL (kept alive for hook lifetime)
// =============================================================================
static HMODULE g_hOrigDll = nullptr;

// =============================================================================
//  Per-interface patch-applied guards  (prevent double-patching shared vtables)
// =============================================================================
static volatile LONG g_patchedUtils = 0;
static volatile LONG g_patchedApps  = 0;
static volatile LONG g_patchedUser  = 0;

// =============================================================================
//  Saved original vtable slot pointers
//  These are filled during VTablePatch() so we can call through if needed.
// =============================================================================
static AppId_t (*orig_vt_ISteamUtils_GetAppID)(void*)          = nullptr;
static bool    (*orig_vt_ISteamApps_BIsSubscribedApp)(void*, AppId_t) = nullptr;
static bool    (*orig_vt_ISteamApps_BIsAppInstalled)(void*, AppId_t)  = nullptr;
static AppId_t (*orig_vt_ISteamUser_GetAppID)(void*)           = nullptr;   // newer iface only

// =============================================================================
//  MinHook trampoline pointers for flat (C-linkage) API hooks
// =============================================================================
using fn_SteamAPI_Init                 = bool  (__cdecl*)();
using fn_SteamAPI_ISteamUtils_GetAppID = AppId_t(__cdecl*)(void*);
using fn_SteamAPI_ISteamUser_GetAppID  = AppId_t(__cdecl*)(void*);
using fn_SteamInternal_CreateInterface = void*  (__cdecl*)(const char*);

static fn_SteamAPI_Init                 orig_SteamAPI_Init                 = nullptr;
static fn_SteamAPI_ISteamUtils_GetAppID orig_SteamAPI_ISteamUtils_GetAppID = nullptr;
static fn_SteamAPI_ISteamUser_GetAppID  orig_SteamAPI_ISteamUser_GetAppID  = nullptr;
static fn_SteamInternal_CreateInterface orig_SteamInternal_CreateInterface = nullptr;


// =============================================================================
//  VTable utility
//
//  Every C++ object with virtual functions starts with a hidden vptr:
//
//      [0..7]   vptr  ──────────────────────────────────────────────┐
//      ...              vtable[0]  fn ptr  (slot 0)                  │
//                       vtable[1]  fn ptr  (slot 1)                  │
//                       vtable[N]  fn ptr  (slot N)  ◄───────────────┘
//
//  We unlock PAGE_EXECUTE_READWRITE on the specific slot,
//  overwrite it, and restore the original page protection.
// =============================================================================
static bool VTablePatch(void*  pInterface,
                        int    slotIndex,
                        void*  pNewFn,
                        void** ppOldFn = nullptr)
{
    if (!pInterface || slotIndex < 0 || !pNewFn)
        return false;

    // The object's first 8 bytes ARE the vptr.
    void** pVTable = *reinterpret_cast<void***>(pInterface);

    if (ppOldFn)
        *ppOldFn = pVTable[slotIndex];

    DWORD oldProt = 0;
    if (!VirtualProtect(&pVTable[slotIndex], sizeof(void*),
                        PAGE_EXECUTE_READWRITE, &oldProt))
        return false;

    pVTable[slotIndex] = pNewFn;
    VirtualProtect(&pVTable[slotIndex], sizeof(void*), oldProt, &oldProt);
    return true;
}


// =============================================================================
//  vtable.txt parser
//
//  Expected file format (UTF-8, one entry per line):
//
//      # comment lines are ignored
//      InterfaceName.MethodName = <integer>
//
//  Example:
//      ISteamUtils.GetAppID     = 9
//      ISteamApps.BIsSubscribedApp = 6
//      ISteamApps.BIsAppInstalled  = 19
//
//  The parser is deliberately lenient: extra whitespace, blank lines,
//  and comment lines (# ...) are all silently skipped.
//
//  Values are stored in g_vtableIdx so GetVtIdx() can retrieve them later.
// =============================================================================
static void LoadVTableIndexes(const std::string& filePath)
{
    std::ifstream f(filePath);
    if (!f.is_open())
        return;

    std::string line;
    while (std::getline(f, line))
    {
        // Strip inline comments
        auto hash = line.find('#');
        if (hash != std::string::npos)
            line = line.substr(0, hash);

        // Find '='
        auto eq = line.find('=');
        if (eq == std::string::npos)
            continue;

        std::string key   = line.substr(0, eq);
        std::string value = line.substr(eq + 1);

        // Trim whitespace from key
        while (!key.empty()   && isspace((unsigned char)key.back()))    key.pop_back();
        while (!key.empty()   && isspace((unsigned char)key.front()))   key.erase(key.begin());

        // Trim whitespace from value
        while (!value.empty() && isspace((unsigned char)value.front())) value.erase(value.begin());
        while (!value.empty() && isspace((unsigned char)value.back()))  value.pop_back();

        if (key.empty() || value.empty())
            continue;

        try { g_vtableIdx[key] = std::stoi(value); }
        catch (...) { /* malformed integer – skip */ }
    }
}

// Helper: look up a vtable slot index; return 'fallback' if not found.
static int GetVtIdx(const char* iface, const char* method, int fallback)
{
    std::string key = std::string(iface) + "." + method;
    auto it = g_vtableIdx.find(key);
    return (it != g_vtableIdx.end()) ? it->second : fallback;
}


// =============================================================================
//  VTable hook implementations
//  x64 ABI: 'this' is the first implicit argument → first parameter below.
//  All calling conventions collapse to the Microsoft x64 ABI on 64-bit builds.
// =============================================================================

// --- ISteamUtils::GetAppID  (vtable slot 9, confirmed from vtable.txt) ---
static AppId_t ISteamUtils_GetAppID_Hook(void* pThis)
{
    (void)pThis;
    return TARGET_APPID;
}

// --- ISteamApps::BIsSubscribedApp  (vtable slot 6) ---
static bool ISteamApps_BIsSubscribedApp_Hook(void* pThis, AppId_t nAppID)
{
    (void)pThis;
    (void)nAppID;
    return true;   // Always report subscribed → license bypass
}

// --- ISteamApps::BIsAppInstalled  (vtable slot 19) ---
static bool ISteamApps_BIsAppInstalled_Hook(void* pThis, AppId_t appID)
{
    (void)pThis;
    (void)appID;
    return true;   // Always report installed → ownership bypass
}

// --- ISteamUser::GetAppID  (slot loaded from vtable.txt; absent in older SDKs) ---
static AppId_t ISteamUser_GetAppID_Hook(void* pThis)
{
    (void)pThis;
    return TARGET_APPID;
}


// =============================================================================
//  PatchInterface
//  Called from SteamInternal_CreateInterface hook (and opportunistically from
//  the flat-API GetAppID hooks) whenever an interface pointer is obtained.
//  Identifies the interface by its version string prefix and applies the
//  relevant vtable patches exactly once per interface type.
// =============================================================================
static void PatchInterface(const char* pchVersion, void* pInterface)
{
    if (!pInterface || !pchVersion)
        return;

    // ── ISteamUtils ─────────────────────────────────────────────────────────
    // Version strings: "SteamUtils009", "SteamUtils017", etc.
    if (strncmp(pchVersion, "SteamUtils", 10) == 0)
    {
        if (InterlockedCompareExchange(&g_patchedUtils, 1, 0) == 0)
        {
            int slot = GetVtIdx("ISteamUtils", "GetAppID", 9);
            void* pOld = nullptr;
            if (VTablePatch(pInterface, slot,
                            reinterpret_cast<void*>(&ISteamUtils_GetAppID_Hook), &pOld))
            {
                orig_vt_ISteamUtils_GetAppID =
                    reinterpret_cast<AppId_t(*)(void*)>(pOld);
            }
        }
        return;
    }

    // ── ISteamApps ───────────────────────────────────────────────────────────
    // Version strings: "STEAMAPPS_INTERFACE_VERSION008", "SteamApps008", etc.
    if (strncmp(pchVersion, "STEAMAPPS_INTERFACE_VERSION", 26) == 0 ||
        strncmp(pchVersion, "SteamApps",                    9) == 0)
    {
        if (InterlockedCompareExchange(&g_patchedApps, 1, 0) == 0)
        {
            int slotSub  = GetVtIdx("ISteamApps", "BIsSubscribedApp", 6);
            int slotInst = GetVtIdx("ISteamApps", "BIsAppInstalled",  19);

            void* pOldSub  = nullptr;
            void* pOldInst = nullptr;

            VTablePatch(pInterface, slotSub,
                        reinterpret_cast<void*>(&ISteamApps_BIsSubscribedApp_Hook),
                        &pOldSub);
            VTablePatch(pInterface, slotInst,
                        reinterpret_cast<void*>(&ISteamApps_BIsAppInstalled_Hook),
                        &pOldInst);

            if (pOldSub)
                orig_vt_ISteamApps_BIsSubscribedApp =
                    reinterpret_cast<bool(*)(void*, AppId_t)>(pOldSub);
            if (pOldInst)
                orig_vt_ISteamApps_BIsAppInstalled =
                    reinterpret_cast<bool(*)(void*, AppId_t)>(pOldInst);
        }
        return;
    }

    // ── ISteamUser ───────────────────────────────────────────────────────────
    // Version strings: "SteamUser021", "SteamUser023", etc.
    // GetAppID does NOT exist in older interface revisions (not in vtable.txt
    // for this SDK snapshot).  We only patch if the key is present in the
    // loaded vtable map, making this forward-compatible with newer SDK builds.
    if (strncmp(pchVersion, "SteamUser", 9) == 0)
    {
        if (InterlockedCompareExchange(&g_patchedUser, 1, 0) == 0)
        {
            auto it = g_vtableIdx.find("ISteamUser.GetAppID");
            if (it != g_vtableIdx.end())
            {
                void* pOld = nullptr;
                if (VTablePatch(pInterface, it->second,
                                reinterpret_cast<void*>(&ISteamUser_GetAppID_Hook),
                                &pOld))
                {
                    orig_vt_ISteamUser_GetAppID =
                        reinterpret_cast<AppId_t(*)(void*)>(pOld);
                }
            }
        }
        return;
    }
}


// =============================================================================
//  Environment & steam_appid.txt setup
//  Must be called as early as possible – ideally before any SteamAPI call –
//  so that both steam_api64_o.dll internals and GameOverlayRenderer64.dll
//  read the spoofed AppID from the environment on their first access.
// =============================================================================
static void SetupSteamEnvironment()
{
    SetEnvironmentVariableA("SteamAppId",   APPID_STR);
    SetEnvironmentVariableA("SteamGameId",  APPID_STR);

    // Create steam_appid.txt in the current (game) directory.
    // CREATE_NEW guarantees we do not overwrite an existing file.
    HANDLE hFile = CreateFileA("steam_appid.txt",
                               GENERIC_WRITE, 0, nullptr,
                               CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        WriteFile(hFile, APPID_STR, (DWORD)strlen(APPID_STR), &written, nullptr);
        CloseHandle(hFile);
    }
}


// =============================================================================
//  Flat API detour implementations
// =============================================================================

// ── SteamAPI_Init ────────────────────────────────────────────────────────────
static bool __cdecl Detour_SteamAPI_Init()
{
    // Re-apply env vars in case the game process mutated them before calling Init.
    SetupSteamEnvironment();

    bool result = orig_SteamAPI_Init ? orig_SteamAPI_Init() : false;
    return result ? result : false;
    // NOTE: We do NOT force-return true here.  SteamAPI_Init failing means
    //       steam_api64_o.dll could not connect to Steam; returning true would
    //       cause downstream null-pointer crashes when the game dereferences
    //       interface pointers.  If you are certain Steam is running, you may
    //       change this to: return result || true;
}

// ── SteamAPI_ISteamUtils_GetAppID ────────────────────────────────────────────
static AppId_t __cdecl Detour_SteamAPI_ISteamUtils_GetAppID(void* pISteamUtils)
{
    // Belt-and-suspenders: patch the vtable the first time we get the pointer.
    if (pISteamUtils && !g_patchedUtils)
        PatchInterface("SteamUtils", pISteamUtils);

    return TARGET_APPID;
}

// ── SteamAPI_ISteamUser_GetAppID ─────────────────────────────────────────────
static AppId_t __cdecl Detour_SteamAPI_ISteamUser_GetAppID(void* pISteamUser)
{
    (void)pISteamUser;
    return TARGET_APPID;
}

// ── SteamInternal_CreateInterface ────────────────────────────────────────────
//  This is the single choke-point through which the Steam client returns every
//  versioned interface pointer.  Hooking it gives us a guaranteed opportunity
//  to patch vtables regardless of which call path the game takes.
static void* __cdecl Detour_SteamInternal_CreateInterface(const char* pchVersion)
{
    void* pIface = orig_SteamInternal_CreateInterface
                   ? orig_SteamInternal_CreateInterface(pchVersion)
                   : nullptr;

    if (pIface && pchVersion)
        PatchInterface(pchVersion, pIface);

    return pIface;
}


// =============================================================================
//  MinHook installation
//  All hooks target functions inside steam_api64_o.dll's loaded image.
//  Because the .def forwarder records cause Windows to load the DLL before
//  DLL_PROCESS_ATTACH fires, GetModuleHandleA is sufficient here.
// =============================================================================
struct HookEntry
{
    const char* procName;
    void*       pDetour;
    void**      ppOriginal;
};

static const HookEntry k_hooks[] =
{
    {
        "SteamAPI_Init",
        reinterpret_cast<void*>(&Detour_SteamAPI_Init),
        reinterpret_cast<void**>(&orig_SteamAPI_Init)
    },
    {
        "SteamAPI_ISteamUtils_GetAppID",
        reinterpret_cast<void*>(&Detour_SteamAPI_ISteamUtils_GetAppID),
        reinterpret_cast<void**>(&orig_SteamAPI_ISteamUtils_GetAppID)
    },
    {
        "SteamAPI_ISteamUser_GetAppID",
        reinterpret_cast<void*>(&Detour_SteamAPI_ISteamUser_GetAppID),
        reinterpret_cast<void**>(&orig_SteamAPI_ISteamUser_GetAppID)
    },
    {
        // SteamInternal_CreateInterface may not appear in all .def exports;
        // it is always present as a named export in steam_api64_o.dll itself.
        "SteamInternal_CreateInterface",
        reinterpret_cast<void*>(&Detour_SteamInternal_CreateInterface),
        reinterpret_cast<void**>(&orig_SteamInternal_CreateInterface)
    },
};

static bool InstallHooks()
{
    // steam_api64_o.dll is already in the process image by the time
    // DLL_PROCESS_ATTACH fires (the .def forwarder causes an implicit load).
    // We call LoadLibraryA to obtain a stable HMODULE and increment refcount.
    g_hOrigDll = LoadLibraryA(ORIG_DLL);
    if (!g_hOrigDll)
        return false;

    if (MH_Initialize() != MH_OK)
        return false;

    for (const auto& h : k_hooks)
    {
        FARPROC pTarget = GetProcAddress(g_hOrigDll, h.procName);
        if (!pTarget)
            continue;   // Missing export in this SDK version – silently skip.

        MH_STATUS st = MH_CreateHook(
            reinterpret_cast<LPVOID>(pTarget),
            h.pDetour,
            reinterpret_cast<LPVOID*>(h.ppOriginal));

        if (st != MH_OK && st != MH_ERROR_ALREADY_CREATED)
            return false;
    }

    return MH_EnableHook(MH_ALL_HOOKS) == MH_OK;
}

static void RemoveHooks()
{
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}


// =============================================================================
//  DllMain entry point
// =============================================================================
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)lpvReserved;

    switch (fdwReason)
    {
    // -------------------------------------------------------------------------
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hinstDLL);

        // ── Step 1: Set SteamAppId in the process environment.
        //    This must happen before ANYTHING reads it.  GameOverlayRenderer64
        //    and the Steam client internal code both read this env var during
        //    their own DLL_PROCESS_ATTACH, which fires after ours.
        SetupSteamEnvironment();

        // ── Step 2: Resolve vtable.txt path (same directory as this DLL).
        char dllPath[MAX_PATH] = {};
        GetModuleFileNameA(hinstDLL, dllPath, MAX_PATH);
        std::string dir(dllPath);
        auto slash = dir.find_last_of("\\/");
        std::string vtablePath = (slash != std::string::npos)
                                  ? dir.substr(0, slash + 1) + VTABLE_FILE
                                  : VTABLE_FILE;

        LoadVTableIndexes(vtablePath);

        // ── Step 3: Install MinHook inline hooks into steam_api64_o.dll.
        //    Failure is non-fatal: the env vars and steam_appid.txt are
        //    already applied, and all exports still forward correctly.
        InstallHooks();

        break;
    }

    // -------------------------------------------------------------------------
    case DLL_PROCESS_DETACH:
    {
        RemoveHooks();
        if (g_hOrigDll)
        {
            FreeLibrary(g_hOrigDll);
            g_hOrigDll = nullptr;
        }
        break;
    }

    default:
        break;
    }

    return TRUE;
}
