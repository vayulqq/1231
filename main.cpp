// =============================================================================
//  dllmain.cpp  –  Steam Proxy DLL  (DEBUG BUILD — VTable hooks disabled)
//  All calls are logged to proxy_log.txt in the game directory.
//
//  Build (MSVC x64):
//    cl /LD /EHsc /std:c++17 dllmain.cpp /Fe:steam_api64.dll
//       /link /DEF:steam_api64.def MinHook.x64.lib kernel32.lib
// =============================================================================

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdio>
#include <cstring>

#include "MinHook.h"

// =============================================================================
//  Constants
// =============================================================================
static constexpr DWORD TARGET_APPID = 480;
static constexpr char  ORIG_DLL[]   = "steam_api64_o.dll";
static constexpr char  APPID_STR[]  = "480";
static constexpr char  LOG_FILE[]   = "proxy_log.txt";

using AppId_t = unsigned int;

// =============================================================================
//  Logger  —  unbuffered, flushes on every write so output survives a crash
// =============================================================================
static CRITICAL_SECTION g_logCs;
static FILE*            g_logFile = nullptr;

static void LogInit()
{
    InitializeCriticalSection(&g_logCs);
    g_logFile = fopen(LOG_FILE, "w");
    if (g_logFile)
        setvbuf(g_logFile, nullptr, _IONBF, 0);  // no buffering
}

static void LogShutdown()
{
    if (g_logFile) { fclose(g_logFile); g_logFile = nullptr; }
    DeleteCriticalSection(&g_logCs);
}

static void Log(const char* fmt, ...)
{
    if (!g_logFile) return;
    EnterCriticalSection(&g_logCs);
    fprintf(g_logFile, "[%6lu ms] ", GetTickCount());
    va_list args;
    va_start(args, fmt);
    vfprintf(g_logFile, fmt, args);
    va_end(args);
    fprintf(g_logFile, "\n");
    LeaveCriticalSection(&g_logCs);
}

// =============================================================================
//  Globals
// =============================================================================
static HMODULE g_hOrigDll = nullptr;

using fn_SteamAPI_Init                  = bool    (__cdecl*)();
using fn_SteamAPI_RestartAppIfNecessary = bool    (__cdecl*)(AppId_t);
using fn_SteamAPI_Shutdown              = void    (__cdecl*)();
using fn_SteamAPI_RunCallbacks          = void    (__cdecl*)();
using fn_SteamAPI_ISteamUtils_GetAppID  = AppId_t (__cdecl*)(void*);
using fn_SteamAPI_ISteamUser_GetAppID   = AppId_t (__cdecl*)(void*);
using fn_SteamInternal_CreateInterface  = void*   (__cdecl*)(const char*);

static fn_SteamAPI_Init                  orig_SteamAPI_Init                  = nullptr;
static fn_SteamAPI_RestartAppIfNecessary orig_SteamAPI_RestartAppIfNecessary = nullptr;
static fn_SteamAPI_Shutdown              orig_SteamAPI_Shutdown              = nullptr;
static fn_SteamAPI_RunCallbacks          orig_SteamAPI_RunCallbacks          = nullptr;
static fn_SteamAPI_ISteamUtils_GetAppID  orig_SteamAPI_ISteamUtils_GetAppID  = nullptr;
static fn_SteamAPI_ISteamUser_GetAppID   orig_SteamAPI_ISteamUser_GetAppID   = nullptr;
static fn_SteamInternal_CreateInterface  orig_SteamInternal_CreateInterface  = nullptr;

// =============================================================================
//  Environment setup
// =============================================================================
static void SetupSteamEnvironment()
{
    SetEnvironmentVariableA("SteamAppId",  APPID_STR);
    SetEnvironmentVariableA("SteamGameId", APPID_STR);
    Log("SetEnvironmentVariable SteamAppId=%s  SteamGameId=%s", APPID_STR, APPID_STR);

    HANDLE hFile = CreateFileA("steam_appid.txt",
                               GENERIC_WRITE, 0, nullptr,
                               CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        WriteFile(hFile, APPID_STR, (DWORD)strlen(APPID_STR), &written, nullptr);
        CloseHandle(hFile);
        Log("Created steam_appid.txt");
    }
    else
    {
        Log("steam_appid.txt already exists — skipped");
    }
}

// =============================================================================
//  Detours
// =============================================================================
static bool __cdecl Detour_SteamAPI_RestartAppIfNecessary(AppId_t unOwnAppID)
{
    Log("SteamAPI_RestartAppIfNecessary(appID=%u) -> returning false", unOwnAppID);
    return false;
}

static bool __cdecl Detour_SteamAPI_Init()
{
    Log("SteamAPI_Init() -> calling original...");
    bool result = orig_SteamAPI_Init ? orig_SteamAPI_Init() : false;
    Log("SteamAPI_Init() returned %s", result ? "TRUE" : "FALSE");
    return result;
}

static void __cdecl Detour_SteamAPI_Shutdown()
{
    Log("SteamAPI_Shutdown()");
    if (orig_SteamAPI_Shutdown) orig_SteamAPI_Shutdown();
}

static void __cdecl Detour_SteamAPI_RunCallbacks()
{
    static volatile LONG once = 0;
    if (InterlockedCompareExchange(&once, 1, 0) == 0)
        Log("SteamAPI_RunCallbacks() — first call (not logging further)");
    if (orig_SteamAPI_RunCallbacks) orig_SteamAPI_RunCallbacks();
}

static AppId_t __cdecl Detour_SteamAPI_ISteamUtils_GetAppID(void* pISteamUtils)
{
    Log("SteamAPI_ISteamUtils_GetAppID(ptr=%p) -> %u", pISteamUtils, TARGET_APPID);
    return TARGET_APPID;
}

static AppId_t __cdecl Detour_SteamAPI_ISteamUser_GetAppID(void* pISteamUser)
{
    Log("SteamAPI_ISteamUser_GetAppID(ptr=%p) -> %u", pISteamUser, TARGET_APPID);
    return TARGET_APPID;
}

static void* __cdecl Detour_SteamInternal_CreateInterface(const char* pchVersion)
{
    Log("SteamInternal_CreateInterface(\"%s\") ...", pchVersion ? pchVersion : "<null>");
    void* pIface = orig_SteamInternal_CreateInterface
                   ? orig_SteamInternal_CreateInterface(pchVersion)
                   : nullptr;
    Log("SteamInternal_CreateInterface(\"%s\") -> %p",
        pchVersion ? pchVersion : "<null>", pIface);
    return pIface;
}

// =============================================================================
//  Hook table + install
// =============================================================================
struct HookEntry { const char* name; void* detour; void** orig; };

static const HookEntry k_hooks[] =
{
    { "SteamAPI_RestartAppIfNecessary",
      (void*)&Detour_SteamAPI_RestartAppIfNecessary,
      (void**)&orig_SteamAPI_RestartAppIfNecessary },

    { "SteamAPI_Init",
      (void*)&Detour_SteamAPI_Init,
      (void**)&orig_SteamAPI_Init },

    { "SteamAPI_Shutdown",
      (void*)&Detour_SteamAPI_Shutdown,
      (void**)&orig_SteamAPI_Shutdown },

    { "SteamAPI_RunCallbacks",
      (void*)&Detour_SteamAPI_RunCallbacks,
      (void**)&orig_SteamAPI_RunCallbacks },

    { "SteamAPI_ISteamUtils_GetAppID",
      (void*)&Detour_SteamAPI_ISteamUtils_GetAppID,
      (void**)&orig_SteamAPI_ISteamUtils_GetAppID },

    { "SteamAPI_ISteamUser_GetAppID",
      (void*)&Detour_SteamAPI_ISteamUser_GetAppID,
      (void**)&orig_SteamAPI_ISteamUser_GetAppID },

    { "SteamInternal_CreateInterface",
      (void*)&Detour_SteamInternal_CreateInterface,
      (void**)&orig_SteamInternal_CreateInterface },
};

static bool InstallHooks()
{
    Log("LoadLibraryA(\"%s\") ...", ORIG_DLL);
    g_hOrigDll = LoadLibraryA(ORIG_DLL);
    if (!g_hOrigDll)
    {
        Log("FATAL: failed to load %s  (error=%lu)", ORIG_DLL, GetLastError());
        return false;
    }
    Log("Loaded %s  base=%p", ORIG_DLL, (void*)g_hOrigDll);

    MH_STATUS st = MH_Initialize();
    Log("MH_Initialize() -> %d", (int)st);
    if (st != MH_OK) return false;

    for (const auto& h : k_hooks)
    {
        FARPROC target = GetProcAddress(g_hOrigDll, h.name);
        if (!target) { Log("  SKIP  %s  (not exported)", h.name); continue; }

        st = MH_CreateHook((LPVOID)target, h.detour, (LPVOID*)h.orig);
        Log("  %s  %-50s  target=%p  st=%d",
            (st == MH_OK || st == MH_ERROR_ALREADY_CREATED) ? "HOOK" : "FAIL",
            h.name, (void*)target, (int)st);
    }

    st = MH_EnableHook(MH_ALL_HOOKS);
    Log("MH_EnableHook(ALL) -> %d", (int)st);
    return st == MH_OK;
}

static void RemoveHooks()
{
    Log("RemoveHooks");
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

// =============================================================================
//  DllMain
// =============================================================================
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)lpvReserved;
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hinstDLL);
        LogInit();

        Log("========================================");
        Log("DLL_PROCESS_ATTACH  hinstDLL=%p", (void*)hinstDLL);

        char path[MAX_PATH] = {};
        GetModuleFileNameA(hinstDLL, path, MAX_PATH);
        Log("Proxy DLL : %s", path);

        char cwd[MAX_PATH] = {};
        GetCurrentDirectoryA(MAX_PATH, cwd);
        Log("CWD       : %s", cwd);

        DWORD attr = GetFileAttributesA(ORIG_DLL);
        if (attr == INVALID_FILE_ATTRIBUTES)
            Log("WARNING   : %s NOT FOUND in CWD!", ORIG_DLL);
        else
            Log("Found     : %s  (attr=0x%lx)", ORIG_DLL, attr);

        SetupSteamEnvironment();

        bool ok = InstallHooks();
        Log("InstallHooks -> %s", ok ? "OK" : "FAILED");
        Log("DLL_PROCESS_ATTACH done");
        Log("========================================");
        break;
    }
    case DLL_PROCESS_DETACH:
    {
        Log("DLL_PROCESS_DETACH");
        RemoveHooks();
        if (g_hOrigDll) { FreeLibrary(g_hOrigDll); g_hOrigDll = nullptr; }
        LogShutdown();
        break;
    }
    default: break;
    }
    return TRUE;
}
