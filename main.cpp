#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>

using AppId_t = uint32_t;

static constexpr AppId_t SPACEWAR_APPID = 480; // Для обхода через Spacewar
static constexpr AppId_t ORIGINAL_APPID = 242760; // The Forest

static HMODULE g_hOrig = nullptr;
static char    g_appidPath[MAX_PATH] = { 0 };
static bool    g_PathInitialized = false;

// =============================================================================
//  Утилиты
// =============================================================================

template<typename T>
static inline T GetProc(const char* name)
{
    if (!g_hOrig) return nullptr;
    return reinterpret_cast<T>(GetProcAddress(g_hOrig, name));
}

static void WriteAppId(AppId_t id)
{
    if (g_appidPath[0] == '\0') return;

    char buf[12];
    int len = wsprintfA(buf, "%u", id);
    
    HANDLE h = CreateFileA(g_appidPath, GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    
    if (h != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(h, buf, len, &written, nullptr);
        CloseHandle(h);
    }
}

static void InitPath()
{
    if (g_PathInitialized) return;

    // Получаем путь к папке с игрой и создаем путь к steam_appid.txt
    GetModuleFileNameA(nullptr, g_appidPath, MAX_PATH);
    char* sep = strrchr(g_appidPath, '\\');
    if (sep) *(sep + 1) = '\0';
    lstrcatA(g_appidPath, "steam_appid.txt");

    g_PathInitialized = true;
}

static bool DoInit(const char* name)
{
    InitPath();
    
    // Переключаем на Spacewar перед инициализацией
    WriteAppId(SPACEWAR_APPID);
    
    bool result = false;
    if (auto fn = GetProc<bool(*)()>(name))
        result = fn();
        
    // Возвращаем родной AppID после вызова
    WriteAppId(ORIGINAL_APPID);
    return result;
}

// =============================================================================
//  Экспорты (Proxy)
// =============================================================================

extern "C" __declspec(dllexport) bool SteamAPI_Init()
{ 
    return DoInit("SteamAPI_Init"); 
}

extern "C" __declspec(dllexport) bool SteamAPI_InitSafe()
{ 
    return DoInit("SteamAPI_InitSafe"); 
}

extern "C" __declspec(dllexport) bool SteamAPI_RestartAppIfNecessary(AppId_t)
{ 
    // Возвращаем false, чтобы Steam не пытался перезапустить игру сам
    return false; 
}

extern "C" __declspec(dllexport) bool SteamGameServer_Init(
    uint32_t unIP, uint16_t usSteamPort, uint16_t usGamePort,
    uint16_t usQueryPort, int eServerMode, const char* pchVersionString)
{
    InitPath();
    WriteAppId(SPACEWAR_APPID);
    
    bool result = false;
    if (auto fn = GetProc<bool(*)(uint32_t,uint16_t,uint16_t,uint16_t,int,const char*)>("SteamGameServer_Init"))
        result = fn(unIP, usSteamPort, usGamePort, usQueryPort, eServerMode, pchVersionString);
        
    WriteAppId(ORIGINAL_APPID);
    return result;
}

// =============================================================================
//  DllMain
// =============================================================================

BOOL WINAPI DllMain(HINSTANCE, DWORD fdwReason, LPVOID)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        // Загружаем оригинальную либу
        g_hOrig = LoadLibraryA("steam_api64_o.dll");
        if (!g_hOrig) return FALSE;
    }
    else if (fdwReason == DLL_PROCESS_DETACH)
    {
        if (g_hOrig) FreeLibrary(g_hOrig);
    }
    return TRUE;
}
