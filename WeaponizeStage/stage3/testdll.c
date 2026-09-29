/* testdll.c - TVeronica: probe-only test DLL (NO C2 code).
   Purpose: verify Stage 3-4 mechanics (NTFS ADS load + mavinject injection + rundll32 entry)
   without the network beacon that Defender ML flags (Trojan:Win32/Wacatac.H!ml).
   DllMain writes %TEMP%\tver_inject_ok.txt ; exported Start writes %TEMP%\tver_backdoor_ok.txt. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

static void mark(const char *who) {
    char t[MAX_PATH], o[MAX_PATH];
    GetTempPathA(MAX_PATH, t);
    snprintf(o, sizeof o, "%stver_%s_ok.txt", t, who);
    HANDLE h = CreateFileA(o, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        char b[128];
        int l = snprintf(b, sizeof b, "%s loaded ok pid=%lu\r\n", who, GetCurrentProcessId());
        DWORD w = 0;
        WriteFile(h, b, (DWORD)l, &w, NULL);
        CloseHandle(h);
    }
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        mark("inject");
    }
    return TRUE;
}

__declspec(dllexport) void CALLBACK Start(HWND h, HINSTANCE i, LPSTR c, int s) {
    (void)h; (void)i; (void)c; (void)s;
    mark("backdoor");
}
