#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winhttp.h>
#include <shellapi.h>
#include <stdio.h>

#define PREVIEW_BYTES 16384

static BOOL visit(const wchar_t *url)
{
    URL_COMPONENTS components = {0};
    wchar_t host[256] = {0};
    wchar_t path[2048] = {0};
    HINTERNET session = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    BOOL ok = FALSE;

    components.dwStructSize = sizeof(components);
    components.lpszHostName = host;
    components.dwHostNameLength = (DWORD)(sizeof(host) / sizeof(host[0]) - 1);
    components.lpszUrlPath = path;
    components.dwUrlPathLength = (DWORD)(sizeof(path) / sizeof(path[0]) - 1);

    if (!WinHttpCrackUrl(url, 0, 0, &components)) {
        return FALSE;
    }

    session = WinHttpOpen(L"Transparent Windows connectivity test",
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME,
                          WINHTTP_NO_PROXY_BYPASS,
                          0);
    if (session == NULL) {
        goto cleanup;
    }

    WinHttpSetTimeouts(session, 10000, 10000, 15000, 30000);

    connection = WinHttpConnect(session, host, components.nPort, 0);
    if (connection == NULL) {
        goto cleanup;
    }

    request = WinHttpOpenRequest(connection,
                                 L"GET",
                                 path[0] != L'\0' ? path : L"/",
                                 NULL,
                                 WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES,
                                 components.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
    if (request == NULL) {
        goto cleanup;
    }

    if (!WinHttpSendRequest(request,
                            WINHTTP_NO_ADDITIONAL_HEADERS,
                            0,
                            WINHTTP_NO_REQUEST_DATA,
                            0,
                            0,
                            0)) {
        goto cleanup;
    }

    if (!WinHttpReceiveResponse(request, NULL)) {
        goto cleanup;
    }

    {
        DWORD status_code = 0;
        DWORD status_size = sizeof(status_code);
        if (WinHttpQueryHeaders(request,
                                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX,
                                &status_code,
                                &status_size,
                                WINHTTP_NO_HEADER_INDEX)) {
            printf("%lu\n", status_code);
        }
    }

    {
        BYTE buffer[4096];
        DWORD available = 0;
        DWORD written = 0;

        while (WinHttpQueryDataAvailable(request, &available) && available > 0) {
            DWORD to_read = available > (DWORD)sizeof(buffer) ? (DWORD)sizeof(buffer) : available;
            DWORD bytes_read = 0;

            if (!WinHttpReadData(request, buffer, to_read, &bytes_read) || bytes_read == 0) {
                break;
            }

            if (written < PREVIEW_BYTES) {
                DWORD remaining = PREVIEW_BYTES - written;
                DWORD to_write = bytes_read < remaining ? bytes_read : remaining;
                fwrite(buffer, 1, to_write, stdout);
                written += to_write;
            }
        }
    }

    printf("\n");
    fflush(stdout);
    ok = TRUE;

cleanup:
    if (request != NULL) {
        WinHttpCloseHandle(request);
    }
    if (connection != NULL) {
        WinHttpCloseHandle(connection);
    }
    if (session != NULL) {
        WinHttpCloseHandle(session);
    }
    return ok;
}

int wmain(void)
{
    SetConsoleOutputCP(CP_UTF8);

    printf("Transparent Windows connectivity test\n");

    printf("https://fangcunleap.com/\n");
    visit(L"https://fangcunleap.com/");
    Sleep(1000);

    printf("http://127.0.0.1:8765/\n");
    visit(L"http://127.0.0.1:8765/");

    getwchar();
    return 0;
}
