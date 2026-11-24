
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "winhttp.lib")

#define PREVIEW_BYTES 16384
#define TOKEN_BUFFER_SIZE 2048

static void print_help(void)
{
    printf(
        "Windows Connectivity Test\n"
        "\n"
        "Usage:\n"
        "  connectivity.exe [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  -h, --help        Show this help message\n"
        "  --token TOKEN     HTTP Bearer authentication token\n"
        "\n"
        "Environment:\n"
        "  FC_TEST_TOKEN     Authentication token\n"
        "\n"
        "Examples:\n"
        "  connectivity.exe --help\n"
        "  connectivity.exe --token YOUR_TOKEN\n"
        "  connectivity.exe\n"
        "\n"
        "Targets:\n"
        "  https://fangcunleap.com/  (authenticated)\n"
        "  http://112.126.85.175/  (connectivity only)\n"
    );
}

static BOOL valid_token(const wchar_t *token)
{
    if (token == NULL || *token == L'\0')
        return FALSE;

    for (const wchar_t *p = token; *p; ++p) {
        if (*p <= 32 || *p > 126)
            return FALSE;
    }

    return TRUE;
}

static BOOL visit(const wchar_t *url, const wchar_t *token)
{
    URL_COMPONENTS components = {0};
    wchar_t host[256] = {0};
    wchar_t path[2048] = {0};
    wchar_t extra[1024] = {0};
    wchar_t request_path[3072] = {0};

    HINTERNET session = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;

    BOOL ok = FALSE;
    DWORD status_code = 0;

    components.dwStructSize = sizeof(components);
    components.lpszHostName = host;
    components.dwHostNameLength = _countof(host);
    components.lpszUrlPath = path;
    components.dwUrlPathLength = _countof(path);
    components.lpszExtraInfo = extra;
    components.dwExtraInfoLength = _countof(extra);

    if (!WinHttpCrackUrl(url, 0, 0, &components)) {
        fprintf(stderr, "Invalid URL: %lu\n", GetLastError());
        return FALSE;
    }

    // Never transmit credentials over plaintext HTTP.
    if (token != NULL &&
        components.nScheme != INTERNET_SCHEME_HTTPS) {
        fprintf(stderr, "Authentication requires HTTPS.\n");
        return FALSE;
    }

    if (swprintf_s(
            request_path,
            _countof(request_path),
            L"%ls%ls",
            path[0] ? path : L"/",
            extra) < 0) {
        fprintf(stderr, "Request path is too long.\n");
        return FALSE;
    }

    session = WinHttpOpen(
        L"Windows Connectivity Test/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!session)
        goto cleanup;

    WinHttpSetTimeouts(session, 10000, 10000, 15000, 30000);

    connection = WinHttpConnect(
        session,
        host,
        components.nPort,
        0
    );

    if (!connection)
        goto cleanup;

    request = WinHttpOpenRequest(
        connection,
        L"GET",
        request_path,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        components.nScheme == INTERNET_SCHEME_HTTPS
            ? WINHTTP_FLAG_SECURE : 0
    );

    if (!request)
        goto cleanup;

    // Prevent automatic redirects with credentials.
    {
        DWORD flags = WINHTTP_DISABLE_REDIRECTS;

        if (!WinHttpSetOption(
                request,
                WINHTTP_OPTION_DISABLE_FEATURE,
                &flags,
                sizeof(flags))) {
            goto cleanup;
        }
    }

    // Add Bearer authentication if requested.
    if (token != NULL) {
        wchar_t header[TOKEN_BUFFER_SIZE + 64];

        if (!valid_token(token)) {
            fprintf(stderr, "Invalid authentication token.\n");
            goto cleanup;
        }

        if (swprintf_s(
                header,
                _countof(header),
                L"Authorization: Bearer %ls\r\n",
                token) < 0) {
            fprintf(stderr, "Authentication token is too long.\n");
            goto cleanup;
        }

        if (!WinHttpAddRequestHeaders(
                request,
                header,
                (DWORD)-1L,
                WINHTTP_ADDREQ_FLAG_ADD |
                WINHTTP_ADDREQ_FLAG_REPLACE)) {
            goto cleanup;
        }

        printf("Authentication header attached.\n");
    }

    if (!WinHttpSendRequest(
            request,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0)) {
        goto cleanup;
    }

    if (!WinHttpReceiveResponse(request, NULL))
        goto cleanup;

    {
        DWORD status_size = sizeof(status_code);

        if (!WinHttpQueryHeaders(
                request,
                WINHTTP_QUERY_STATUS_CODE |
                WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX,
                &status_code,
                &status_size,
                WINHTTP_NO_HEADER_INDEX)) {
            goto cleanup;
        }
    }

    printf("HTTP Status: %lu\n", status_code);

    if (status_code == 401) {
        printf("Authentication failed: Unauthorized\n");
    } else if (status_code == 403) {
        printf("Authentication failed: Forbidden\n");
    }

    {
        BYTE buffer[4096];
        DWORD available = 0;
        DWORD written = 0;

        while (WinHttpQueryDataAvailable(request, &available)
               && available > 0) {

            DWORD to_read = available > sizeof(buffer)
                ? sizeof(buffer) : available;

            DWORD bytes_read = 0;

            if (!WinHttpReadData(
                    request, buffer, to_read, &bytes_read)
                || bytes_read == 0) {
                break;
            }

            if (written < PREVIEW_BYTES) {
                DWORD remaining = PREVIEW_BYTES - written;
                DWORD to_write = bytes_read < remaining
                    ? bytes_read : remaining;

                fwrite(buffer, 1, to_write, stdout);
                written += to_write;
            }
        }
    }

    printf("\n");

    ok = status_code >= 200 && status_code < 300;

cleanup:
    if (!ok && status_code == 0) {
        fprintf(stderr, "Request failed. Win32 error: %lu\n",
                GetLastError());
    }

    if (request)
        WinHttpCloseHandle(request);

    if (connection)
        WinHttpCloseHandle(connection);

    if (session)
        WinHttpCloseHandle(session);

    fflush(stdout);
    return ok;
}

# int visit()
# 具体鉴权细节隐藏，请下载最新版本
# int auth()
# 具体鉴权细节隐藏，请下载最新版本

int wmain(int argc, wchar_t *argv[])
{
    SetConsoleOutputCP(CP_UTF8);

    const wchar_t *token = NULL;
    wchar_t env_token[TOKEN_BUFFER_SIZE] = {0};

    // Parse command-line arguments.
    for (int i = 1; i < argc; i++) {

        if (wcscmp(argv[i], L"--help") == 0 ||
            wcscmp(argv[i], L"-h") == 0) {
            print_help();
            return 0;
        }

        if (wcscmp(argv[i], L"--token") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Missing value for --token\n");
                return 1;
            }

            token = argv[++i];
            continue;
        }

        fprintf(stderr, "Unknown argument.\n");
        print_help();
        return 1;
    }

    // Use environment variable when --token is absent.
    if (token == NULL) {
        DWORD len = GetEnvironmentVariableW(
            L"FC_TEST_TOKEN",
            env_token,
            _countof(env_token)
        );

        if (len >= _countof(env_token)) {
            fprintf(stderr, "Environment token is too long.\n");
            return 1;
        }

        if (len > 0)
            token = env_token;
    }

    if (!valid_token(token)) {
        fprintf(stderr,
                "Missing or invalid token. Use --help for usage.\n");
        return 1;
    }

    printf("Windows Connectivity Test\n\n");

    printf("Target: https://fangcunleap.com/\n");
    BOOL result1 = visit(L"https://fangcunleap.com/", token);

    Sleep(1000);

    printf("\nTarget: http://112.126.85.175/\n");
    BOOL result2 = visit(L"http://112.126.85.175/", NULL);
    ret = auth("http://112.126.85.175")
    visit(ret, "http://112.126.85.175/")
    printf("\nResult: %s\n",
           (result1 && result2) ? "SUCCESS" : "FAILED");

    printf("Press Enter to exit...\n");
    getchar();

    return (result1 && result2) ? 0 : 1;
}
