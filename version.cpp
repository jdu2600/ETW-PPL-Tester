#include "singleheader.h"

#pragma comment(lib, "ntdll.lib")
extern "C" {
    NTSTATUS WINAPI RtlGetVersion(PRTL_OSVERSIONINFOW);
}

void PrintVersion()
{
    RTL_OSVERSIONINFOW vi{};
    vi.dwOSVersionInfoSize = sizeof(PRTL_OSVERSIONINFOW);
    (void)RtlGetVersion(&vi);

    HKEY hKey = NULL;
    (void)RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey);

    DWORD dwUBR = 0;
    DWORD dwSize = sizeof(dwUBR);
    (void)RegQueryValueExW(hKey, L"UBR", 0, NULL, reinterpret_cast<LPBYTE>(&dwUBR), &dwSize);

    WCHAR szProduct[512]{};
    dwSize = sizeof(szProduct);
    (void)RegQueryValueExW(hKey, L"ProductName", 0, NULL, (LPBYTE)szProduct, &dwSize);
    constexpr DWORD WIN11_21H2 = 22000;
    if ((vi.dwBuildNumber >= WIN11_21H2) && (0 == wcsncmp(szProduct, L"Windows 10", 10))) {  // lies!
        szProduct[9] = L'1';
    }

    WCHAR szDisplayVersion[512]{};
    dwSize = sizeof(szDisplayVersion);
    (void)RegQueryValueExW(hKey, L"DisplayVersion", 0, NULL, (LPBYTE)szDisplayVersion, &dwSize);
    if (0 == wcslen(szDisplayVersion)) {
        dwSize = sizeof(szDisplayVersion);
        (void)RegQueryValueExW(hKey, L"ReleaseId", 0, NULL, (LPBYTE)szDisplayVersion, &dwSize);
    }

    WCHAR szBuild[512]{};
    dwSize = sizeof(szBuild);
    (void)RegQueryValueExW(hKey, L"BuildLabEx", 0, NULL, (LPBYTE)szBuild, &dwSize);

    printf("%S %S %d.%d.%d.%d %S\n", szProduct, szDisplayVersion, vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber, dwUBR, szBuild);
}