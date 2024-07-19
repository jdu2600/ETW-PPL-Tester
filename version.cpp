#include "singleheader.h"

#pragma comment(lib, "ntdll.lib")
extern "C" {
    NTSTATUS WINAPI RtlGetVersion(PRTL_OSVERSIONINFOW);
}

void PrintVersion()
{
    HKEY hKey;
    WCHAR szProduct[512]{};
    WCHAR szDisplayVersion[512]{};
    WCHAR szBuild[512]{};
    DWORD dwUBR;
    DWORD dwSize;
    RTL_OSVERSIONINFOW vi{};
    vi.dwOSVersionInfoSize = sizeof(PRTL_OSVERSIONINFOW);
    RtlGetVersion(&vi);

    RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey);
    dwSize = sizeof(dwUBR);
    RegQueryValueExW(hKey, L"UBR", 0, NULL, reinterpret_cast<LPBYTE>(&dwUBR), &dwSize);
    dwSize = sizeof(szProduct);
    RegQueryValueExW(hKey, L"ProductName", 0, NULL, (LPBYTE)szProduct, &dwSize);
    dwSize = sizeof(szDisplayVersion);
    RegQueryValueExW(hKey, L"DisplayVersion", 0, NULL, (LPBYTE)szDisplayVersion, &dwSize);
    if (0 == wcslen(szDisplayVersion))
    {
        dwSize = sizeof(szDisplayVersion);
        (void)RegQueryValueExW(hKey, L"ReleaseId", 0, NULL, (LPBYTE)szDisplayVersion, &dwSize);
    }
    dwSize = sizeof(szBuild);
    RegQueryValueExW(hKey, L"BuildLabEx", 0, NULL, (LPBYTE)szBuild, &dwSize);
    printf("%S %S %d.%d.%d.%d %S\n", szProduct, szDisplayVersion,
        vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber, dwUBR, szBuild);
}