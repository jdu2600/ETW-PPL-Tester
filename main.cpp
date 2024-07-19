#include "singleheader.h"

krabs::user_trace g_trace(L"EtwTiTester");
DWORD WINAPI EtwEventThread(LPVOID) {
    g_trace.start();
    return 0;
}

int wmain(int, wchar_t**) {
    PrintVersion();
    
    // See https://github.com/microsoft/krabsetw for documentation on the krabs etw library.
    printf("[*] Enabling Microsoft-Windows-Threat-Intelligence\n");
    krabs::provider<> ti_provider(L"Microsoft-Windows-Threat-Intelligence");

    // Keywords, event ids and field information available here -
    // https://github.com/zodiacon/EtwExplorer
    // https://github.com/jdu2600/Windows10EtwEvents/blob/main/manifest/Microsoft-Windows-Threat-Intelligence.tsv

    // Enable any desired events via their keywords.
    // Some events require additional configuration. For background see -
    // https://www.riskinsight-wavestone.com/en/2023/10/a-universal-edr-bypass-built-in-windows-10/
    // https://www.legacyy.xyz/defenseevasion/windows/2024/04/24/disabling-etw-ti-without-ppl.html
    ti_provider.any(ETW_THREAT_INTEL_KEYWORD_ALLOCVM_LOCAL);

    auto callback = [](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        static krabs::schema schema(record, trace_context.schema_locator);
        static krabs::parser parser(schema);
        
        switch (record.EventHeader.EventDescriptor.Id)
        {
        case ETW_THREAT_INTEL_ALLOCVM_LOCAL:
        {
            auto protectionMask = parser.parse<DWORD>(L"ProtectionMask");
            if (PAGE_EXECUTE_READWRITE == protectionMask)
            {
                auto regionSize = (SIZE_T)parser.parse<PVOID>(L"RegionSize");
                auto baseAddress = (ULONG_PTR)parser.parse<PVOID>(L"BaseAddress");
                printf("pid:%u VirtualAlloc( 0x%llx, 0x%llx, PAGE_EXECUTE_READWRITE )\n", record.EventHeader.ProcessId, baseAddress, regionSize);
            }
            break;
        }
        default:
            printf("Unhandled ETW-TI event id:%hu\n", record.EventHeader.EventDescriptor.Id);
        };
    };

    ti_provider.add_on_event_callback(callback);
    
    // Use BYOVD to enable PPL and start our trace.
    g_trace.enable(ti_provider);
    InstallVulnerableDriver();
    EnablePPL();
    HANDLE hThread = CreateThread(NULL, 0, EtwEventThread, NULL, 0, NULL);
    assert(NULL != hThread);
    Sleep(1000);
    DisablePPL();

    
    // Then keep watching.
    while (true) {};

    return 0;
}