#include <windows.h>
#include <iostream>
#include <vector>
#include <intrin.h>
#include <wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

using u64 = unsigned long long;
using u32 = unsigned int;
using u8  = unsigned char;

// Detection flags
#define FLG_BIOS 0x1
#define FLG_CPU  0x2
#define FLG_WMI  0x4
#define FLG_TIME 0x8

// Count the number of WMI query results
int wmi_count(IWbemServices* svc, const wchar_t* query) {
    IEnumWbemClassObject* enumerator = nullptr;

    if (FAILED(svc->ExecQuery(SysAllocString(L"WQL"), SysAllocString(query), WBEM_FLAG_FORWARD_ONLY, nullptr, &enumerator)))
        return 0;

    IWbemClassObject* object = nullptr;
    ULONG returned = 0;
    int count = 0;

    while (enumerator) {
        enumerator->Next(WBEM_INFINITE, 1, &object, &returned);
        if (!returned) break;
        count++;
        object->Release();
    }

    enumerator->Release();
    return count;
}

int main() {
    u32 detectionMask = 0;

    // Initialize COM for WMI
    if (SUCCEEDED(CoInitializeEx(nullptr, COINIT_MULTITHREADED))) {
        CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                             RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);

        IWbemLocator* locator = nullptr;
        IWbemServices* service = nullptr;

        if (SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (void**)&locator))) {
            if (SUCCEEDED(locator->ConnectServer(SysAllocString(L"ROOT\\CIMV2"), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &service))) {
                CoSetProxyBlanket(service, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
                                  RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

                // Check for WMI objects that are usually missing in VMs
                if (!wmi_count(service, L"SELECT * FROM Win32_Fan"))          detectionMask |= FLG_WMI;
                if (!wmi_count(service, L"SELECT * FROM Win32_CacheMemory"))  detectionMask |= FLG_WMI;
                if (!wmi_count(service, L"SELECT * FROM Win32_VoltageProbe")) detectionMask |= FLG_WMI;

                service->Release();
            }
            locator->Release();
        }
        CoUninitialize();
    }

    // Check BIOS table
    DWORD tableSize = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (tableSize) {
        std::vector<u8> buffer(tableSize);
        GetSystemFirmwareTable('RSMB', 0, buffer.data(), tableSize);

        u8* ptr = buffer.data() + 8;
        u8* end = buffer.data() + tableSize;

        while (ptr < end) {
            if (*ptr == 127) break;
            if (*ptr == 0 && *(ptr + 1) > 0x12) {
                u64 biosBits = *(u64*)(ptr + 8);
                if ((biosBits >> 3) & 1) detectionMask |= FLG_BIOS;

                // Count number of set bits (real BIOS usually has >10)
                int bitsSet = 0;
                for (int i = 0; i < 64; ++i) bitsSet += (biosBits >> i) & 1;
                if (bitsSet < 10) detectionMask |= FLG_BIOS;

                break;
            }
            ptr += *(ptr + 1);
            while (ptr < end - 1 && (*ptr || *(ptr + 1))) ptr++;
            ptr += 2;
        }
    }

    // CPU checks
    int cpuInfo[4];

    // RDTSCP check
    __cpuid(cpuInfo, 0x80000001);
    if (!((cpuInfo[3] >> 27) & 1)) detectionMask |= FLG_CPU;

    // Measure TSC timing
    u64 t1 = __rdtsc();
    __cpuid(cpuInfo, 0);
    u64 t2 = __rdtsc();
    if ((t2 - t1) > 1200) detectionMask |= FLG_TIME;

    if (detectionMask) {
        std::cout << "VM detected. Detection mask: 0x" << std::hex << detectionMask << "\n";
        return 1;
    }

    std::cout << "System appears clean.\n";
    return 0;
}
