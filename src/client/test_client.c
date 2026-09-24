#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include "hv_comm_user.h"

static DWORD FindProcess(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("  ForgeHV Communication Test Client\n");
    printf("========================================\n\n");

    printf("[TEST 1] Pinging hypervisor... ");
    if (HvPing()) {
        printf("SUCCESS - ForgeHV is running!\n");
    } else {
        printf("FAILED - ForgeHV not detected.\n");
        printf("  Make sure the driver is loaded (sc start ForgeHV)\n");
        printf("\nPress any key to exit...\n");
        system("pause >nul");
        return 1;
    }

    const char* targetName = (argc > 1) ? argv[1] : "notepad.exe";
    printf("\n[TEST 2] Looking for '%s'... ", targetName);

    DWORD pid = FindProcess(targetName);
    if (!pid) {
        printf("NOT FOUND.\n");
        printf("  Please open %s first, or pass a process name:\n", targetName);
        printf("  test_client.exe notepad.exe\n");
        printf("\nPress any key to exit...\n");
        system("pause >nul");
        return 1;
    }
    printf("Found PID %u\n", pid);

    printf("  Attaching via HV... ");
    if (HvAttach((uint64_t)pid)) {
        printf("SUCCESS - Attached to PID %u\n", pid);
    } else {
        printf("FAILED - Could not find CR3 for PID %u\n", pid);
        printf("  (EPROCESS offsets may need updating for your Windows build)\n");
        printf("\nPress any key to exit...\n");
        system("pause >nul");
        return 1;
    }

    printf("\n[TEST 3] Getting module base... ");
    uint64_t base = HvGetModuleBase();
    if (base && base > 0x10000) {
        printf("SUCCESS - Base address: 0x%llX\n", (unsigned long long)base);
    } else if (base >= 0xE1 && base <= 0xEF) {

        const char* diag[] = {
            "EPROCESS not found",
            "PEB is NULL (bad offset?)",
            "PEB page not mapped in CR3",
            "Ldr PA read failed",
            "Ldr is NULL",
            "Ldr.InLoadOrder VA xlat fail",
            "First entry PA read failed",
            "First entry is NULL",
            "DllBase VA xlat failed",
            "DllBase PA read failed",
            "PEB base OK but Ldr page unmapped",
        };
        unsigned idx = (unsigned)(base - 0xE1);
        printf("FAILED - Diag 0x%llX: %s\n", (unsigned long long)base,
               idx < 11 ? diag[idx] : "unknown");
    } else {
        printf("FAILED (returned 0x%llX)\n", (unsigned long long)base);
    }

    if (base && base > 0x10000) {
        printf("\n[TEST 4] Reading PE header (first 2 bytes)... ");

        unsigned char mzHeader[2] = {0};
        if (HvRead(base, mzHeader, 2)) {
            if (mzHeader[0] == 'M' && mzHeader[1] == 'Z') {
                printf("SUCCESS - Read 'MZ' (0x%02X 0x%02X) - PE header confirmed!\n",
                       mzHeader[0], mzHeader[1]);
            } else {
                printf("Read succeeded but got 0x%02X 0x%02X (expected 'MZ')\n",
                       mzHeader[0], mzHeader[1]);
            }
        } else {
            printf("FAILED - HvRead returned false\n");
        }

        printf("\n[TEST 5] Reading first 64 bytes of PE header:\n  ");
        unsigned char header[64] = {0};
        if (HvRead(base, header, 64)) {
            for (int i = 0; i < 64; i++) {
                printf("%02X ", header[i]);
                if ((i + 1) % 16 == 0) printf("\n  ");
            }
            printf("\n");
        } else {
            printf("  FAILED\n");
        }
    }

    printf("[TEST 6] Detaching... ");
    if (HvDetach()) {
        printf("SUCCESS\n");
    } else {
        printf("FAILED\n");
    }

    printf("\n========================================\n");
    printf("  All tests complete!\n");
    printf("========================================\n");

    printf("\nPress any key to exit...\n");
    system("pause >nul");
    return 0;
}
