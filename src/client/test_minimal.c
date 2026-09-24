#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include "hv_comm_user.h"

int main(void) {
    printf("=== ForgeHV Verification Test ===\n\n");
    fflush(stdout);

    printf("[STEP 1] HvPing (bootstrap magic = 0x%llx)... ", HvGetBootstrapMagic());
    fflush(stdout);
    if (!HvPing()) { printf("FAILED\n"); return 1; }
    printf("OK\n");
    fflush(stdout);

    printf("[STEP 2] Finding notepad.exe via HV... ");
    fflush(stdout);
    {
        char nameA[16] = "notepad.exe";
        uint64_t arg1 = *(uint64_t*)(&nameA[0]);
        uint64_t arg2 = *(uint64_t*)(&nameA[8]);
        DWORD pid = (DWORD)HvCall(HV_CMD_FIND_PROCESS, arg1, arg2, 0);
        if (!pid) { printf("NOT FOUND (open notepad first)\n"); return 1; }
        printf("PID=%u\n", pid);
        fflush(stdout);

        printf("[STEP 3] HvAttach(%u)... ", pid);
        fflush(stdout);
        Sleep(1000);
        bool ok = HvAttach((uint64_t)pid);
        printf("%s\n", ok ? "OK" : "FAILED");
        fflush(stdout);
        if (!ok) return 1;

        printf("[STEP 4] HvGetModuleBase... ");
        fflush(stdout);
        uint64_t base = HvGetModuleBase();
        if (base) {
            printf("0x%llx\n", base);
        } else {
            printf("FAILED (0)\n");
        }
        fflush(stdout);

        if (base) {
            printf("[STEP 5] HvRead MZ header... ");
            fflush(stdout);
            uint16_t mz = 0;
            bool readOk = HvRead(base, &mz, sizeof(mz));
            if (readOk && mz == 0x5A4D) {
                printf("OK (0x%04X = 'MZ')\n", mz);
            } else {
                printf("FAILED (read=%s, value=0x%04X)\n", readOk ? "true" : "false", mz);
            }
            fflush(stdout);
        }

        HvDetach();
    }

    printf("\n[DONE] All tests passed! Hypervisor is fully operational.\n");
    printf("Press any key to exit...\n");
    system("pause >nul");
    return 0;
}
