#ifndef HV_COMM_USER_H
#define HV_COMM_USER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef _MSC_VER
#include <intrin.h>
#endif

#define HV_MAGIC_SEED         0x46475248ULL
#define HV_MAGIC_MIX(bootId)  (HV_MAGIC_SEED ^ ((uint64_t)(bootId) * 0x5DEECE66DULL + 0xBULL))

#define HV_CMD_PING          0x01
#define HV_CMD_ATTACH        0x10
#define HV_CMD_READ          0x11
#define HV_CMD_WRITE         0x12
#define HV_CMD_GET_BASE      0x13
#define HV_CMD_DETACH        0x14
#define HV_CMD_FIND_PROCESS  0x17
#define HV_CMD_DIAG          0x20

#define HV_STATUS_OK         0x00000001
#define HV_STATUS_FAIL       0x00000000
#define HV_STATUS_NO_TARGET  0x00000002
#define HV_STATUS_BAD_VA     0x00000003

extern uint64_t HvVmmcall(uint64_t magic, uint64_t command,
                           uint64_t arg1, uint64_t arg2, uint64_t arg3);

static uint64_t g_HvBootstrapMagic = 0;
static uint64_t g_HvCommMagic = 0;

static inline uint64_t HvGetBootstrapMagic(void) {
    if (g_HvBootstrapMagic == 0) {

        uint32_t bootId = *(volatile uint32_t*)(0x7FFE02C4);
        g_HvBootstrapMagic = HV_MAGIC_MIX(bootId);

        if (g_HvBootstrapMagic == 0 || g_HvBootstrapMagic == 0x464F5247ULL)
            g_HvBootstrapMagic ^= 0xDEADCAFEULL;
    }
    return g_HvBootstrapMagic;
}

static inline uint64_t HvGetMagic(void) {
    return g_HvCommMagic ? g_HvCommMagic : HvGetBootstrapMagic();
}

static inline uint64_t HvCall(uint64_t command, uint64_t arg1,
                               uint64_t arg2, uint64_t arg3) {
    return HvVmmcall(HvGetMagic(), command, arg1, arg2, arg3);
}

static inline bool HvPing(void) {
    uint64_t result = HvVmmcall(HvGetBootstrapMagic(), HV_CMD_PING, 0, 0, 0);
    if (result != 0 && result != HV_STATUS_FAIL) {

        if (result != HV_STATUS_OK) {
            g_HvCommMagic = result;
        }
        return true;
    }
    return false;
}

static inline bool HvAttach(uint64_t pid) {
    return HvCall(HV_CMD_ATTACH, pid, 0, 0) == HV_STATUS_OK;
}

static inline bool HvDetach(void) {
    return HvCall(HV_CMD_DETACH, 0, 0, 0) == HV_STATUS_OK;
}

static inline bool HvRead(uint64_t targetVa, void* buffer, uint64_t size) {
    return HvCall(HV_CMD_READ, targetVa, (uint64_t)buffer, size) == HV_STATUS_OK;
}

static inline bool HvWrite(uint64_t targetVa, const void* buffer, uint64_t size) {
    return HvCall(HV_CMD_WRITE, targetVa, (uint64_t)buffer, size) == HV_STATUS_OK;
}

static inline uint64_t HvGetModuleBase(void) {
    uint64_t result = HvCall(HV_CMD_GET_BASE, 0, 0, 0);
    if (result == HV_STATUS_FAIL || result == HV_STATUS_NO_TARGET)
        return 0;
    return result;
}

#ifdef __cplusplus
template<typename T>
inline T HvReadValue(uint64_t address) {
    T value{};
    HvRead(address, &value, sizeof(T));
    return value;
}

template<typename T>
inline bool HvWriteValue(uint64_t address, const T& value) {
    return HvWrite(address, &value, sizeof(T));
}
#endif

#endif
