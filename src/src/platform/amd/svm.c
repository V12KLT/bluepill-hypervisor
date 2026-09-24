#include "svm.h"
#include "../../hv_comm.h"

#define EFER_VALID_MASK                                                        \
  0x000000000000FD01ULL

BOOLEAN SvmIsSupported(void) {
  int cpuInfo[4];

  __cpuid(cpuInfo, 0x80000001);
  if (!(cpuInfo[2] & (1 << 2))) {
    LOG_ERROR("SVM is not supported by CPUID.");
    return FALSE;
  }

  __cpuid(cpuInfo, 1);
  if (cpuInfo[2] & (1u << 31)) {
    int vendor[4];
    __cpuid(vendor, 0x40000000);
    LOG_ERROR("Existing hypervisor detected (CPUID HV-bit set).");
    LOG_ERROR("  Vendor leaf 0x40000000: '%c%c%c%c%c%c%c%c%c%c%c%c'",
              ((char *)&vendor[1])[0], ((char *)&vendor[1])[1],
              ((char *)&vendor[1])[2], ((char *)&vendor[1])[3],
              ((char *)&vendor[2])[0], ((char *)&vendor[2])[1],
              ((char *)&vendor[2])[2], ((char *)&vendor[2])[3],
              ((char *)&vendor[3])[0], ((char *)&vendor[3])[1],
              ((char *)&vendor[3])[2], ((char *)&vendor[3])[3]);

    if (vendor[1] == 0x7263694D && vendor[2] == 0x666F736F &&
        vendor[3] == 0x76482074) {
      LOG_ERROR("  -> Microsoft Hyper-V active. Disable VBS/HVCI/Hyper-V and "
                "reboot:");
      LOG_ERROR("     bcdedit /set hypervisorlaunchtype off");
      LOG_ERROR("     Settings -> Device Security -> Core Isolation -> Memory "
                "Integrity = OFF");
    }

    if (vendor[1] == 0x61774D56 && vendor[2] == 0x4D566572 &&
        vendor[3] == 0x65726177) {
      LOG_ERROR("  -> VMware root hypervisor in guest. We're nested under "
                "VMware (expected).");
    }
    return FALSE;
  }

  ULONG64 vmCr = __readmsr(MSR_VM_CR);
  if (vmCr & VM_CR_SVMDIS) {
    LOG_ERROR("SVM is locked disabled by BIOS (VM_CR.SVMDIS=1).");
    return FALSE;
  }

  ULONG64 hsavePa = __readmsr(MSR_VM_HSAVE_PA);
  if (hsavePa != 0) {
    LOG_ERROR("VM_HSAVE_PA already populated (0x%llx). Another HV owns SVM. "
              "Aborting.",
              hsavePa);
    return FALSE;
  }

  return TRUE;
}

BOOLEAN SvmEnablePhase3(void) {
  if (!SvmIsSupported()) {
    return FALSE;
  }

  ULONG64 efer = __readmsr(MSR_EFER);
  efer = (efer & EFER_VALID_MASK) | EFER_SVME;
  __writemsr(MSR_EFER, efer);

  __svm_stgi();

  ULONG coreNumber = KeGetCurrentProcessorNumber();
  PHYSICAL_ADDRESS hsaPhysical = g_Hv.perCpu[coreNumber].hostSaveAreaPhysical;

  __writemsr(MSR_VM_HSAVE_PA, hsaPhysical.QuadPart);

  return TRUE;
}

VOID SvmDisablePhase3(void) {

  ULONG64 efer = __readmsr(MSR_EFER);
  efer = (efer & EFER_VALID_MASK) & ~EFER_SVME;
  __writemsr(MSR_EFER, efer);
}

extern VOID SvmGuestContinuation(void);

static ULONG DecodeMovDrGprIndex(PVMCB vmcb) {
  UCHAR numBytes = vmcb->ControlArea.NumberOfBytesFetched;
  PUCHAR insn = vmcb->ControlArea.GuestInstructionBytes;

  if (numBytes < 3)
    return 0xFFFF;

  ULONG pos = 0;
  UCHAR rexB = 0;

  while (pos < numBytes) {
    UCHAR b = insn[pos];
    if (b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E ||
        b == 0x64 || b == 0x65 ||
        b == 0x66 || b == 0x67 ||
        b == 0xF0 || b == 0xF2 || b == 0xF3) {
      pos++;
    } else {
      break;
    }
  }

  if (pos < numBytes && (insn[pos] & 0xF0) == 0x40) {
    rexB = (insn[pos] & 0x01);
    pos++;
  }

  if (pos + 2 >= numBytes)
    return 0xFFFF;
  if (insn[pos] != 0x0F)
    return 0xFFFF;
  pos++;

  if (insn[pos] != 0x21 && insn[pos] != 0x23)
    return 0xFFFF;
  pos++;

  UCHAR modRM = insn[pos];
  ULONG gprIndex = (ULONG)(modRM & 0x07) | ((ULONG)rexB << 3);

  return gprIndex;
}

static ULONG64 ReadGuestGpr(PGUEST_CONTEXT ctx, PVMCB vmcb, ULONG idx) {
  switch (idx) {
  case 0:
    return vmcb->StateSaveArea.Rax;
  case 1:
    return ctx->Rcx;
  case 2:
    return ctx->Rdx;
  case 3:
    return ctx->Rbx;
  case 4:
    return vmcb->StateSaveArea.Rsp;
  case 5:
    return ctx->Rbp;
  case 6:
    return ctx->Rsi;
  case 7:
    return ctx->Rdi;
  case 8:
    return ctx->R8;
  case 9:
    return ctx->R9;
  case 10:
    return ctx->R10;
  case 11:
    return ctx->R11;
  case 12:
    return ctx->R12;
  case 13:
    return ctx->R13;
  case 14:
    return ctx->R14;
  case 15:
    return ctx->R15;
  default:
    return 0;
  }
}

static VOID WriteGuestGpr(PGUEST_CONTEXT ctx, PVMCB vmcb, ULONG idx,
                          ULONG64 val) {
  switch (idx) {
  case 0:
    vmcb->StateSaveArea.Rax = val;
    break;
  case 1:
    ctx->Rcx = val;
    break;
  case 2:
    ctx->Rdx = val;
    break;
  case 3:
    ctx->Rbx = val;
    break;
  case 4:
    vmcb->StateSaveArea.Rsp = val;
    break;
  case 5:
    ctx->Rbp = val;
    break;
  case 6:
    ctx->Rsi = val;
    break;
  case 7:
    ctx->Rdi = val;
    break;
  case 8:
    ctx->R8 = val;
    break;
  case 9:
    ctx->R9 = val;
    break;
  case 10:
    ctx->R10 = val;
    break;
  case 11:
    ctx->R11 = val;
    break;
  case 12:
    ctx->R12 = val;
    break;
  case 13:
    ctx->R13 = val;
    break;
  case 14:
    ctx->R14 = val;
    break;
  case 15:
    ctx->R15 = val;
    break;
  }
}

static __forceinline void HvProbeJitter(void) {
    ULONG64 count = __rdtsc() & 0x1FFULL;
    for (ULONG64 i = 0; i < count; i++) {
        _mm_pause();
    }
}

BOOLEAN SvmExitDispatcher(PGUEST_CONTEXT GuestContext, PVMCB VmcbVirtual);

VOID SvmSnapshotDispatcherHash(void) {
    const volatile UCHAR *code = (const volatile UCHAR *)&SvmExitDispatcher;
    g_Hv.expectedDispatcherHash = HvFnv1aCode(code, HV_DISPATCH_CHECK_BYTES);
    g_Hv.dispatcherIntegrityFailed = 0;
}

__forceinline static VOID SvmCheckDispatcherIntegrity(ULONG core) {

    static volatile ULONG s_dispatcherCheckCounter[256];
    if (core >= RTL_NUMBER_OF(s_dispatcherCheckCounter)) return;
    if ((++s_dispatcherCheckCounter[core] & 0x1FF) != 0) return;

    const volatile UCHAR *code = (const volatile UCHAR *)&SvmExitDispatcher;
    ULONG64 now = HvFnv1aCode(code, HV_DISPATCH_CHECK_BYTES);
    if (now != g_Hv.expectedDispatcherHash) {

        InterlockedExchange(&g_Hv.dispatcherIntegrityFailed, 1);
        InterlockedExchange(&g_Hv.killSwitch, 1);
    }
}

BOOLEAN SvmExitDispatcher(PGUEST_CONTEXT GuestContext, PVMCB VmcbVirtual) {

  ULONG core = KeGetCurrentProcessorNumber();

  SvmCheckDispatcherIntegrity(core);

  VmcbVirtual->ControlArea.VmcbClean =
      (1u << 1) | (1u << 2) | (1u << 6) | (1u << 7) |
      (1u << 8) | (1u << 10) | (1u << 11);
  VmcbVirtual->ControlArea.EventInj =
      0;

  {
    ULONG rawExitIntInfo = VmcbVirtual->ControlArea.ExitIntInfo;
    if (rawExitIntInfo & (1UL << 31)) {
      VmcbVirtual->ControlArea.EventInj =
          (ULONG64)rawExitIntInfo |
          ((ULONG64)VmcbVirtual->ControlArea.ExitIntInfoErr << 32);
    }
  }

  ULONG64 exitCode = VmcbVirtual->ControlArea.ExitCode;
  ULONG64 guestCr3 = VmcbVirtual->StateSaveArea.Cr3;

  if (InterlockedCompareExchange(&g_Hv.killSwitch, 1, 1) == 1) {
    if (g_Hv.perCpu[core].singleStepForNpt) {
        VmcbVirtual->StateSaveArea.Rflags &= ~0x100ULL;
        g_Hv.perCpu[core].singleStepForNpt = FALSE;
        g_Hv.perCpu[core].lastModifiedPte = NULL;
    }
    VmcbVirtual->StateSaveArea.Rip = VmcbVirtual->ControlArea.nRip;
    return FALSE;
  }

  {
    LONG refreshCounter =
        InterlockedIncrement(&g_Hv.perCpu[core].cr3RefreshCounter);
    BOOLEAN forceRefresh =
        ((refreshCounter & 0xFFFF) == 0);

    if (guestCr3 != g_Hv.perCpu[core].lastGuestCr3 || forceRefresh) {
      g_Hv.perCpu[core].lastGuestCr3 = guestCr3;
      HvRefreshHostCr3(guestCr3);
    }

    if (forceRefresh) {
      extern VOID HvGcStaleHostCr3Slots(ULONG64 guestCr3);
      HvGcStaleHostCr3Slots(guestCr3);
    }
  }

  if (InterlockedCompareExchange(&g_Hv.tlbFlushFlags[core], 0, 1) ==
      1) {
    VmcbVirtual->ControlArea.TlbControl = 1;
  } else {
    VmcbVirtual->ControlArea.TlbControl = 0;
  }

  if (g_Hv.perCpu[core].singleStepForNpt) {
    LONG age = InterlockedIncrement(&g_Hv.perCpu[core].singleStepAge);
    if (age > 256) {

      VmcbVirtual->StateSaveArea.Rflags &= ~0x100ULL;
      g_Hv.perCpu[core].singleStepForNpt = FALSE;

      PNPT_PTE pt = (PNPT_PTE)g_Hv.perCpu[core].lastModifiedPte;
      if (pt) {
        NPT_PTE snapshot;
        snapshot.AsUInt64 = pt->AsUInt64;
        ULONG64 realPfn = g_Hv.perCpu[core].savedRealPfn;

        if (snapshot.Fields.PageFrameNumber == realPfn) {

          ULONG decoyIndex = (ULONG)(realPfn % 4);
          NPT_PTE newEntry;
          newEntry.AsUInt64 = snapshot.AsUInt64;
          newEntry.Fields.PageFrameNumber =
              g_Hv.decoyPagesPhysical[decoyIndex].QuadPart >> 12;
          newEntry.Fields.NoExecute = 1;
          newEntry.Fields.ReadWrite = 1;
          pt->AsUInt64 = newEntry.AsUInt64;
        }

      }
      g_Hv.perCpu[core].lastModifiedPte = NULL;
      VmcbVirtual->ControlArea.TlbControl = 1;
    }
  }

  if (exitCode == 0x81) {
    ULONG64 rax = VmcbVirtual->StateSaveArea.Rax;

    if (rax == HV_VMMCALL_MAGIC && GuestContext->Rcx == HV_VMMCALL_DEVIRT) {
      VmcbVirtual->StateSaveArea.Rip = VmcbVirtual->ControlArea.nRip;
      return FALSE;
    }

    if (rax == g_Hv.bootstrapMagic || rax == g_Hv.commMagic) {
      ULONG64 command = GuestContext->Rcx;
      ULONG64 arg1 = GuestContext->Rdx;
      ULONG64 arg2 = GuestContext->R8;
      ULONG64 arg3 = GuestContext->R9;
      ULONG64 result;

      if (command == HV_CMD_PING) {

        result = g_Hv.commMagic;
      } else if (command == HV_CMD_MAP_ALLOW) {
        g_Hv.perCpu[core].mapperAllowed = TRUE;
        result = HV_STATUS_OK;
      } else if (command == HV_CMD_MAP_BLOCK) {
        g_Hv.perCpu[core].mapperAllowed = FALSE;
        result = HV_STATUS_OK;
      } else {

        result = HvCommDispatch(command, arg1, arg2, arg3, guestCr3);
      }

      VmcbVirtual->StateSaveArea.Rax = (ULONG64)(ULONG32)result;
      GuestContext->Rdx = (ULONG64)(ULONG32)(result >> 32);
      GuestContext->Rbx = 0;
      GuestContext->Rcx = 0;

      VmcbVirtual->StateSaveArea.Rip = VmcbVirtual->ControlArea.nRip;
      return TRUE;
    }

    VmcbVirtual->ControlArea.EventInj = 0x80000306ULL;
    HvProbeJitter();
    return TRUE;
  }

  if (exitCode == VMEXIT_CPUID) {
    int cpuInfo[4];
    ULONG32 leaf = (ULONG32)VmcbVirtual->StateSaveArea.Rax;
    ULONG32 subleaf = (ULONG32)GuestContext->Rcx;

    if (leaf == 0x40000000) {
      cpuInfo[0] = g_Hv.cachedCpuid40000000[0];
      cpuInfo[1] = g_Hv.cachedCpuid40000000[1];
      cpuInfo[2] = g_Hv.cachedCpuid40000000[2];
      cpuInfo[3] = g_Hv.cachedCpuid40000000[3];
    } else if (leaf >= 0x40000001 && leaf <= 0x4000000F) {
      cpuInfo[0] = cpuInfo[1] = cpuInfo[2] = cpuInfo[3] = 0;
    } else {
      __cpuidex(cpuInfo, leaf, subleaf);
      if (leaf == 1) {
        cpuInfo[2] &= ~(1u << 31);

        cpuInfo[0] = (int)(((ULONG)cpuInfo[0] & ~0xFu) |
                           (g_Hv.cpuidSteppingRotation & 0xF));
      }

      else if (leaf == 0x8000000A) {
        cpuInfo[0] = cpuInfo[1] = cpuInfo[2] = cpuInfo[3] = 0;
      }

      else if (leaf == 0x80000008) {
        cpuInfo[2] &= ~0x0000FF00u;
      }

      else if (leaf == 0x80000004) {
        ULONG edx = (ULONG)cpuInfo[3];
        edx = (edx & 0x00FFFFFFu) |
              ((ULONG)g_Hv.cpuidBrandRotation << 24);
        cpuInfo[3] = (int)edx;
      }
    }

    VmcbVirtual->StateSaveArea.Rax = (ULONG64)(ULONG32)cpuInfo[0];
    GuestContext->Rbx = (ULONG64)(ULONG32)cpuInfo[1];
    GuestContext->Rcx = (ULONG64)(ULONG32)cpuInfo[2];
    GuestContext->Rdx = (ULONG64)(ULONG32)cpuInfo[3];

    VmcbVirtual->StateSaveArea.Rip = VmcbVirtual->ControlArea.nRip;
    HvProbeJitter();
    return TRUE;
  }

  if (exitCode == VMEXIT_VMRUN) {
    if ((g_Hv.perCpu[core].guestEfer & EFER_SVME) == 0) {
      VmcbVirtual->ControlArea.EventInj =
          0x80000306ULL;
    } else {
      VmcbVirtual->ControlArea.EventInj =
          0x80000B0DULL;
    }
    HvProbeJitter();
    return TRUE;
  }

  if (exitCode == VMEXIT_VMLOAD || exitCode == VMEXIT_VMSAVE ||
      exitCode == VMEXIT_STGI || exitCode == VMEXIT_CLGI ||
      exitCode == VMEXIT_SKINIT) {
    if ((g_Hv.perCpu[core].guestEfer & EFER_SVME) == 0) {

      VmcbVirtual->ControlArea.EventInj = 0x80000306ULL;
      HvProbeJitter();
      return TRUE;
    }

    VmcbVirtual->StateSaveArea.Rip = VmcbVirtual->ControlArea.nRip;
    HvProbeJitter();
    return TRUE;
  }

  if (exitCode == VMEXIT_INVLPGA) {
    UCHAR cpl = VmcbVirtual->StateSaveArea.Cpl;
    ULONG64 rip = VmcbVirtual->StateSaveArea.Rip;

    BOOLEAN isKernelRange = (rip >= 0xFFFF800000000000ULL);

    if (cpl == 3 || !isKernelRange) {
      if ((g_Hv.perCpu[core].guestEfer & EFER_SVME) == 0) {
        VmcbVirtual->ControlArea.EventInj = 0x80000306ULL;
      } else {
        VmcbVirtual->ControlArea.EventInj =
            0x80000B0DULL;
      }
      HvProbeJitter();
      return TRUE;
    }

    {
      PVOID guestVa = (PVOID)VmcbVirtual->StateSaveArea.Rax;
      ULONG hwAsid = VmcbVirtual->ControlArea.GuestAsid;
      __svm_invlpga(guestVa, hwAsid);
    }
    VmcbVirtual->StateSaveArea.Rip = VmcbVirtual->ControlArea.nRip;
    return TRUE;
  }

  if (exitCode == VMEXIT_MSR) {
    ULONG32 msrIndex = (ULONG32)GuestContext->Rcx;
    ULONG64 isWrite = VmcbVirtual->ControlArea.ExitInfo1;

    if (msrIndex == MSR_EFER) {
      if (isWrite == 0) {

        ULONG64 currentEfer = VmcbVirtual->StateSaveArea.Efer;
        currentEfer &= ~EFER_SVME;
        VmcbVirtual->StateSaveArea.Rax = (ULONG64)(ULONG32)currentEfer;
        GuestContext->Rdx = (ULONG64)(ULONG32)(currentEfer >> 32);
      } else {

        ULONG64 value = (((ULONG64)(ULONG32)GuestContext->Rdx) << 32) |
                        (ULONG64)(ULONG32)VmcbVirtual->StateSaveArea.Rax;

        g_Hv.perCpu[core].guestEfer = value;

        if (value & ~EFER_VALID_MASK) {

          VmcbVirtual->ControlArea.EventInj = 0x80000B0DULL;
          HvProbeJitter();
          return TRUE;
        }

        value |= EFER_SVME;

        __writemsr(MSR_EFER, value);
        VmcbVirtual->StateSaveArea.Efer = __readmsr(MSR_EFER);
      }
    }

    else if (msrIndex == MSR_VM_HSAVE_PA) {
      if (isWrite == 0) {

        VmcbVirtual->StateSaveArea.Rax = 0;
        GuestContext->Rdx = 0;
      }

    }

    else if (msrIndex == MSR_VM_CR) {
      if (isWrite == 0) {

        ULONG64 realVmCr = __readmsr(MSR_VM_CR);
        realVmCr |= VM_CR_SVMDIS;
        VmcbVirtual->StateSaveArea.Rax = (ULONG64)(ULONG32)realVmCr;
        GuestContext->Rdx = (ULONG64)(ULONG32)(realVmCr >> 32);
      }

    }

    else if (msrIndex >= 0xC0002000UL && msrIndex <= 0xC00023FFUL) {
      ULONG bankIdx = (ULONG)((msrIndex - 0xC0002000UL) / 0x10UL);
      if (g_Hv.mcBankCount != 0 && bankIdx < g_Hv.mcBankCount) {

        if (isWrite == 0) {
          ULONG64 value = __readmsr(msrIndex);
          VmcbVirtual->StateSaveArea.Rax = (ULONG64)(ULONG32)value;
          GuestContext->Rdx = (ULONG64)(ULONG32)(value >> 32);
        } else {
          ULONG64 value = (((ULONG64)(ULONG32)GuestContext->Rdx) << 32) |
                          (ULONG64)(ULONG32)VmcbVirtual->StateSaveArea.Rax;
          __writemsr(msrIndex, value);
        }
      } else if (g_Hv.mcBankCount != 0) {

        VmcbVirtual->ControlArea.EventInj = 0x80000B0DULL;
        HvProbeJitter();
        return TRUE;
      } else {

        if (isWrite == 0) {
          VmcbVirtual->StateSaveArea.Rax = 0;
          GuestContext->Rdx = 0;
        }
      }
    } else {

      VmcbVirtual->ControlArea.EventInj = 0x80000B0DULL;
      HvProbeJitter();
      return TRUE;
    }

    VmcbVirtual->StateSaveArea.Rip = VmcbVirtual->ControlArea.nRip;
    HvProbeJitter();
    return TRUE;
  }

  if (exitCode == VMEXIT_NMI) {
    VmcbVirtual->ControlArea.EventInj = 0x80000202ULL;
    HvProbeJitter();
    return TRUE;
  }

  if (exitCode == VMEXIT_EXCEPTION_DB) {
    if (g_Hv.perCpu[core].singleStepForNpt) {
      g_Hv.perCpu[core].singleStepForNpt = FALSE;

      VmcbVirtual->StateSaveArea.Rflags &= ~0x100ULL;

      PNPT_PTE pt = (PNPT_PTE)g_Hv.perCpu[core].lastModifiedPte;
      if (pt) {
        ULONG64 realPfn = g_Hv.perCpu[core].savedRealPfn;

        if (pt->Fields.PageFrameNumber == realPfn) {
          ULONG decoyIndex = (ULONG)(realPfn % 4);
          pt->Fields.PageFrameNumber = g_Hv.decoyPagesPhysical[decoyIndex].QuadPart >> 12;
          pt->Fields.NoExecute = 1;
          pt->Fields.ReadWrite = 1;
        }
      }
      g_Hv.perCpu[core].lastModifiedPte = NULL;

      VmcbVirtual->ControlArea.TlbControl = 1;
      return TRUE;
    }

    VmcbVirtual->ControlArea.EventInj = 0x80000301ULL;
    HvProbeJitter();
    return TRUE;
  }

  if (exitCode == VMEXIT_SHUTDOWN) {

    LOG_ERROR("=== VMEXIT_SHUTDOWN (triple fault) on core %u ===", core);
    LOG_ERROR("  RIP=0x%llx  RSP=0x%llx  RFLAGS=0x%llx  CR3=0x%llx",
              VmcbVirtual->StateSaveArea.Rip, VmcbVirtual->StateSaveArea.Rsp,
              VmcbVirtual->StateSaveArea.Rflags,
              VmcbVirtual->StateSaveArea.Cr3);
    InterlockedExchange(&g_Hv.killSwitch, 1);
    return FALSE;
  }

  if (exitCode == 0xFFFFFFFFFFFFFFFF) {

    LOG_ERROR("=== VMEXIT_INVALID on core %u ===", core);
    LOG_ERROR("  ExitInfo1=0x%llx  ExitInfo2=0x%llx",
              VmcbVirtual->ControlArea.ExitInfo1,
              VmcbVirtual->ControlArea.ExitInfo2);
    LOG_ERROR("  Guest RIP=0x%llx  RSP=0x%llx  RFLAGS=0x%llx",
              VmcbVirtual->StateSaveArea.Rip, VmcbVirtual->StateSaveArea.Rsp,
              VmcbVirtual->StateSaveArea.Rflags);
    LOG_ERROR("  Guest CR0=0x%llx  CR3=0x%llx  CR4=0x%llx  EFER=0x%llx",
              VmcbVirtual->StateSaveArea.Cr0, VmcbVirtual->StateSaveArea.Cr3,
              VmcbVirtual->StateSaveArea.Cr4, VmcbVirtual->StateSaveArea.Efer);
    LOG_ERROR("  Guest DR6=0x%llx  DR7=0x%llx  GPat=0x%llx  CPL=%u",
              VmcbVirtual->StateSaveArea.Dr6, VmcbVirtual->StateSaveArea.Dr7,
              VmcbVirtual->StateSaveArea.GPat,
              (ULONG)VmcbVirtual->StateSaveArea.Cpl);
    LOG_ERROR("  CS  sel=0x%04x attr=0x%04x base=0x%llx limit=0x%x",
              VmcbVirtual->StateSaveArea.Cs.Selector,
              VmcbVirtual->StateSaveArea.Cs.Attributes.AsUInt16,
              VmcbVirtual->StateSaveArea.Cs.Base,
              VmcbVirtual->StateSaveArea.Cs.Limit);
    LOG_ERROR("  SS  sel=0x%04x attr=0x%04x",
              VmcbVirtual->StateSaveArea.Ss.Selector,
              VmcbVirtual->StateSaveArea.Ss.Attributes.AsUInt16);
    LOG_ERROR("  TR  sel=0x%04x attr=0x%04x base=0x%llx",
              VmcbVirtual->StateSaveArea.Tr.Selector,
              VmcbVirtual->StateSaveArea.Tr.Attributes.AsUInt16,
              VmcbVirtual->StateSaveArea.Tr.Base);
    LOG_ERROR("  GDTR base=0x%llx limit=0x%x  IDTR base=0x%llx limit=0x%x",
              VmcbVirtual->StateSaveArea.Gdtr.Base,
              VmcbVirtual->StateSaveArea.Gdtr.Limit,
              VmcbVirtual->StateSaveArea.Idtr.Base,
              VmcbVirtual->StateSaveArea.Idtr.Limit);
    LOG_ERROR(
        "  ASID=%u NCr3=0x%llx NestedCtl=0x%llx TlbCtl=%u InterceptMisc2=0x%x",
        VmcbVirtual->ControlArea.GuestAsid, VmcbVirtual->ControlArea.NCr3,
        VmcbVirtual->ControlArea.NestedCtl,
        (ULONG)VmcbVirtual->ControlArea.TlbControl,
        VmcbVirtual->ControlArea.InterceptMisc2);
    LOG_ERROR("  IOPM=0x%llx MSRPM=0x%llx", VmcbVirtual->ControlArea.IopmBasePa,
              VmcbVirtual->ControlArea.MsrpmBasePa);
    InterlockedExchange(&g_Hv.killSwitch, 1);
    return FALSE;
  }

  if (exitCode == VMEXIT_NPF) {
    ULONG64 faultingGpa = VmcbVirtual->ControlArea.ExitInfo2;
    ULONG64 npfInfo = VmcbVirtual->ControlArea.ExitInfo1;

    if (faultingGpa == g_Hv.perCpu[core].lastNpfGpa) {
      if (++g_Hv.perCpu[core].npfStreakCount > NPF_STORM_THRESHOLD) {

        extern BOOLEAN NptForceRestoreIdentity(ULONG64 gpa);
        if (NptForceRestoreIdentity(faultingGpa)) {
          g_Hv.perCpu[core].npfStreakCount = 0;
          VmcbVirtual->ControlArea.TlbControl = 1;
          return TRUE;
        }

      }
    } else {
      g_Hv.perCpu[core].lastNpfGpa = faultingGpa;
      g_Hv.perCpu[core].npfStreakCount = 1;
    }

    if (!NptHandleNestedPageFault(npfInfo, faultingGpa)) {

      LOG_ERROR("FATAL NPF: GPA=0x%llx, Info=0x%llx, RIP=0x%llx", faultingGpa,
                npfInfo, VmcbVirtual->StateSaveArea.Rip);
      InterlockedExchange(&g_Hv.killSwitch, 1);
      VmcbVirtual->ControlArea.NestedCtl = 0;
      VmcbVirtual->ControlArea.TlbControl = 1;
    }
    return TRUE;
  }

  LOG_ERROR("=== Unhandled VMEXIT on core %u ===", core);
  LOG_ERROR("  ExitCode=0x%llx  ExitInfo1=0x%llx  ExitInfo2=0x%llx", exitCode,
            VmcbVirtual->ControlArea.ExitInfo1,
            VmcbVirtual->ControlArea.ExitInfo2);
  LOG_ERROR("  Guest RIP=0x%llx  RSP=0x%llx  CR3=0x%llx",
            VmcbVirtual->StateSaveArea.Rip, VmcbVirtual->StateSaveArea.Rsp,
            VmcbVirtual->StateSaveArea.Cr3);
  InterlockedExchange(&g_Hv.killSwitch, 1);
  return FALSE;
}

VOID SvmDevirtualizeCore(void) {

  AsmVmmcallDevirtualize();

}

BOOLEAN SvmSubvertCore(void) {
  ULONG coreNumber = KeGetCurrentProcessorNumber();
  PVMCB vmcb = (PVMCB)g_Hv.perCpu[coreNumber].guestVmcb;

  if (g_Hv.xsaveAreaSize == 0) {
    int cpuInfo[4];
    __cpuidex(cpuInfo, 0xD, 0);
    g_Hv.xsaveAreaSize =
        (ULONG)cpuInfo[1];
    if (g_Hv.xsaveAreaSize < 512)
      g_Hv.xsaveAreaSize = 512;
  }

  RtlSecureZeroMemory(vmcb, 4096);

  vmcb->ControlArea.InterceptDr = 0;

  vmcb->ControlArea.InterceptException = (1 << 1);

  vmcb->ControlArea.InterceptMisc1 =
      (1u << 18) | (1 << 26) | (1 << 28) | (1u << 31);

  vmcb->ControlArea.InterceptMisc2 =
      0x7F;

  vmcb->ControlArea.GuestAsid = 1;

  vmcb->ControlArea.TlbControl = 1;

  vmcb->ControlArea.NestedCtl = 1;

  vmcb->ControlArea.NCr3 = g_Hv.nptPml4Physical.QuadPart;

  vmcb->ControlArea.IopmBasePa = g_Hv.iopmBitmapPhysical.QuadPart;
  vmcb->ControlArea.MsrpmBasePa = g_Hv.msrBitmapPhysical.QuadPart;

  __svm_vmsave(g_Hv.perCpu[coreNumber].hostVmcbPhysical.QuadPart);

  __svm_vmsave(g_Hv.perCpu[coreNumber].guestVmcbPhysical.QuadPart);

  vmcb->StateSaveArea.Cs.Selector = 0x10;
  vmcb->StateSaveArea.Cs.Attributes.AsUInt16 =
      0x029B;
  vmcb->StateSaveArea.Cs.Limit = 0xFFFFFFFF;
  vmcb->StateSaveArea.Cs.Base = 0;

  vmcb->StateSaveArea.Ds.Selector = 0x18;
  vmcb->StateSaveArea.Ds.Attributes.AsUInt16 =
      0x0C93;
  vmcb->StateSaveArea.Ds.Limit = 0xFFFFFFFF;
  vmcb->StateSaveArea.Ds.Base = 0;

  vmcb->StateSaveArea.Es.Selector = 0x18;
  vmcb->StateSaveArea.Es.Attributes.AsUInt16 = 0x0C93;
  vmcb->StateSaveArea.Es.Limit = 0xFFFFFFFF;
  vmcb->StateSaveArea.Es.Base = 0;

  vmcb->StateSaveArea.Ss.Selector = 0x18;
  vmcb->StateSaveArea.Ss.Attributes.AsUInt16 = 0x0C93;
  vmcb->StateSaveArea.Ss.Limit = 0xFFFFFFFF;
  vmcb->StateSaveArea.Ss.Base = 0;

  vmcb->StateSaveArea.Gdtr.Base = AsmGetGdtBase();
  vmcb->StateSaveArea.Gdtr.Limit = AsmGetGdtLimit();
  vmcb->StateSaveArea.Idtr.Base = AsmGetIdtBase();
  vmcb->StateSaveArea.Idtr.Limit = AsmGetIdtLimit();

  vmcb->StateSaveArea.Cr0 = __readcr0();
  vmcb->StateSaveArea.Cr2 = __readcr2();
  vmcb->StateSaveArea.Cr3 = __readcr3();

  vmcb->StateSaveArea.Cr4 = __readcr4();

  vmcb->StateSaveArea.Cpl = 0;

  vmcb->StateSaveArea.Star = __readmsr(0xC0000081);
  vmcb->StateSaveArea.Lstar = __readmsr(0xC0000082);
  vmcb->StateSaveArea.Cstar = __readmsr(0xC0000083);
  vmcb->StateSaveArea.Sfmask = __readmsr(0xC0000084);
  vmcb->StateSaveArea.KernelGsBase = __readmsr(0xC0000102);

  vmcb->StateSaveArea.Dr6 = __readdr(6);
  vmcb->StateSaveArea.Dr7 = __readdr(7);

  g_Hv.perCpu[coreNumber].guestDr0 = __readdr(0);
  g_Hv.perCpu[coreNumber].guestDr1 = __readdr(1);
  g_Hv.perCpu[coreNumber].guestDr2 = __readdr(2);
  g_Hv.perCpu[coreNumber].guestDr3 = __readdr(3);
  g_Hv.perCpu[coreNumber].guestDr6 = __readdr(6);
  g_Hv.perCpu[coreNumber].guestDr7 = __readdr(7);

  g_Hv.perCpu[coreNumber].guestApicBase = __readmsr(MSR_IA32_APIC_BASE);

  vmcb->StateSaveArea.GPat = __readmsr(0x277);

  ULONG64 currentEfer = __readmsr(MSR_EFER);

  currentEfer |= EFER_SVME | (1ULL << 10);

  currentEfer &= 0x000000000000FD01ULL;
  vmcb->StateSaveArea.Efer = currentEfer;

  g_Hv.perCpu[coreNumber].guestEfer = currentEfer & ~EFER_SVME;

  extern VOID SvmGuestContinuation(void);
  vmcb->StateSaveArea.Rip = (ULONG64)SvmGuestContinuation;

  ULONG64 physical = g_Hv.perCpu[coreNumber].guestVmcbPhysical.QuadPart;

  extern VOID SvmSubvertCoreHostEntry(
      ULONG64 VmcbPhysical, PULONG64 pGuestRsp, PULONG64 pGuestRflags,
      PVOID HypervisorStackBase, PVMCB VmcbVirtual, ULONG64 HostVmcbPhysical,
      ULONG64 HostCr3);
  SvmSubvertCoreHostEntry(physical, &vmcb->StateSaveArea.Rsp,
                          &vmcb->StateSaveArea.Rflags,
                          g_Hv.perCpu[coreNumber].hypervisorStack, vmcb,
                          g_Hv.perCpu[coreNumber].hostVmcbPhysical.QuadPart,
                          g_Hv.hostCr3Physical.QuadPart);

  InterlockedExchange(&g_Hv.perCpu[coreNumber].virtualizationActive, 1);

  return TRUE;
}
