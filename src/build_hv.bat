@echo off
setlocal enabledelayedexpansion

echo ================================================
echo    ElevationHV - Ring -1 Hypervisor Build
echo ================================================
echo.

:: ---------------------------------------------------------------
:: Find Visual Studio
:: ---------------------------------------------------------------
set "VCVARS="
for %%V in (18 17) do (
    for %%E in (Community Professional Enterprise) do (
        if exist "C:\Program Files\Microsoft Visual Studio\%%V\%%E\VC\Auxiliary\Build\vcvarsall.bat" (
            set "VCVARS=C:\Program Files\Microsoft Visual Studio\%%V\%%E\VC\Auxiliary\Build\vcvarsall.bat"
            goto :found_vs
        )
    )
)

:found_vs
if "!VCVARS!"=="" (
    echo [ERROR] Visual Studio not found
    exit /b 1
)
echo [+] Found Visual Studio
call "!VCVARS!" x64 >nul 2>&1

:: ---------------------------------------------------------------
:: WDK paths (hardcoded to detected version)
:: ---------------------------------------------------------------
set "WDK_VER=10.0.26100.0"
set "WDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\!WDK_VER!"
set "WDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\!WDK_VER!"

if not exist "!WDK_INC!\km\ntddk.h" (
    echo [ERROR] WDK headers not found at !WDK_INC!\km\
    exit /b 1
)
echo [+] WDK Version: !WDK_VER!

:: ---------------------------------------------------------------
:: Compile
:: ---------------------------------------------------------------
echo.
echo [*] Compiling ElevationHV kernel driver...
echo.

if not exist build mkdir build

echo [~] Assembling MASM files...
ml64.exe /nologo /c /Cx /Zi /Fo"build\svm_asm.obj" src\platform\amd\svm_asm.asm
if %ERRORLEVEL% neq 0 (
    echo [ERROR] MASM Assembly failed!
    exit /b 1
)

echo.
echo [~] Compiling C source...
cl.exe /nologo /W3 /WX- /O2 /Oi ^
    /D "_KERNEL_MODE" /D "_AMD64_" /D "NTDDI_VERSION=0x0A000000" /D "_WIN64" ^
    /D "WINVER=0x0A00" /D "WINNT=1" /D "NDEBUG" ^
    /GS- /Gy /Zp8 /Gz /TC /kernel ^
    /I"!WDK_INC!\km" /I"!WDK_INC!\shared" /I"!WDK_INC!\km\crt" ^
    /I"src" ^
    src\driver_entry.c ^
    src\hv_platform.c ^
    src\hv_comm.c ^
    src\platform\amd\svm.c ^
    src\platform\amd\npt.c ^
    src\platform\amd\iommu.c ^
    src\platform\intel\vmx.c ^
    /link ^
    build\svm_asm.obj ^
    /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry ^
    /LIBPATH:"!WDK_LIB!\km\x64" ^
    ntoskrnl.lib hal.lib wdmsec.lib BufferOverflowK.lib ^
    /OUT:"build\ElevationHV.sys" ^
    /RELEASE /MERGE:.rdata=.text /INTEGRITYCHECK

if !ERRORLEVEL! equ 0 (
    echo To test Phase 1:
    echo   1. Enable test signing:  bcdedit /set testsigning on
    echo   2. Reboot
    echo   3. Copy ElevationHV.sys to the VM
    echo   4. sc create ElevationHV type=kernel binPath=C:\path\to\ElevationHV.sys
    echo   5. sc start ElevationHV
    echo   6. Check output with DebugView
    echo   7. sc stop ElevationHV
    echo   8. sc delete ElevationHV
) else (
    echo.
    echo [FAILED] Build failed
)

echo.
