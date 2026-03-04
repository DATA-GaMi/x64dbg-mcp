@echo off
setlocal

set BUILD_X64=1
set BUILD_X86=1
set CLEAN_BUILD=0
set BUILD_CONFIG=Release
set BUILD_FAILED=0

echo ========================================
echo x64dbg MCP Server - Build Script
echo ========================================
echo.

:parse_args
if "%~1"=="" goto :args_done

if /I "%~1"=="--clean" (
    set CLEAN_BUILD=1
) else if /I "%~1"=="--x64-only" (
    set BUILD_X64=1
    set BUILD_X86=0
) else if /I "%~1"=="--x86-only" (
    set BUILD_X64=0
    set BUILD_X86=1
) else if /I "%~1"=="--debug" (
    set BUILD_CONFIG=Debug
) else if /I "%~1"=="--release" (
    set BUILD_CONFIG=Release
) else (
    echo [ERROR] Unknown option: %~1
    echo Usage: build.bat [--clean] [--x64-only ^| --x86-only] [--debug ^| --release]
    exit /b 1
)

shift
goto :parse_args

:args_done
if "%BUILD_X64%%BUILD_X86%"=="00" (
    echo [ERROR] No target architecture selected
    exit /b 1
)

REM Check vcpkg
if not defined VCPKG_ROOT set VCPKG_ROOT=C:\vcpkg
if not exist "%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" (
    echo [ERROR] vcpkg not found at %VCPKG_ROOT%
    exit /b 1
)
set VCPKG_TOOLCHAIN=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake

echo Using vcpkg: %VCPKG_ROOT%
echo Build config: %BUILD_CONFIG%
if "%BUILD_X64%"=="1" (
    echo Build x64: yes
) else (
    echo Build x64: no
)
if "%BUILD_X86%"=="1" (
    echo Build x86: yes
) else (
    echo Build x86: no
)
echo.

REM Clean
if "%CLEAN_BUILD%"=="1" (
    if exist build_x64 rmdir /s /q build_x64
    if exist build_x86 rmdir /s /q build_x86
    if exist dist rmdir /s /q dist
)
if not exist dist mkdir dist

if "%BUILD_X64%"=="1" (
    call :build_x64
    if errorlevel 1 set BUILD_FAILED=1
)

if "%BUILD_X86%"=="1" (
    call :build_x86
    if errorlevel 1 set BUILD_FAILED=1
)

goto :done

:build_x64
echo ========================================
echo Building x64
echo ========================================
echo.

cmake -B build_x64 -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE="%VCPKG_TOOLCHAIN%" -DCMAKE_BUILD_TYPE=%BUILD_CONFIG% -DVCPKG_TARGET_TRIPLET=x64-windows -DXDBG_ARCH=x64

if errorlevel 1 (
    echo [ERROR] x64 configure failed
    exit /b 1
)

cmake --build build_x64 --config %BUILD_CONFIG% -j

if errorlevel 1 (
    echo [ERROR] x64 build failed
    exit /b 1
)

if exist "build_x64\bin\%BUILD_CONFIG%\x64dbg_mcp.dp64" (
    copy /Y "build_x64\bin\%BUILD_CONFIG%\x64dbg_mcp.dp64" "dist\" >nul
    echo [OK] x64 plugin: dist\x64dbg_mcp.dp64
    exit /b 0
)

echo [ERROR] x64 plugin output not found
exit /b 1

:build_x86
echo.
echo ========================================
echo Building x86
echo ========================================
echo.

cmake -B build_x86 -G "Visual Studio 17 2022" -A Win32 -DCMAKE_TOOLCHAIN_FILE="%VCPKG_TOOLCHAIN%" -DCMAKE_BUILD_TYPE=%BUILD_CONFIG% -DVCPKG_TARGET_TRIPLET=x86-windows -DXDBG_ARCH=x86

if errorlevel 1 (
    echo [ERROR] x86 configure failed
    exit /b 1
)

cmake --build build_x86 --config %BUILD_CONFIG% -j

if errorlevel 1 (
    echo [ERROR] x86 build failed
    exit /b 1
)

if exist "build_x86\bin\%BUILD_CONFIG%\x32dbg_mcp.dp32" (
    copy /Y "build_x86\bin\%BUILD_CONFIG%\x32dbg_mcp.dp32" "dist\" >nul
    echo [OK] x86 plugin: dist\x32dbg_mcp.dp32
    exit /b 0
)

echo [ERROR] x86 plugin output not found
exit /b 1

:done
echo.
echo ========================================
echo Build Complete
echo ========================================
echo.

dir /b dist\*.dp* 2>nul

echo.
echo Plugins are in: dist\
echo.

if "%BUILD_FAILED%"=="1" (
    exit /b 1
)

exit /b 0
