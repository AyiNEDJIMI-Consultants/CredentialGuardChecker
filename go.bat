@echo off
echo ========================================
echo Credential Guard Checker - Compilation
echo Ayi NEDJIMI Consultants
echo ========================================
echo.

cl.exe /EHsc /std:c++17 /W4 /Fe:CredentialGuardChecker.exe CredentialGuardChecker.cpp ^
    wbemuuid.lib comctl32.lib tbs.lib advapi32.lib ole32.lib oleaut32.lib user32.lib gdi32.lib /link /SUBSYSTEM:WINDOWS

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Compilation reussie!
    echo Executable: CredentialGuardChecker.exe
    echo.
    echo Lancement...
    CredentialGuardChecker.exe
) else (
    echo.
    echo Erreur de compilation!
    pause
)
