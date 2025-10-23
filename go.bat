@echo off
REM Script de compilation pour NTLMAudit
REM Auteur: Ayi NEDJIMI

echo Compilation de NTLMAudit...

cl.exe /EHsc /std:c++17 /DUNICODE /D_UNICODE NTLMAudit.cpp ^
/Fe:NTLMAudit.exe /link user32.lib comctl32.lib wevtapi.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Compilation reussie!
    echo Executable: NTLMAudit.exe
    echo.
    echo IMPORTANT: Lancez en tant qu'Administrateur pour acceder au journal Security
) else (
    echo.
    echo Erreur de compilation!
)

pause
