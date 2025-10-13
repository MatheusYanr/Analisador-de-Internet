@echo off
echo ====================================
echo MONITOR DE REDE PROFESSIONAL v2.0
echo ====================================
echo.
echo Iniciando o monitor...
echo.

REM
cd /d "%~dp0"

python monitoramento.py
pause
