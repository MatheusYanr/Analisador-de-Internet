@echo off
:: ============================================
:: Monitor de Rede - Execução Automática como ADMINISTRADOR
:: ============================================

:: Verifica se já está rodando como administrador
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Executando como Administrador
    goto :executar
)

:: Se não estiver como admin, solicita elevação
echo Solicitando permissões de Administrador...
powershell -Command "Start-Process '%~f0' -Verb RunAs"
exit /b

:executar
:: Muda para o diretório do script
cd /d "%~dp0"

echo.
echo ========================================
echo   Monitor de Rede Professional v3.3.7
echo ========================================
echo.
echo [INFO] Python detectado:
python --version
echo.
echo [INFO] Iniciando monitor...
echo.

:: Executa o monitor
python monitoramento.py

:: Se der erro, mantém janela aberta
if %errorLevel% neq 0 (
    echo.
    echo [ERRO] O monitor foi encerrado com erro!
    echo Código de saída: %errorLevel%
    echo.
    pause
)
