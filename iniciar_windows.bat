@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ==============================================
echo    ALMOXARIFADO CENTRAL - INICIALIZACAO
echo ==============================================
if not exist ".venv\Scripts\python.exe" (
  echo Criando ambiente Python...
  where py >nul 2>nul
  if %errorlevel% equ 0 (
    py -3 -m venv .venv
  ) else (
    python -m venv .venv
  )
)
if not exist ".venv\Scripts\python.exe" (
  echo ERRO: Instale Python 3.11 ou mais recente.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if %errorlevel% neq 0 (
 echo Erro ao instalar dependencias. Verifique sua conexao.
 pause
 exit /b 1
)
echo.
echo Acesse no navegador: http://127.0.0.1:8000
echo Se for o primeiro acesso, sua senha inicial sera mostrada abaixo.
echo Nao feche esta janela enquanto utilizar o sistema.
echo.
".venv\Scripts\python.exe" -m uvicorn main:app --host 127.0.0.1 --port 8000
pause
