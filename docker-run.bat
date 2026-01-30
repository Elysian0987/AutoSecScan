@echo off
REM AutoSecScan Docker Build and Run Script for Windows
REM This script builds the Docker image and provides easy command shortcuts

setlocal enabledelayedexpansion

set IMAGE_NAME=autosecscan
set IMAGE_TAG=latest

if "%1"=="" (
    call :show_help
    exit /b 1
)

if /i "%1"=="build" (
    call :build_image
    exit /b %ERRORLEVEL%
)

if /i "%1"=="scan" (
    if "%2"=="" (
        echo [ERROR] No target URL provided
        echo Usage: %0 scan ^<URL^> [additional flags]
        exit /b 1
    )
    call :run_scan %*
    exit /b %ERRORLEVEL%
)

if /i "%1"=="shell" (
    call :run_shell
    exit /b %ERRORLEVEL%
)

if /i "%1"=="help" (
    call :show_help
    exit /b 0
)

echo [ERROR] Unknown command: %1
echo.
call :show_help
exit /b 1

:build_image
echo [INFO] Building Docker image: %IMAGE_NAME%:%IMAGE_TAG%
docker build -t %IMAGE_NAME%:%IMAGE_TAG% .
if %ERRORLEVEL% equ 0 (
    echo [INFO] Docker image built successfully!
    docker images | findstr %IMAGE_NAME%
) else (
    echo [ERROR] Failed to build Docker image
    exit /b 1
)
exit /b 0

:run_scan
shift
set TARGET=%1
shift
set EXTRA_ARGS=
:parse_args
if not "%1"=="" (
    set EXTRA_ARGS=!EXTRA_ARGS! %1
    shift
    goto :parse_args
)

echo [INFO] Scanning target: %TARGET%

REM Create reports directory if it doesn't exist
if not exist reports mkdir reports

docker run --rm -v "%CD%\reports:/app/reports" %IMAGE_NAME%:%IMAGE_TAG% %TARGET% %EXTRA_ARGS%
exit /b %ERRORLEVEL%

:run_shell
echo [INFO] Starting interactive shell in container
docker run --rm -it -v "%CD%\reports:/app/reports" --entrypoint /bin/sh %IMAGE_NAME%:%IMAGE_TAG%
exit /b %ERRORLEVEL%

:show_help
echo AutoSecScan Docker Helper Script (Windows)
echo.
echo Usage:
echo     %0 ^<command^> [options]
echo.
echo Commands:
echo     build               Build the Docker image
echo     scan ^<URL^> [flags]  Run a security scan on target URL
echo     shell               Start interactive shell in container
echo     help                Show this help message
echo.
echo Examples:
echo     REM Build the image
echo     %0 build
echo.
echo     REM Run a basic scan
echo     %0 scan https://example.com
echo.
echo     REM Run scan with custom options
echo     %0 scan https://example.com --output both --skip nmap
echo.
echo     REM Run scan with verbose output
echo     %0 scan https://example.com --verbose
echo.
echo     REM Start interactive shell
echo     %0 shell
echo.
echo Docker Compose:
echo     REM Build using docker-compose
echo     docker-compose build
echo.
echo     REM Run a scan
echo     docker-compose run --rm autosecscan https://example.com
echo.
echo Direct Docker:
echo     docker run --rm -v "%%CD%%\reports:/app/reports" %IMAGE_NAME%:%IMAGE_TAG% https://example.com
echo.
exit /b 0
