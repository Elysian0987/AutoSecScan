@echo off
REM Test Coverage Script for AutoSecScan (Windows)
REM Run all tests with coverage reporting

echo.
echo Running AutoSecScan Test Suite with Coverage
echo ==============================================
echo.

REM Create coverage directory
if not exist coverage mkdir coverage

echo Running tests with coverage...
echo.

REM Run tests with coverage
go test -v -race -coverprofile=coverage\coverage.out -covermode=atomic .\...

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [32mAll tests passed![0m
) else (
    echo.
    echo [31mSome tests failed[0m
    exit /b 1
)

REM Generate coverage report
echo.
echo Generating coverage report...
go tool cover -html=coverage\coverage.out -o coverage\coverage.html

REM Display coverage summary
echo.
echo Coverage Summary:
go tool cover -func=coverage\coverage.out | findstr /C:"total:"

echo.
echo Detailed HTML report: coverage\coverage.html
echo Open the HTML file in your browser to see detailed coverage
echo.

pause
