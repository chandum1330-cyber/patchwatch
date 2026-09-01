@echo off
REM Convenience wrapper. Usage:
REM   run.bat test     - run the test suite
REM   run.bat dry      - dry run, no model, no tickets
REM   run.bat drymodel - dry run with the model
REM   run.bat live     - real run
REM   run.bat health   - heartbeat check
REM   run.bat schema   - inspect the Apple feed shape

setlocal
if "%PYTHONUTF8%"=="" set PYTHONUTF8=1

if "%1"=="test"     ( python -m unittest discover -s tests -v & goto :eof )
if "%1"=="dry"      ( python -m patchwatch run --dry-run --no-model & goto :eof )
if "%1"=="drymodel" ( python -m patchwatch run --dry-run & goto :eof )
if "%1"=="live"     ( python -m patchwatch run & goto :eof )
if "%1"=="health"   ( python -m patchwatch health & goto :eof )
if "%1"=="schema"   ( python -m patchwatch dump-schema apple & goto :eof )

echo Usage: run.bat [test^|dry^|drymodel^|live^|health^|schema]
endlocal
