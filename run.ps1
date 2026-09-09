$ErrorActionPreference = "Stop"

$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvDir = Join-Path $ProjectDir ".venv"
$Python = Join-Path $VenvDir "Scripts\python.exe"

if (-not (Test-Path $Python)) {
    & py -3 -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create the virtual environment. Install Python 3.12+ and ensure the py launcher is available."
    }
}

& $Python -m pip install -r (Join-Path $ProjectDir "requirements.txt")
if ($LASTEXITCODE -ne 0) {
    throw "Dependency installation failed."
}

& $Python (Join-Path $ProjectDir "manage.py") start_demo @args
exit $LASTEXITCODE