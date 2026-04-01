$ErrorActionPreference = "Continue"

$tempDir = Join-Path $PSScriptRoot "temp"
if (-not (Test-Path $tempDir)) {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
}

$examplesDir = Join-Path $PSScriptRoot "examples"
$simfFiles = Get-ChildItem -Path $examplesDir -Filter "*.simf" | Sort-Object Name

foreach ($simf in $simfFiles) {
    $base = $simf.BaseName
    $argsFile = Join-Path $examplesDir "$base.args"
    $witFiles = Get-ChildItem -Path $examplesDir -Filter "*.wit" |
    Where-Object { $_.Name -like "$base.*" } |
    Sort-Object Name

    $baseArgs = @($simf.FullName)
    if (Test-Path $argsFile) {
        $baseArgs += "-a", $argsFile
    }

    # Run without witness
    $outFile = Join-Path $tempDir "$base.txt"
    Write-Host "=== $base (no witness) => $outFile" -ForegroundColor Cyan
    & cargo run -- @baseArgs *> $outFile
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  FAILED (exit $LASTEXITCODE)" -ForegroundColor Red
    }

    # Run once per .wit file
    foreach ($wit in $witFiles) {
        $witSuffix = $wit.BaseName.Substring($base.Length)
        $outFile = Join-Path $tempDir "$base$witSuffix.txt"
        Write-Host "=== $base + $($wit.Name) => $outFile" -ForegroundColor Cyan
        $witArgs = $baseArgs + @("-w", $wit.FullName)
        & cargo run -- @witArgs *> $outFile
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  FAILED (exit $LASTEXITCODE)" -ForegroundColor Red
        }
    }
}