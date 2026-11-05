param(
    [string]$PastaSmaliris = "",
    [string]$PastaMobSF = ".\resultados_mobsf",
    [string]$PastaSaida = ".\comparacao",
    [string]$Gabarito = ""
)

$ErrorActionPreference = "Stop"
chcp 65001 | Out-Null
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

if (-not $PastaSmaliris) {
    $candidatas = @(
        ".\resultados_smaliris",
        ".\output",
        ".\resultados"
    )

    foreach ($candidata in $candidatas) {
        if (
            (Test-Path -LiteralPath $candidata) -and
            (Get-ChildItem -Path $candidata -Filter "manifest_analysis.json" -File -Recurse | Select-Object -First 1)
        ) {
            $PastaSmaliris = $candidata
            break
        }
    }
}

if (-not $PastaSmaliris) {
    Write-Error "Nao foi localizada uma pasta com relatorios da SMALIRIS. Informe -PastaSmaliris."
    exit 1
}

if (-not (Test-Path -LiteralPath $PastaMobSF)) {
    Write-Error "Pasta do MobSF nao encontrada: $PastaMobSF"
    exit 1
}

$comparador = Join-Path $PSScriptRoot "compare_results.py"
$catalogo = Join-Path $PSScriptRoot "comparison_catalog.json"
$argumentos = @(
    $comparador,
    "--smaliris", $PastaSmaliris,
    "--mobsf", $PastaMobSF,
    "--output", $PastaSaida,
    "--catalog", $catalogo
)

if ($Gabarito) {
    $argumentos += @("--ground-truth", $Gabarito)
}

Write-Host "[+] Resultados SMALIRIS: $PastaSmaliris"
Write-Host "[+] Resultados MobSF: $PastaMobSF"
Write-Host "[+] Saida: $PastaSaida"
Write-Host ""

& python @argumentos
exit $LASTEXITCODE
