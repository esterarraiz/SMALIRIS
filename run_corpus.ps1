param(
    [string]$PastaCorpus = ".\Corpus",
    [int]$MaxCallDepth = 7
)

$RaizSmaliris = $PSScriptRoot
$PastaCorpus = (Resolve-Path -LiteralPath $PastaCorpus).Path

$PastaLogs = Join-Path $RaizSmaliris "logs"
$RelatorioExecucoes = Join-Path $RaizSmaliris "execucoes_corpus.csv"

New-Item -ItemType Directory -Path $PastaLogs -Force | Out-Null

# Procura APKs em todas as subpastas
$apks = @(
    Get-ChildItem `
        -Path $PastaCorpus `
        -Filter "*.apk" `
        -File `
        -Recurse |
    Sort-Object DirectoryName, Name
)

if ($apks.Count -eq 0) {
    Write-Error "Nenhum APK encontrado em: $PastaCorpus"
    exit 1
}

# A SMALIRIS cria a saída usando o nome do APK.
# Nomes repetidos sobrescreveriam resultados.
$nomesDuplicados = @(
    $apks |
    Group-Object BaseName |
    Where-Object { $_.Count -gt 1 }
)

if ($nomesDuplicados.Count -gt 0) {
    Write-Host ""
    Write-Host "[-] Existem APKs com o mesmo nome:" -ForegroundColor Red

    foreach ($grupo in $nomesDuplicados) {
        Write-Host "    $($grupo.Name).apk"

        foreach ($arquivo in $grupo.Group) {
            Write-Host "      $($arquivo.FullName)"
        }
    }

    Write-Host ""
    Write-Host "Renomeie esses APKs antes de iniciar o experimento."
    exit 1
}

Write-Host ""
Write-Host "[+] APKs encontrados: $($apks.Count)"
Write-Host "[+] Corpus: $PastaCorpus"
Write-Host "[+] Profundidade máxima: $MaxCallDepth"
Write-Host "[+] Execução sequencial iniciada"
Write-Host ""

$resultados = @()
$contador = 0

Push-Location $RaizSmaliris

try {
    foreach ($apk in $apks) {
        $contador++

        # O nome da pasta em que o APK está será sua categoria
        $categoria = $apk.Directory.Name
        $categoriaSegura = $categoria -replace '[^\p{L}\p{N}_. -]', '_'
        $nomeSeguro = $apk.BaseName -replace '[^\p{L}\p{N}_.-]', '_'

        # Separa os logs pelas mesmas categorias do corpus
        $PastaLogsCategoria = Join-Path $PastaLogs $categoriaSegura

        New-Item `
            -ItemType Directory `
            -Path $PastaLogsCategoria `
            -Force |
            Out-Null

        $arquivoLog = Join-Path $PastaLogsCategoria "$nomeSeguro.log"

        Write-Host "============================================================"
        Write-Host "[$contador/$($apks.Count)] $categoria"
        Write-Host "APK: $($apk.Name)"
        Write-Host "============================================================"

        $hash = Get-FileHash `
            -LiteralPath $apk.FullName `
            -Algorithm SHA256

        $inicio = Get-Date
        $cronometro = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            & python ".\main.py" "$($apk.FullName)" `
                --max-call-depth $MaxCallDepth 2>&1 |
                Tee-Object -FilePath $arquivoLog

            $codigoSaida = $LASTEXITCODE
        }
        catch {
            $_ | Out-File `
                -FilePath $arquivoLog `
                -Append `
                -Encoding UTF8

            $codigoSaida = -1
        }

        $cronometro.Stop()
        $fim = Get-Date

        if ($codigoSaida -eq 0) {
            $status = "sucesso"

            Write-Host `
                "[+] Análise concluída: $($apk.Name)" `
                -ForegroundColor Green
        }
        else {
            $status = "erro"

            Write-Host `
                "[-] Falha na análise: $($apk.Name)" `
                -ForegroundColor Red
        }

        $resultados += [PSCustomObject]@{
            categoria        = $categoria
            arquivo          = $apk.Name
            caminho          = $apk.FullName
            tamanho_bytes    = $apk.Length
            sha256           = $hash.Hash
            max_call_depth   = $MaxCallDepth
            inicio           = $inicio.ToString("yyyy-MM-dd HH:mm:ss")
            fim              = $fim.ToString("yyyy-MM-dd HH:mm:ss")
            duracao_segundos = [math]::Round(
                $cronometro.Elapsed.TotalSeconds,
                2
            )
            codigo_saida     = $codigoSaida
            status           = $status
            log              = $arquivoLog
            relatorio_json   = Join-Path `
                $RaizSmaliris `
                "output\$($apk.BaseName)\manifest_analysis.json"
            relatorio_html   = Join-Path `
                $RaizSmaliris `
                "output\$($apk.BaseName)\analysis_report.html"
        }

        # Atualiza o CSV após cada APK.
        # Se a execução for interrompida, os resultados anteriores permanecem.
        $resultados |
            Export-Csv `
                -Path $RelatorioExecucoes `
                -NoTypeInformation `
                -Encoding UTF8
    }
}
finally {
    Pop-Location
}

$sucessos = @(
    $resultados |
    Where-Object { $_.status -eq "sucesso" }
).Count

$erros = @(
    $resultados |
    Where-Object { $_.status -eq "erro" }
).Count

Write-Host ""
Write-Host "[+] Corpus finalizado"
Write-Host "    APKs processados: $($resultados.Count)"
Write-Host "    Sucessos: $sucessos"
Write-Host "    Erros: $erros"
Write-Host "    Resumo: $RelatorioExecucoes"
Write-Host "    Logs: $PastaLogs"