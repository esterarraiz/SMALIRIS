param(
    [Parameter(Mandatory = $true)]
    [string]$ApiKey,

    [string]$PastaCorpus = ".\corpus",
    [string]$PastaSaida = ".\resultados_mobsf",
    [string]$Servidor = "http://127.0.0.1:8000",
    [switch]$BaixarPdf,
    [switch]$ForcarNovaAnalise
)

$ErrorActionPreference = "Stop"

chcp 65001 | Out-Null
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$ApiKey = $ApiKey.Trim()
$Servidor = $Servidor.TrimEnd("/")

if ($ApiKey -notmatch "^[0-9a-fA-F]{64}$") {
    Write-Error "A chave da API deve possuir exatamente 64 caracteres hexadecimais."
    exit 1
}

try {
    $script:PythonCommand = (Get-Command python -ErrorAction Stop).Source
}
catch {
    Write-Error "Python nao encontrado no PATH. Ele e necessario para ler os relatorios JSON do MobSF."
    exit 1
}

$script:PythonJsonHelperPath = Join-Path `
    ([System.IO.Path]::GetTempPath()) `
    ("smaliris_mobsf_json_" + $PID + ".py")

$pythonJsonHelperCode = @'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8-sig") as stream:
    report = json.load(stream)

keys = (
    "error",
    "app_name",
    "package_name",
    "file_name",
    "version_name",
    "hash",
    "md5",
)

summary = {key: report.get(key) for key in keys}
print(json.dumps(summary, ensure_ascii=True))
'@

$utf8SemBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText(
    $script:PythonJsonHelperPath,
    $pythonJsonHelperCode,
    $utf8SemBom
)

function Invoke-MobSFRequest {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RequestArguments,

        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )

    $curlArguments = @(
        "--silent",
        "--show-error",
        "--fail-with-body",
        "--retry", "5",
        "--retry-delay", "5",
        "--retry-all-errors",
        "--output", $OutputFile
    ) + $RequestArguments

    & curl.exe @curlArguments

    if ($LASTEXITCODE -ne 0) {
        $responseBody = ""

        if (Test-Path -LiteralPath $OutputFile) {
            $responseBody = Get-Content -LiteralPath $OutputFile -Raw -ErrorAction SilentlyContinue
        }

        throw "Falha na requisicao ao MobSF (curl $LASTEXITCODE). $responseBody"
    }
}

function Get-MobSFReportSummary {
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonFile
    )

    # Windows PowerShell 5.1 usa chaves sem diferenciar maiusculas e
    # minusculas em ConvertFrom-Json. Relatorios do MobSF podem conter, por
    # exemplo, okio/Buffer.java e okio/buffer.java no mesmo objeto. O auxiliar
    # Python preserva essas chaves e devolve somente os campos de controle.
    $preferenciaAnterior = $ErrorActionPreference

    try {
        # No PowerShell 5.1, stderr de programas nativos pode virar excecao
        # prematura quando ErrorActionPreference esta como Stop.
        $ErrorActionPreference = "Continue"
        $pythonOutput = & $script:PythonCommand `
            $script:PythonJsonHelperPath `
            $JsonFile `
            2>&1
        $pythonExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $preferenciaAnterior
    }

    if ($pythonExitCode -ne 0) {
        throw "Nao foi possivel validar o JSON do MobSF com Python. $($pythonOutput | Out-String)"
    }

    return (($pythonOutput | Out-String).Trim() | ConvertFrom-Json)
}

$PastaCorpus = (Resolve-Path -LiteralPath $PastaCorpus).Path

if (-not [System.IO.Path]::IsPathRooted($PastaSaida)) {
    $PastaSaida = Join-Path (Get-Location) $PastaSaida
}

$PastaSaida = [System.IO.Path]::GetFullPath($PastaSaida)
New-Item -ItemType Directory -Path $PastaSaida -Force | Out-Null

$ArquivoResumo = Join-Path $PastaSaida "resumo_execucoes_mobsf.csv"

try {
    Invoke-WebRequest -Uri $Servidor -UseBasicParsing -TimeoutSec 15 | Out-Null
}
catch {
    Write-Error "O MobSF nao esta acessivel em $Servidor"
    exit 1
}

$apks = @(
    Get-ChildItem -Path $PastaCorpus -Filter "*.apk" -File -Recurse |
        Sort-Object DirectoryName, Name
)

if ($apks.Count -eq 0) {
    Write-Error "Nenhum APK encontrado em $PastaCorpus"
    exit 1
}

$digestImagem = "nao identificado"

try {
    $digestImagem = (
        docker image inspect `
            opensecurity/mobile-security-framework-mobsf:v4.5.2 `
            --format '{{index .RepoDigests 0}}' |
            Out-String
    ).Trim()
}
catch {
    $digestImagem = "nao identificado"
}

Write-Host ""
Write-Host "[+] MobSF disponivel: $Servidor"
Write-Host "[+] APKs encontrados: $($apks.Count)"
Write-Host "[+] Pasta de saida: $PastaSaida"
Write-Host "[+] Analise sequencial iniciada"
Write-Host ""

$resultados = @()
$contador = 0

foreach ($apk in $apks) {
    $contador++

    $categoria = $apk.Directory.Name
    $categoriaSegura = $categoria -replace '[^\p{L}\p{N}_. -]', '_'
    $nomeSeguro = $apk.BaseName -replace '[^\p{L}\p{N}_. -]', '_'

    $PastaCategoria = Join-Path $PastaSaida $categoriaSegura
    $PastaAplicacao = Join-Path $PastaCategoria $nomeSeguro
    New-Item -ItemType Directory -Path $PastaAplicacao -Force | Out-Null

    $ArquivoUpload = Join-Path $PastaAplicacao "upload_response.json"
    $ArquivoScan = Join-Path $PastaAplicacao "scan_response.json"
    $ArquivoJson = Join-Path $PastaAplicacao "report.json"
    $ArquivoPdf = Join-Path $PastaAplicacao "report.pdf"
    $ArquivoMetadata = Join-Path $PastaAplicacao "metadata.json"
    $ArquivoErro = Join-Path $PastaAplicacao "erro.txt"

    Write-Host "============================================================"
    Write-Host "[$contador/$($apks.Count)] $categoria"
    Write-Host "APK: $($apk.Name)"
    Write-Host "============================================================"

    # Recupera uma analise que o MobSF concluiu, mas que uma versao anterior
    # do script nao conseguiu converter por haver chaves que diferem apenas
    # entre maiusculas e minusculas.
    if (
        -not $ForcarNovaAnalise -and
        -not (Test-Path -LiteralPath $ArquivoJson) -and
        (Test-Path -LiteralPath $ArquivoScan)
    ) {
        try {
            $resumoScanExistente = Get-MobSFReportSummary -JsonFile $ArquivoScan

            if (
                -not $resumoScanExistente.error -and
                (
                    $resumoScanExistente.app_name -or
                    $resumoScanExistente.package_name -or
                    $resumoScanExistente.file_name
                )
            ) {
                Copy-Item -LiteralPath $ArquivoScan -Destination $ArquivoJson -Force
                Write-Host "[=] Relatorio recuperado da execucao anterior."
            }
        }
        catch {
            Write-Host "[!] A resposta anterior estava incompleta; o APK sera analisado novamente."
        }
    }

    # O JSON retornado por /api/v1/scan e o artefato principal do experimento.
    # O PDF e opcional porque algumas versoes/instalacoes do MobSF retornam
    # "Report not Found" mesmo depois de uma analise estatica concluida.
    if (-not $ForcarNovaAnalise -and (Test-Path -LiteralPath $ArquivoJson)) {
        try {
            $relatorioExistente = Get-MobSFReportSummary -JsonFile $ArquivoJson

            if (
                -not $relatorioExistente.error -and
                (
                    $relatorioExistente.app_name -or
                    $relatorioExistente.package_name -or
                    $relatorioExistente.file_name
                )
            ) {
                $metadataExistente = $null

                if (Test-Path -LiteralPath $ArquivoMetadata) {
                    $metadataExistente = Get-Content -LiteralPath $ArquivoMetadata -Raw | ConvertFrom-Json
                }

                $shaExistente = (Get-FileHash -LiteralPath $apk.FullName -Algorithm SHA256).Hash
                $mobsfHashExistente = ""
                $inicioExistente = ""
                $duracaoExistente = ""
                $pdfStatusExistente = "indisponivel"
                $pdfErroExistente = "PDF nao gerado pelo endpoint do MobSF. O JSON permanece valido."

                if ($metadataExistente) {
                    if ($metadataExistente.sha256) {
                        $shaExistente = $metadataExistente.sha256
                    }

                    $mobsfHashExistente = $metadataExistente.mobsf_hash
                    $inicioExistente = $metadataExistente.inicio
                    $duracaoExistente = $metadataExistente.duracao_segundos

                    if ($metadataExistente.erro) {
                        $pdfErroExistente = $metadataExistente.erro
                    }
                }

                if (Test-Path -LiteralPath $ArquivoPdf) {
                    try {
                        $bytesPdfExistente = [System.IO.File]::ReadAllBytes($ArquivoPdf)

                        if (
                            $bytesPdfExistente.Length -ge 4 -and
                            [System.Text.Encoding]::ASCII.GetString($bytesPdfExistente, 0, 4) -eq "%PDF"
                        ) {
                            $pdfStatusExistente = "disponivel"
                            $pdfErroExistente = ""
                        }
                    }
                    catch {
                        $pdfStatusExistente = "indisponivel"
                    }
                }

                # Corrige metadados de execucoes anteriores que marcaram toda
                # a analise como erro apenas porque o PDF nao foi encontrado.
                if ($metadataExistente) {
                    $metadataExistente.status = "sucesso"
                    $metadataExistente.erro = ""
                    $metadataExistente |
                        Add-Member -MemberType NoteProperty -Name pdf_status -Value $pdfStatusExistente -Force
                    $metadataExistente |
                        Add-Member -MemberType NoteProperty -Name pdf_erro -Value $pdfErroExistente -Force

                    $metadataExistente |
                        ConvertTo-Json -Depth 10 |
                        Set-Content -LiteralPath $ArquivoMetadata -Encoding UTF8
                }

                if (Test-Path -LiteralPath $ArquivoErro) {
                    Remove-Item -LiteralPath $ArquivoErro -Force -ErrorAction SilentlyContinue
                }

                Write-Host "[=] Relatorio JSON existente. APK ignorado."

                if ($pdfStatusExistente -ne "disponivel") {
                    Write-Host "[!] PDF indisponivel; isso nao invalida a analise JSON." -ForegroundColor Yellow
                }

                $resultados += [PSCustomObject]@{
                    categoria        = $categoria
                    arquivo          = $apk.Name
                    sha256           = $shaExistente
                    mobsf_hash       = $mobsfHashExistente
                    status           = "ja analisado"
                    pdf_status       = $pdfStatusExistente
                    inicio           = $inicioExistente
                    duracao_segundos = $duracaoExistente
                    json             = $ArquivoJson
                    pdf              = if ($pdfStatusExistente -eq "disponivel") { $ArquivoPdf } else { "" }
                    erro             = ""
                }

                $resultados | Export-Csv -Path $ArquivoResumo -NoTypeInformation -Encoding UTF8
                continue
            }
        }
        catch {
            Write-Host "[!] Resultado anterior incompleto. Executando novamente."
        }
    }

    $inicio = Get-Date
    $cronometro = [System.Diagnostics.Stopwatch]::StartNew()
    $sha256 = (Get-FileHash -LiteralPath $apk.FullName -Algorithm SHA256).Hash

    $status = "erro"
    $mensagemErro = ""
    $mobsfHash = ""
    $appName = ""
    $packageName = ""
    $versionName = ""
    $pdfStatus = "nao solicitado"
    $pdfErro = ""

    try {
        if (Test-Path -LiteralPath $ArquivoErro) {
            Remove-Item -LiteralPath $ArquivoErro -Force
        }

        Write-Host "    [1/3] Enviando APK..."

        Invoke-MobSFRequest `
            -RequestArguments @(
                "-X", "POST",
                "-H", "Authorization: $ApiKey",
                "-F", ("file=@" + $apk.FullName),
                "$Servidor/api/v1/upload"
            ) `
            -OutputFile $ArquivoUpload

        $upload = Get-Content -LiteralPath $ArquivoUpload -Raw | ConvertFrom-Json

        if (-not $upload.hash) {
            throw "O MobSF nao retornou o hash do upload."
        }

        $mobsfHash = $upload.hash

        Write-Host "    [2/3] Executando analise estatica..."

        Invoke-MobSFRequest `
            -RequestArguments @(
                "-X", "POST",
                "-H", "Authorization: $ApiKey",
                "--data-urlencode", ("scan_type=" + $upload.scan_type),
                "--data-urlencode", ("file_name=" + $upload.file_name),
                "--data-urlencode", ("hash=" + $upload.hash),
                "--data-urlencode", "re_scan=1",
                "$Servidor/api/v1/scan"
            ) `
            -OutputFile $ArquivoScan

        $scanResponse = Get-MobSFReportSummary -JsonFile $ArquivoScan

        if ($scanResponse.error) {
            throw "Falha na analise: $($scanResponse.error)"
        }

        # Na versao v4.5.2, /api/v1/scan ja devolve o relatorio JSON
        # completo. Reaproveitar essa resposta evita o 404 observado em
        # /api/v1/report_json.
        Copy-Item `
            -LiteralPath $ArquivoScan `
            -Destination $ArquivoJson `
            -Force

        $relatorioJson = $scanResponse

        $appName = $relatorioJson.app_name
        $packageName = $relatorioJson.package_name
        $versionName = $relatorioJson.version_name

        if ($BaixarPdf) {
            Write-Host "    [3/3] Tentando baixar relatorio PDF (opcional)..."

            try {
                Invoke-MobSFRequest `
                    -RequestArguments @(
                        "-X", "POST",
                        "-H", "Authorization: $ApiKey",
                        "--data-urlencode", ("hash=" + $mobsfHash),
                        "$Servidor/api/v1/download_pdf"
                    ) `
                    -OutputFile $ArquivoPdf

                $bytesPdf = [System.IO.File]::ReadAllBytes($ArquivoPdf)

                if ($bytesPdf.Length -lt 4) {
                    throw "O relatorio PDF esta vazio."
                }

                $cabecalhoPdf = [System.Text.Encoding]::ASCII.GetString($bytesPdf, 0, 4)

                if ($cabecalhoPdf -ne "%PDF") {
                    throw "O arquivo retornado nao e um PDF valido."
                }

                $pdfStatus = "disponivel"
            }
            catch {
                $pdfStatus = "indisponivel"
                $pdfErro = $_.Exception.Message

                if (Test-Path -LiteralPath $ArquivoPdf) {
                    Remove-Item -LiteralPath $ArquivoPdf -Force -ErrorAction SilentlyContinue
                }

                Write-Host "[!] PDF indisponivel; mantendo a analise JSON como sucesso." -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "    [3/3] PDF ignorado (opcional)."
        }

        $status = "sucesso"
        Write-Host "[+] Analise concluida." -ForegroundColor Green
    }
    catch {
        $mensagemErro = $_.Exception.Message
        $mensagemErro | Set-Content -LiteralPath $ArquivoErro -Encoding UTF8
        Write-Host "[-] $mensagemErro" -ForegroundColor Red
    }
    finally {
        $cronometro.Stop()
    }

    $fim = Get-Date

    $metadata = [ordered]@{
        ferramenta       = "MobSF"
        versao           = "v4.5.2"
        imagem_docker    = "opensecurity/mobile-security-framework-mobsf:v4.5.2"
        digest_imagem    = $digestImagem
        servidor         = $Servidor
        tipo_analise     = "estatica"
        categoria        = $categoria
        arquivo          = $apk.Name
        caminho_original = $apk.FullName
        tamanho_bytes    = $apk.Length
        sha256           = $sha256
        mobsf_hash       = $mobsfHash
        app_name         = $appName
        package_name     = $packageName
        version_name     = $versionName
        inicio           = $inicio.ToString("yyyy-MM-dd HH:mm:ss")
        fim              = $fim.ToString("yyyy-MM-dd HH:mm:ss")
        duracao_segundos = [math]::Round($cronometro.Elapsed.TotalSeconds, 2)
        status           = $status
        pdf_status       = $pdfStatus
        pdf_erro         = $pdfErro
        erro             = $mensagemErro
    }

    $metadata |
        ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath $ArquivoMetadata -Encoding UTF8

    $resultados += [PSCustomObject]@{
        categoria        = $categoria
        arquivo          = $apk.Name
        sha256           = $sha256
        mobsf_hash       = $mobsfHash
        status           = $status
        pdf_status       = $pdfStatus
        inicio           = $inicio.ToString("yyyy-MM-dd HH:mm:ss")
        duracao_segundos = [math]::Round($cronometro.Elapsed.TotalSeconds, 2)
        json             = $ArquivoJson
        pdf              = if ($pdfStatus -eq "disponivel") { $ArquivoPdf } else { "" }
        erro             = $mensagemErro
    }

    $resultados | Export-Csv -Path $ArquivoResumo -NoTypeInformation -Encoding UTF8
    Start-Sleep -Seconds 2
}

$sucessos = @(
    $resultados |
        Where-Object { $_.status -eq "sucesso" -or $_.status -eq "ja analisado" }
).Count

$erros = @(
    $resultados |
        Where-Object { $_.status -eq "erro" }
).Count

$pdfsDisponiveis = @(
    $resultados |
        Where-Object { $_.pdf_status -eq "disponivel" }
).Count

Write-Host ""
Write-Host "[+] Execucao do corpus finalizada"
Write-Host "    APKs registrados: $($resultados.Count)"
Write-Host "    Sucessos: $sucessos"
Write-Host "    Erros: $erros"
Write-Host "    PDFs disponiveis (opcionais): $pdfsDisponiveis"
Write-Host "    Resumo: $ArquivoResumo"
Write-Host "    Resultados: $PastaSaida"

if (Test-Path -LiteralPath $script:PythonJsonHelperPath) {
    Remove-Item -LiteralPath $script:PythonJsonHelperPath -Force -ErrorAction SilentlyContinue
}
