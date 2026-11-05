# Comparador SMALIRIS × MobSF 1.0.1

Comparador experimental para associar relatórios pelo SHA-256, normalizar
categorias equivalentes e registrar concordâncias, divergências e recursos que
não são comparáveis entre as ferramentas.

Esta revisão mantém a linha 1.0 e corrige a normalização usada nos experimentos:

- lê `debuggable` também a partir dos achados do Manifest;
- calcula o padrão efetivo de `usesCleartextTraffic` pelo `targetSdk` quando o
  atributo não estiver declarado;
- lê o score do MobSF em `appsec.security_score`;
- separa componentes efetivamente exportados dos explicitamente exportados;
- compara componentes exportados pelos nomes normalizados, usando quantidade
  apenas quando uma ferramenta não fornecer os nomes;
- compara achados de código por presença, mantendo a quantidade de evidências
  como informação auxiliar;
- gera arquivos para revisão manual e construção do gabarito.

## Requisitos

- Python 3.10 ou superior;
- resultados da SMALIRIS contendo `manifest_analysis.json`;
- resultados do MobSF contendo `report.json` e, preferencialmente, o
  `metadata.json` criado pelo `run_mobsf_corpus.ps1`.

Não são necessárias bibliotecas externas.

## Estrutura sugerida

```text
C:\SMALIRIS\
├── compare_results.py
├── comparison_catalog.json
├── run_comparison.ps1
├── resultados_smaliris\
└── resultados_mobsf\
```

Os relatórios podem estar em qualquer quantidade de subpastas.

Se os arquivos do comparador estiverem na pasta principal da SMALIRIS, a forma
mais simples é:

```powershell
.\run_comparison.ps1
```

O script procura automaticamente os relatórios da SMALIRIS em
`resultados_smaliris`, `output` ou `resultados`.

## Execução

```powershell
python .\compare_results.py `
    --smaliris ".\resultados_smaliris" `
    --mobsf ".\resultados_mobsf" `
    --output ".\comparacao"
```

Se os resultados da SMALIRIS estiverem em `output`, use:

```powershell
python .\compare_results.py `
    --smaliris ".\output" `
    --mobsf ".\resultados_mobsf" `
    --output ".\comparacao"
```

## Saídas

- `comparacao_apks.csv`: resumo por APK;
- `comparacao_categorias.csv`: uma linha por APK e categoria normalizada;
- `divergencias.csv`: casos que precisam de revisão;
- `revisao_manual.csv`: divergências comparáveis com campos para decisão,
  fonte, justificativa, revisor e data;
- `comparison_report.json`: relatório completo e reproduzível;
- `comparison_report.html`: visualização para inspeção;
- `metricas_gabarito.csv`: precisão, revocação e F1 quando houver gabarito.
- `ground_truth_template.json`: modelo gerado para todos os APKs e categorias
  comparáveis. Valores `null` não entram nas métricas.

Os CSVs usam `;` e UTF-8 com BOM para abertura correta no Excel em português.

## Gabarito opcional

O MobSF não é considerado gabarito. Para calcular VP, FP, FN e VN, forneça um
arquivo independente:

```json
{
  "schema_version": "1.1",
  "apps": [
    {
      "file_name": "InsecureBankv2.apk",
      "categories": {
        "APP_DEBUGGABLE": {
          "expected": true,
          "evidence_source": "AndroidManifest.xml revisado manualmente",
          "notes": "android:debuggable=true"
        },
        "SQL_INJECTION_RISK": {
          "expected": null,
          "evidence_source": "",
          "notes": "Aguardando revisão do fluxo"
        }
      }
    }
  ]
}
```

Execute acrescentando:

```powershell
--ground-truth ".\ground_truth.json"
```

Categorias fora do escopo de uma ferramenta são registradas como
`nao_comparavel` e não entram como falsos negativos.

O arquivo de exemplo aceita também o formato antigo com valores booleanos
diretos. Textos vazios e valores `null` são ignorados; eles não são convertidos
incorretamente para `false`.

## Definição de componente exportado

Para a comparação com o MobSF, `EXPORTED_ACTIVITY`, `EXPORTED_SERVICE`,
`EXPORTED_RECEIVER` e `EXPORTED_PROVIDER` significam componente com
`android:exported="true"` declarado explicitamente. A SMALIRIS continua
registrando separadamente a exportação efetiva inferida pelo Android, inclusive
por `intent-filter`.

Os nomes são normalizados para o formato totalmente qualificado e comparados
como conjuntos. O relatório informa componentes comuns e componentes presentes
em apenas uma ferramenta. Quando o MobSF disponibiliza somente a contagem, o
campo `base_comparacao` recebe `quantidade_fallback`.

## Procedimento recomendado para o TCC

1. Execute o comparador sem gabarito.
2. Revise `revisao_manual.csv`, consultando o Manifest, o Smali, a documentação
   do aplicativo e o resultado esperado do benchmark.
3. Preencha uma cópia de `ground_truth_template.json`. Inclua também casos
   negativos; revisar apenas divergências produz métricas enviesadas.
4. Execute novamente com `--ground-truth`.
5. Use a linha `TOTAL` e as linhas por categoria de `metricas_gabarito.csv`.

Precisão, revocação e F1 medem a concordância com o gabarito independente. Elas
não medem concordância com o MobSF.

## Testes

```powershell
python -m unittest discover -s tests -v
```
