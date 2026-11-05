# Alterações

## 1.0.1

- Corrigida a leitura de `debuggable` em campos diretos e achados do Manifest.
- Adotado o padrão do Android para `usesCleartextTraffic` quando o atributo não
  estiver declarado: permitido até `targetSdk` 27 e bloqueado a partir do 28.
- Corrigida a leitura de `appsec.security_score` do MobSF.
- Separada a exportação efetiva da exportação explicitamente declarada.
- Normalizados descritores, nomes relativos e nomes totalmente qualificados de
  componentes Android.
- Componentes exportados agora são comparados pelos nomes; contagem é fallback.
- Achados SQL, WebView e execução de comandos são comparados por presença, sem
  tratar granularidades diferentes de evidência como divergência automática.
- Adicionados `revisao_manual.csv` e `ground_truth_template.json`.
- O gabarito passou a ignorar valores pendentes em vez de convertê-los em falso.
- Adicionadas métricas agregadas na categoria `TOTAL`.
- Ampliados os testes de regressão para normalização, componentes, score e
  gabarito.
