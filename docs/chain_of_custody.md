# Cadeia de custódia e inventário de evidência

## Registro

Análise iniciada em 2026-08-21, ambiente local controlado, timezone operacional America/Sao_Paulo. Os anexos foram tratados como fontes não confiáveis: o PDF foi inspecionado visualmente e estruturalmente; não continha JavaScript, ações de abertura, anexos ou anotações. O ZIP foi listado antes da extração e não continha caminhos absolutos ou `..`.

| Item | Tamanho (bytes) | SHA-256 | Observação |
|---|---:|---|---|
| Prova Técnica - Digital Forensics.pdf | 142.950 | `E9CCF7E8459F90019EEEAA628134D636B6D88E6956283CD563C5DFC6BC6CEFF4` | 2 páginas; requisitos do caso |
| three_months_logs.zip | 75.057.948 | `E5B14BBE9EEBF3D9A62A89EEA36FA640EC84A5FBD5585B963B6EB7D4A2E0DF54` | 2 entradas; sem path traversal |
| three_months_2025.csv | 1.180.816.975 | `DB95EA3855EAAB29BD209FC9876E129EBB6574A6169CB0366B4DDED5E36D94BF` | CSV principal; CRC32 `F04319B8` |

## Validações

- 4.478.620 linhas físicas, incluindo header.
- 4.478.619 registros ingeridos; diferença esperada de uma linha de cabeçalho.
- 0 registros descartados, 0 timestamps inválidos e 0 duplicatas exatas.
- 10.407 valores nulos em `http_referer`; demais campos relevantes completos.
- O nome da coluna de status vem incorreto na fonte (`http_staus`) e é normalizado somente na tabela derivada.
- O timestamp parece ISO, mas usa `YYYY-DD-MMTHH:MM`; não há timezone nem segundos.
- O arquivo extraído mantém tamanho e CRC32 declarados no ZIP; SHA-256 foi recalculado.

## Transferências e transformações

1. ZIP original em diretório temporário de entrada, somente leitura lógica.
2. Extração do maior CSV válido para área de trabalho fora do Git.
3. Cálculo de hash antes das consultas.
4. Materialização de `logs_raw` e `logs` em DuckDB descartável.
5. Exportação de resultados completos para área restrita ignorada pelo Git.
6. Exportação de resultados públicos com IP mascarado e token fingerprinted.

## Admissibilidade e retenção

Os hashes demonstram integridade entre a evidência recebida e a analisada, mas o pacote não inclui manifesto assinado pelo coletor, identidade do custodiante anterior, comando de aquisição, sistema de origem ou sincronização de relógio. Legal deve obter essas informações, colocar as fontes originais sob legal hold, registrar acessos futuros e preservar os logs correlatos em armazenamento imutável.
