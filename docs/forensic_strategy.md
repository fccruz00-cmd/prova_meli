# Estratégia forense do caso

## Questão central

Determinar se o endpoint vulnerável foi explorado entre 2025-10-01 e 2025-12-31, qual população pode ter sido exposta, quais sites foram afetados e quais decisões de contenção e notificação precisam de evidência adicional.

## Hipóteses testadas

| ID | Hipótese | Teste | Resultado |
|---|---|---|---|
| H1 | Há automação incompatível com uso humano | User-Agent, volume, cardinalidade de invoices e regularidade diária | Sustentada |
| H2 | Um conjunto reduzido de tokens foi reutilizado em massa | Tokens distintos por IP e alcance por token | Sustentada |
| H3 | A atividade aumentou durante o trimestre | Volume diário e mensal | Sustentada |
| H4 | Houve respostas potencialmente capazes de entregar PII | HTTP 200 e invoices distintos com HTTP 200 | Sustentada como potencial exposição; entrega de corpo não provada |
| H5 | É possível provar acesso cross-account | Correlacionar owner do invoice e subject do token | Não testável com a fonte entregue |
| H6 | É possível atribuir a atividade a uma pessoa | IP, ASN e geolocalização | Não sustentada; enriquecimento de rede não é atribuição |

## Método

1. Preservar PDF, ZIP e CSV; registrar SHA-256, tamanho e metadados disponíveis.
2. Validar o ZIP contra path traversal e selecionar somente o CSV principal.
3. Conferir contagem física de linhas, schema, nulos, datas e duplicatas.
4. Fazer parsing sem alterar a evidência; materializar apenas uma base de trabalho descartável.
5. Derivar rankings, distribuições, cardinalidades, séries temporais e indicadores de automação.
6. Enriquecer somente os 20 IPs de maior volume com país/ASN; tratar o resultado como contexto volátil.
7. Separar observação, inferência e desconhecido em cada achado.
8. Exportar versão pública sanitizada e versão restrita completa.
9. Executar testes, revisar o notebook, o relatório e os gráficos; registrar limitações.

## Critério de classificação

Um IP entra no cluster de alta confiança quando todas as suas requisições usam `crawler4j`, `Scrapy` ou `wget`, o volume é igual ou superior a 1.000 e há pelo menos 1.000 invoices distintos. O critério é explícito no código e pode ser ajustado em casos futuros. A classificação não depende apenas de estar no top 20.

## Integridade e repetibilidade

- A evidência original nunca é modificada.
- O banco DuckDB, o CSV extraído e as saídas restritas ficam fora do versionamento.
- Queries, versões de dependências e regra de detecção estão no repositório.
- Resultados públicos usam pseudonimização determinística, permitindo correlação sem publicar identificadores completos.

## Ferramentas

- Python 3.11+ para orquestração, hashing, sanitização e agente.
- DuckDB para leitura eficiente e consultas sobre 4,48 milhões de registros.
- Matplotlib para gráficos.
- IPWho para enriquecimento contextual de país/ASN em 2026-08-21.
- Jupyter/nbformat para o notebook.
- ReportLab/Poppler para o relatório PDF e revisão visual.
- Pytest e GitHub Actions para validação contínua.
