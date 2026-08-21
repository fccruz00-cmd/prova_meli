# Arquitetura da investigação e do agente

```mermaid
flowchart LR
  A["PDF e ZIP recebidos"] --> B["Validação estrutural e SHA-256"]
  B --> C["CSV preservado fora do Git"]
  C --> D["DuckDB: parsing e queries"]
  D --> E["Saída restrita: IPs e tokens completos"]
  D --> F["Saída pública: IPs mascarados e fingerprints"]
  F --> G["Notebook e relatório"]
  F --> H["Agente forense"]
  H --> I["Planejar"]
  I --> J["Executar ferramentas"]
  J --> K["Verificar citações EVID"]
  K --> L["Revisão humana"]
```

## Guardrails do agente

- Recebe somente resumo e resultados sanitizados.
- Trabalha com catálogo fechado de evidências `EVID-001` a `EVID-004`.
- Exige citação de evidência em toda saída GenAI.
- Se não houver modelo configurado, entrega avaliação determinística.
- Impede conclusão de atribuição ou PII confirmada baseada apenas em status HTTP.
- Nunca executa contenção, notificação ou alteração em sistemas; somente recomenda e exige revisão humana.

## Reutilização

O pipeline aceita qualquer CSV/ZIP com o mesmo schema. A regra de suspeição, queries e provider GenAI estão isolados. Para outro caso, ajuste o parser de URI, os limiares e o catálogo de evidências, mantendo a mesma sequência preservar -> analisar -> sanitizar -> raciocinar -> verificar.
