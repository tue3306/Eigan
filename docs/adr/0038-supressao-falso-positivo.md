# ADR-0038 — Marcação de finding e supressão de falso-positivo versionada

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** §13.1

## Contexto

O EIGAN tem memória/diff entre scans, mas não aprendia com o feedback do analista: o
mesmo falso-positivo re-alertava a cada scan. Ruído recorrente é a causa nº 1 de
abandono de ferramenta de segurança — o cliente perde confiança no relatório. Faltava
transformar a decisão humana ("isto é FP" / "risco aceito") em supressão persistente,
**sem** esconder o finding nem suprimir sem decisão.

## Decisão

Introduzir `eigan.findings.suppression`:

- **`SuppressionRule`** — casa findings por `asset` (glob), `cwe`, `fingerprint` ou
  `title_contains` (AND dos matchers definidos), com veredito reusando `FindingStatus`
  (`FALSE_POSITIVE` / `ACCEPTED_RISK` — P6, sem enum paralelo). O `__post_init__`
  **impõe** decisão humana (`decided_by` + `reference` obrigatórios — P9) e ao menos um
  matcher (nunca "suprimir tudo"). Suporta `expires_at`.
- **`SuppressionOutcome`** — ao aplicar, o finding suprimido **não some**: o resultado o
  preserva, expõe `suppressed`, uma `note` "suprimido por decisão em <referência>", e um
  `marked()` que devolve uma **cópia** com o status do veredito (o original fica
  intocado — rastreabilidade, P2).
- **`SuppressionSet`** — conjunto com `digest()` (versão auditável) e `from_dict`/
  `to_dict` (YAML). Remover uma regra reverte a supressão — reversível e versionado.

Domínio puro, determinístico, sem I/O.

## Consequências

- **Positivas:** FP marcado não re-alerta; supressão versionada, auditável e reversível;
  nada é apagado; nunca suprime sem decisão humana; reuso do `FindingStatus` existente.
  Base para o baseline de risco aceito (§13.2) e a retroalimentação do eval (§13.3).
- **Custos/limites:** a aplicação no pipeline de relatório/diff (marcar os outcomes na
  saída) e a persistência do conjunto por engajamento são incremento seguinte; a
  primitiva de decisão já está aqui e testada.
- **Originalidade (P7):** modelo próprio, pelos primeiros princípios; nada de terceiro
  copiado.
