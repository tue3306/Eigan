# ADR-0031 — Trilha de auditoria à prova de adulteração (encadeada por hash)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** §18.3

## Contexto

Um pentest autorizado precisa de **prova defensável** de que o engajamento seguiu as
regras acordadas. Havia gate de escopo (`security/scope.py`) e consent gate — a base
legal (P3) — mas nenhuma camada que registrasse, de forma **verificável e não
adulterável**, a sequência de ações ativas: quem executou, contra qual alvo, quando,
sob qual autorização/RoE e com qual modelo de IA.

Um registro comum (log em arquivo) não serve como prova: pode ser editado a
posteriori sem deixar vestígio. Tanto o operador quanto o cliente precisam de um
artefato que **detecte adulteração** — inclusive edição, remoção ou reordenação de
entradas antigas.

## Decisão

Introduzir `eigan.policy.audit.AuditTrail`: uma trilha **append-only encadeada por
hash**, persistida como JSONL.

- Cada entrada carrega `prev_hash` (o `entry_hash` da anterior) e um
  `entry_hash = sha256(conteúdo_canônico)`, onde o conteúdo assinado **inclui**
  `prev_hash`. A entrada gênese usa `prev_hash` de 64 zeros (`GENESIS_HASH`).
- Como o hash de cada entrada depende do hash da anterior, adulterar a entrada N muda
  seu `entry_hash`, que é o `prev_hash` de N+1 — a divergência se propaga por toda a
  cauda. `verify()` reprocessa a cadeia e aponta o primeiro `seq` quebrado.
- **Determinismo (liga ao §21.3):** o relógio é injetável e a serialização canônica
  ordena as chaves — mesmo conteúdo ⇒ mesmo hash, reproduzível em teste.
- **Sem segredo/PII em claro (P8):** todo campo textual passa por redaction antes de
  ser gravado. Aplica-se aqui o piso conservador (segredos `chave=valor`, e-mail); a
  unificação plena da política de redaction é o §11.2.

A trilha é um **primitivo de infraestrutura** na camada de política — os pontos de
entrada (CLI/API/MCP) e os controles operacionais (fila HITL do §19.5, kill switch do
§18.2, RoE do §18.1) passam a registrar suas ações ativas nela em incrementos
seguintes. A preservação/backup dedicado da trilha é o §27.2.

## Consequências

- **Positivas:** prova defensável de conformidade do engajamento; adulteração
  detectável; determinismo permite snapshot/regressão; append-only real (arquivo em
  modo append, nunca reescrito); sem dependência nova (stdlib `hashlib`/`json` +
  pydantic já presente).
- **Custos/limites:** a integridade é *detectável*, não *impedida* — um atacante com
  acesso de escrita pode truncar o arquivo inteiro; por isso o §27.2 exige backup
  dedicado e verificação da cadeia após restore. Concorrência multiprocesso não é
  tratada neste incremento (append único por processo); fica registrado para o §23.
- **Originalidade (P7):** implementação própria, pelos primeiros princípios
  (encadeamento de hash é técnica padrão da indústria), sem copiar código de terceiros.
