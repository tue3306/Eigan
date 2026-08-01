# ADR-0037 — Preservação da trilha de auditoria (backup dedicado + restore verificado)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** §27.2

## Contexto

A trilha de auditoria (§18.3, ADR-0031) é a prova defensável do engajamento e tem
requisito **mais forte** que os findings: não pode ser perdida nem reescrita. O backup
do store (§27.1) cobre o SQLite, mas a trilha é um artefato JSONL separado, e um backup
que não verifica a cadeia de hash poderia "restaurar" uma trilha já adulterada — o pior
resultado possível para um artefato cuja função é provar integridade.

## Decisão

Adicionar em `eigan.policy.audit` a preservação dedicada:

- **`backup_trail(trail, dest)`** — copia a trilha fielmente (preserva o append-only) e
  devolve a `AuditVerification` da origem. Reporta **honestamente** (P2) se a origem já
  estava comprometida no momento do backup, em vez de mascarar.
- **`restore_trail(src, dest)`** — **verifica a cadeia de hash antes de sobrescrever** o
  destino. Backup com cadeia quebrada ⇒ `AuditIntegrityError` e o destino permanece
  intocado (nunca troca uma trilha íntegra por um backup corrompido — mesmo princípio do
  restore do store, §27.1). Pós-condição: a trilha restaurada verifica com sucesso.
- **`AuditTrail.record_purge(...)`** — um expurgo (§11.3) é **registrado na** trilha
  (append de um evento `purge`), sem reter o dado expurgado e sem apagar a trilha. A
  trilha sobrevive ao expurgo.
- A trilha **não expõe método de deleção** (`delete`/`clear`/`truncate`/…) — garantido
  por teste. Append-only é invariante verificada, não convenção.

## Consequências

- **Positivas:** a trilha é preservável e restaurável com integridade garantida;
  restore nunca destrói dado bom com backup ruim; expurgo é auditável e a trilha
  sobrevive a ele; append-only travado por teste.
- **Custos/limites:** o backup é por cópia de arquivo (adequado a JSONL append-only); a
  amarração do backup da trilha ao fluxo de backup geral (`eigan backup`) e a política de
  retenção que impede expurgo silencioso via CLI são incremento seguinte — as primitivas
  que as sustentam já existem aqui.
- **Originalidade (P7):** implementação própria com stdlib (`shutil`); nada de terceiro
  copiado.
