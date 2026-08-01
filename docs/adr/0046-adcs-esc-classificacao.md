# ADR-0046 — Classificação de ESC de AD CS (TIER X.5/X.6)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** TIER X.5 (AD CS) e X.6 (ESC1–ESC8)

## Contexto

AD CS é um vetor de escalonamento de privilégio comum em ambientes corporativos. A
auditoria (X.1) não encontrou análise de templates/CA nem classificação de ESC. Uma
plataforma de Red/Blue/Purple precisa sinalizar essas configurações inseguras durante
avaliação autorizada.

## Decisão

Adicionar `eigan.analysis.ad.adcs`, com implementação **própria** (P7):

- `CertificateTemplate` e `CaConfiguration` — modelos mínimos dos **atributos coletados**
  relevantes a ESC (EKU de autenticação, enrollee-supplies-subject, aprovação de gerente,
  assinaturas RA, enrolamento por baixo privilégio, ACLs vulneráveis; flags da CA como
  `EDITF_ATTRIBUTESUBJECTALTNAME2`, web enrollment HTTP, channel binding).
- `classify_adcs(templates, ca)` — aplica as condições padrão da indústria para
  **ESC1–ESC8** e devolve `EscFinding`s ordenados por severidade. Cada finding traz alvo,
  justificativa da condição atendida e o rótulo ESC.

Só decide a partir de atributos coletados (P1) — onde a decisão exige contexto externo
(ESC5, ACLs de objetos de PKI mais amplos), o sinal é um **atributo explícito** vindo da
coleta, não uma suposição. É análise **indicativa** para avaliação autorizada (P3):
sinaliza a condição, não afirma exploração.

## Consequências

- **Positivas:** o EIGAN passa a identificar as classes ESC clássicas de AD CS de forma
  determinística e explicável; integra com o attack-path de AD (ADR-0045) e alimenta a
  correlação (X.11) e os relatórios.
- **Custos/limites (honestos):** o *coletor* que popula `CertificateTemplate`/
  `CaConfiguration` a partir de um ambiente real (certipy-like, com credenciais
  autorizadas) é incremento seguinte, validado contra um lab autorizado — os números não
  são fabricados. A classificação é indicativa, não atestação de exploração.
- **Originalidade (P7):** modelos e checagens próprios, pelos primeiros princípios;
  nenhum código/estrutura/nome de ferramenta de terceiro copiado — apenas os conceitos
  ESC padrão da indústria.
