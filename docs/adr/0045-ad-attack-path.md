# ADR-0045 — Active Directory Attack Path Analysis (TIER X.2)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** TIER X.2 (com auditoria X.1)

## Contexto

Auditoria (X.1): existe um plugin `plugins/red/active-directory` (scaffold) e
`plugins/red/ldapsearch` (coleta), mas **não havia** análise de *attack paths* de AD —
descoberta de relações usuário/grupo/ACL/objeto privilegiado e caminhos de escalonamento
de privilégio. Ambientes corporativos são majoritariamente AD; essa análise é essencial
para Red/Blue/Purple.

## Decisão

Implementar, **de forma original** (P7), sobre o Knowledge Graph (P6/X.10):

- Tipos de AD **aditivos** ao grafo: `NodeKind.COMPUTER` e arestas de escalonamento
  `EdgeKind.MEMBER_OF`, `HAS_CONTROL` (com atributo `right`: GenericAll/WriteDacl/…) e
  `ADMIN_TO`.
- `eigan.analysis.ad.attackpath` — o *attack path* é um problema de **alcançabilidade em
  grafo direcionado**: `find_attack_paths(start, target)` enumera caminhos simples
  (sem revisitar nó → corta ciclos) até `max_depth`, ordenados do mais curto ao mais
  longo, com `limit` contra explosão combinatória; `shortest_attack_path` devolve o mais
  curto. Cada `PathStep` carrega a relação e o direito de AD.

O algoritmo é próprio (DFS com poda de caminho simples); baseia-se **apenas nas relações
coletadas** — nenhuma relação inventada (P1). Como toda análise, opera sobre dados de um
engajamento autorizado (P3).

## Consequências

- **Positivas:** o EIGAN passa a identificar caminhos de escalonamento até alvos de alto
  valor (ex.: Domain Admins) de forma determinística e explicável (cada passo com sua
  relação/direito); base para correlacionar com Kerberos/ADCS/NTLM (X.3–X.8) e para a
  narrativa da IA (X.10/X.11).
- **Custos/limites (honestos):** este ADR entrega o **analisador**; o *builder* que
  popula o grafo de AD a partir da coleta (ldapsearch/BloodHound-like) é incremento
  seguinte, guiado por evidência real de um lab autorizado (não fabricado). Kerberos, AD
  CS/ESC, NTLM e Shadow Credentials (X.3–X.8) entram como módulos próprios subsequentes.
- **Originalidade (P7):** modelo, tipos de aresta e algoritmo próprios, pelos primeiros
  princípios — nenhum código/estrutura/nome de ferramenta de terceiro copiado; apenas os
  conceitos padrão da indústria de segurança de AD.
