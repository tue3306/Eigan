# ADR-0054 — Manuseio seguro de credencial (`SecretHandle`) (TIER X.9 / P8)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** TIER X.9; P8

## Contexto

Uma avaliação autorizada às vezes coleta ou usa credenciais. O X.9 exige "nunca armazenar
credenciais em texto puro" e "mecanismos seguros de memória e redaction". Faltava um
primitivo que impedisse, por construção, que uma credencial vazasse em log/trace/repr.

## Decisão

Adicionar `eigan.security.secrets.SecretHandle`:

- Encapsula o valor; `repr`/`str`/`__format__`/f-string devolvem sempre `[REDACTED]`.
- O valor só sai por `reveal()` — chamada explícita, restrita ao ponto que precisa.
- `matches()` compara em **tempo constante** (`hmac.compare_digest`); `__eq__`/`__hash__`
  não expõem o valor (usável em set/dict sem vazar no repr).
- `scrub(text)` remove o valor de um texto antes de persistir/transmitir.

**Honestidade (P1/P2):** Python não permite apagar de forma garantida uma `str` imutável
da memória; o módulo **não finge** wipe seguro — minimiza exposição (nunca serializa em
claro, nunca loga) e registra o wipe determinístico como **limite conhecido** (exigiria
buffer mutável).

## Consequências

- **Positivas:** credencial não vaza por acidente em log/repr/format; comparação sem
  timing leak; base para a validação de credenciais/privilégios de AD (X.9) e para não
  persistir segredo em claro (P8, junto ao §11.2).
- **Custos/limites (honestos):** sem wipe de memória garantido (limitação da linguagem,
  documentada); a integração com um cofre de segredos é o §20.3.
- **Originalidade (P7):** implementação própria com stdlib; nada de terceiro copiado.
