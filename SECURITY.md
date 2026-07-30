# Política de Segurança

O EIGAN é uma ferramenta de segurança; levamos a segurança **do próprio
produto** a sério (é o item nº 2 da nossa precedência de decisão, atrás apenas de
legalidade).

## Versões suportadas

O projeto está em desenvolvimento ativo (pré-alfa, `0.0.0`) — **ainda não há
releases publicadas**. Correções de segurança são aplicadas sobre o branch `main`,
a única linha suportada até a primeira release.

| Versão | Suportada |
|--------|-----------|
| `0.0.0` (pré-alfa, `main`) | ✅ |

## Como reportar uma vulnerabilidade

**Não abra uma Issue pública** para vulnerabilidades de segurança.

1. **Preferencial:** use o [GitHub Private Vulnerability Reporting][ghsa]
   (aba *Security* → *Report a vulnerability*) do repositório.
2. **Alternativa:** e-mail para **hoffmann3701@gmail.com** com o assunto
   `[EIGAN Security]`.

Inclua, se possível: descrição, versão afetada, passos de reprodução, impacto
estimado e qualquer PoC. Pedimos que você **não divulgue publicamente** até
coordenarmos uma correção.

### O que esperar

- **Confirmação de recebimento:** em até 72 horas.
- **Avaliação inicial e triagem:** em até 7 dias.
- **Correção e divulgação coordenada:** conforme severidade; creditamos quem
  reportar, salvo pedido de anonimato.

## Escopo

Em escopo: código do EIGAN (Core Engine, plugins oficiais, API, CLI,
dashboard) que possa levar a execução indevida, vazamento de dados, escape de
sandbox, injeção de comando ou bypass do guardrail de escopo/consent.

Fora de escopo: vulnerabilidades em ferramentas de terceiros que o EIGAN
apenas orquestra (reporte-as ao projeto de origem) e resultados de scans que você
executou nos **seus próprios** alvos.

## Uso responsável e legal

O EIGAN só deve ser usado contra sistemas que você **possui ou tem
autorização escrita** para testar. O produto bloqueia por padrão alvos fora do
`scope.yaml` e exige confirmação de autorização — **não** contorne esses
controles. Uso não autorizado é ilegal e de sua inteira responsabilidade.

[ghsa]: https://docs.github.com/pt/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability
