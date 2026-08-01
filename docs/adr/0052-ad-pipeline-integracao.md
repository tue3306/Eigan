# ADR-0052 — Integração dos analisadores de AD (analisadores → sinais → cenários)

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** TIER X.10/X.11

## Contexto

Os analisadores de AD (attack path, ESC, Kerberos, senha, NTLM, Shadow Credentials)
produzem findings tipados distintos. O X.11 (correlação em cenários) opera sobre um
vocabulário comum de `AdSignal`. Faltava a cola que converte as saídas reais dos
analisadores nesse vocabulário e roda a correlação — tornando a suíte de AD consumível
fim a fim.

## Decisão

Adicionar `eigan.analysis.ad.pipeline`:

- `to_ad_signals(kerberos=, adcs=, password=, ntlm=, shadow=)` — mapeia cada finding para
  os sinais que ele **realmente implica** (P1): só kerberoasting **crítico** ⇒
  `privileged_account`; ESC1 ⇒ `esc1` + `vulnerable_template`; ESC4 ⇒
  `excessive_permissions`; senha fraca ⇒ `weak_password_policy`; sem MFA ⇒ `mfa_absent`;
  SMB signing ⇒ `smb_signing_disabled`; shadow gravável ⇒ `shadow_credentials` +
  `acl_misconfig` (mesmo alvo). Deduplica. Sinais sem evidência (ex.: coerção
  `ntlm_relay`) **não** são fabricados — o cenário correspondente não dispara.
- `analyze_ad_scenarios(...)` — fim a fim: analisadores → sinais → cenários priorizados.

## Consequências

- **Positivas:** a suíte de AD passa a ser consumível de ponta a ponta (dados coletados →
  cenários acionáveis), sem duplicar findings; o mapeamento honesto evita cenário falso.
- **Custos/limites (honestos):** os *coletores* que produzem os inputs dos analisadores a
  partir de AD real são incremento seguinte; o cenário NTLM Relay só dispara quando houver
  um detector de coerção (não fabricado).
- **Originalidade (P7):** mapeamento e composição próprios; nada de terceiro copiado.
