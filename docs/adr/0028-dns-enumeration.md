# ADR-0028 — Enumeração de DNS + zone transfer (AXFR)

- **Status:** aceito
- **Data:** 2026-07-14
- **Relacionado:** profundidade de DNS (roadmap de plataforma); CLAUDE.md §2
  (veracidade — flags verificadas), §6 (plugin novo, Core intacto); ADR-0018
  (expansão de alvos), ADR-0001/0004 (capability/cascata)

## Contexto

A recon do EIGAN resolvia DNS (registros A via `dnsx`, capability `dns_resolution`)
mas **não** enumerava a profundidade de DNS que um pentest real cobre: registros
SOA/NS/MX/TXT/SRV e, sobretudo, **zone transfer (AXFR)** — uma misconfiguração
séria que expõe a zona inteira (todo o mapa de hosts) a qualquer um. As ferramentas
de DNS (`dig`, `dnsrecon`, `dnsenum`, `fierce`) estavam instaladas mas ociosas.

## Decisão

Nova capability `DNS_ENUMERATION` e o plugin Red `plugins/red/dns_enum` sobre o
**`dig`** (escolhido por ter saída estável e flags verificáveis — §2; `dnsrecon`
seria alternativa equivalente). Flags verificadas no `dig` real:
`+noall +answer +time=5 +tries=1` (só a seção de resposta) e `axfr @<ns> <domínio>`.

O runner faz múltiplas consultas (uma por invocação de `dig`, cada uma pelo executor
seguro — lista de args, nunca `shell=True`, timeout): SOA/NS/MX/TXT/SRV e, para cada
nameserver descoberto (teto de 8), tenta AXFR. O parser normaliza:

- **AXFR com registros → finding `CRITICAL`** (`confidence=confirmed` — a
  transferência ocorreu de fato), CWE-200, OWASP A05:2021, ATT&CK T1590.002, com os
  registros vazados como evidência. AXFR recusado → seção vazia → **nenhum finding**
  (comportamento seguro, sem inventar).
- **Registros (SOA/NS/MX/TXT/SRV) → findings `INFO`** (superfície DNS conhecida).

Roteada ao agente **recon** (`built=True`) e às estratégias `ATTACK_SURFACE` e
`FULL_ASSESSMENT`; ordenada logo após a resolução DNS no pipeline.

## Consequências

- **Positivas:** recon de DNS de verdade; o AXFR aberto (achado clássico de alto
  valor) é detectado e reportado com prova. Alimenta a expansão de alvos (ADR-0018)
  pelos hosts revelados. Core intacto (só um plugin + uma capability).
- **Verificação ao vivo:** contra `zonetransfer.me` (zona pública do DigiNinja
  mantida para testar AXFR) o plugin produziu **2 findings CRÍTICOS** (nsztm1/nsztm2
  permitem transfer) + 4 findings INFO de registros — gate cumprido.
- **Limites:** `dig` precisa estar instalado (pacote `dnsutils`/`bind-utils`); o
  `doctor`/`GET /api/v1/tools` reportam a ausência. Não há brute-force de subdomínio
  aqui (é do `subfinder`/`amass`); o foco é registros + AXFR.
- **Testes:** `plugins/red/dns_enum/tests/test_parser.py` (fixture no formato real do
  `dig`): AXFR permitido→CRÍTICO, recusado→sem finding, registros→INFO.
