<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="web/assets/logo-dark.svg">
    <img src="web/assets/logo-light.svg" alt="EIGAN — Enhanced Intelligent Guardian for Autonomous Assessment" height="84">
  </picture>
</p>

<p align="center">
  <strong>Enhanced Intelligent Guardian for Autonomous Assessment</strong><br>
  Agente de segurança <strong>autônomo dirigido por IA</strong> (Red · Blue · Purple): a IA
  <strong>planeja, escolhe as ferramentas, orquestra em cascata adaptativa</strong>, reage às
  descobertas e correlaciona tudo — sobre um Core Engine próprio, arquitetura de plugins
  e independência de provedor (Claude · GPT · Gemini · Groq · … · <strong>Ollama local</strong>).
</p>

<p align="center">
  <img alt="Versão" src="https://img.shields.io/badge/vers%C3%A3o-0.0.0-blue">
  <img alt="Status" src="https://img.shields.io/badge/status-pr%C3%A9--alfa-orange">
  <a href="LICENSE"><img alt="Licença" src="https://img.shields.io/badge/licen%C3%A7a-Apache--2.0-blue"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-3776ab?logo=python&logoColor=white">
  <a href="https://github.com/tue3306/EIGAN/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/tue3306/EIGAN/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="IA" src="https://img.shields.io/badge/IA-native%20(obrigat%C3%B3ria)-6c5ce7">
  <img alt="PRs" src="https://img.shields.io/badge/PRs-bem--vindos-brightgreen">
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> ·
  <a href="#-instalação">Instalação</a> ·
  <a href="#-exemplos-de-uso">Exemplos</a> ·
  <a href="docs/architecture.md">Arquitetura</a> ·
  <a href="CONTRIBUTING.md">Contribuir</a> ·
  <a href="docs/adr/">ADRs</a>
</p>

---

> ### ⚠️ Aviso legal — uso autorizado apenas
> Scanning ativo de vulnerabilidades **sem autorização documentada é ilegal** em muitas
> jurisdições. O EIGAN **bloqueia por padrão** qualquer alvo fora de um escopo autorizado e
> exige confirmação de autorização a cada execução. Você é o **único responsável** por operar
> apenas contra sistemas que possui ou tem permissão escrita para testar. Os testes de
> integração rodam somente contra alvos vulneráveis **locais** (DVWA/Juice Shop), nunca contra
> terceiros.

> ### 🚧 Status do projeto — pré-alfa (`0.0.0`)
> Sem release publicado ainda. O **núcleo agêntico** e o **Recon (Red)** rodam de ponta a
> ponta; **Blue** (análise de logs → MITRE ATT&CK) e **Purple** (correlação ataque × detecção)
> já são funcionais. Módulos avançados (Windows/AD, Cloud, SIEM, threat-hunting) entram como
> **_scaffold honesto_** — visíveis no `doctor`, *sugeridos, não executados*, até serem
> implementados (§3.6). O número de versão só sobe quando o conjunto estiver estável e polido —
> **honestidade acima do número**. Veja o [Roadmap](#-roadmap).

## Índice

- [Sobre](#-sobre)
- [Principais recursos](#-principais-recursos)
- [Demonstração](#-demonstração)
- [Arquitetura](#-arquitetura)
- [Instalação](#-instalação)
- [Quick Start](#-quick-start)
- [Exemplos de uso](#-exemplos-de-uso)
- [Estrutura do projeto](#-estrutura-do-projeto)
- [Roadmap](#-roadmap)
- [Contribuição](#-contribuição)
- [FAQ](#-faq)
- [Licença](#-licença)
- [Créditos](#-créditos)

## 🛡️ Sobre

O EIGAN **não é "só um scanner"**: é uma **plataforma de operações de segurança** com Core
Engine próprio que orquestra ferramentas, **normaliza** os resultados em um schema único,
**correlaciona** entre fontes, **prioriza risco** (CVSS · EPSS · CISA KEV) e **gera
relatórios** — extensível por **plugins**, pensada para crescer a 100+ módulos sem reescrever
o núcleo.

Ele é **AI-native e AI-obrigatória**: a IA é a ferramenta. Rodar um scan exige um provedor de
IA configurado (nuvem **ou Ollama local**); sem provedor, o scan é **recusado** com uma
mensagem acionável. Toda a autonomia da IA acontece **dentro** de um envelope determinístico —
autorização, escopo e grounding — que ela nunca contorna.

Tudo gira em torno de duas perguntas:

| | Perspectiva | Pergunta |
|---|---|---|
| 🌐 | **Outside-In** (`external`) | O que um atacante descobre vindo **de fora** da organização? |
| 🏠 | **Inside-Out** (`internal`) | O que um analista identifica estando **dentro** da rede? |

## ✨ Principais recursos

- 🤖 **Agente de IA que comanda o scan** — planeja a estratégia (objetivo → *capacidades* →
  ordem), reage às descobertas em **ondas adaptativas**, decide quando parar e redige as
  narrativas. Cada passo aparece na **timeline de raciocínio**, justificado — sem caixa-preta.
- 🔌 **Independência de provedor** — **Anthropic (Claude) · OpenAI (GPT) · Google Gemini ·
  OpenRouter · Groq · Together AI · Azure OpenAI · Ollama (local)**. Adicionar um provedor é
  registrar um `ProviderSpec` — o núcleo não muda ([ADR-0010](docs/adr/0010-ai-provider-registry.md)).
- 🧩 **Arquitetura de plugins/capabilities** — pense em *capacidades*, não em ferramentas;
  trocar uma ferramenta não quebra nada acima. Adicionar uma = criar uma pasta (auto-discovery
  por `metadata.yaml`; o Core intacto).
- 🔗 **Cascata adaptativa** — cada descoberta encadeia o próximo passo (porta 445 → enumera
  SMB; WordPress → scan WP), com um **piso determinístico** que garante que nada crítico é
  ignorado.
- 🧭 **Perspectiva de 1ª classe** — Outside-In/Inside-Out dirigem guardrails, ferramentas e
  rate limit por **configuração**, não por `if` espalhado.
- 🎯 **Risk Engine honesto** — CVSS v3.1/v4, EPSS (FIRST.org) e CISA KEV de **fonte oficial**;
  sinal não confirmado sai `UNVERIFIED`, **nunca fabricado**.
- 🔐 **Segurança do próprio produto** — subprocess sempre com lista de argumentos (nunca
  `shell=True`), escopo bloqueado por padrão, consent gate inline, *redaction* de segredos/PII
  antes de qualquer provedor externo, alvos validados contra *argument injection*.
- 📊 **Correlação · inventário · MITRE ATT&CK** — dedup entre ferramentas por ativo, mapa de
  técnicas e gap analysis — sem fundir perspectivas cegamente.
- 📄 **Relatórios corporativos** Técnico e Executivo em **HTML · PDF · JSON · CSV · SARIF** —
  capa com **ID único**, **classificação da informação** (Público → Restrito), **score de
  postura**, gráficos, **mascaramento de segredos por padrão**, aviso de confidencialidade,
  hash de integridade e metodologia (PTES / NIST 800-115). Narrativas por IA; exportações
  determinísticas reprodutíveis para SIEM/CI.
- 🖥️ **Dashboard estilo SOC** — tema **claro/escuro**, gráficos (donut + gauge de score), scan
  **ao vivo** via WebSocket (tempo decorrido · ETA · ferramenta atual · timeline de raciocínio ·
  feed de descobertas) e tabela de findings com **busca/filtro/ordenação/paginação e drill-down**.
- 🚀 **Baixa e roda** — um comando do zip ao menu; wizard guiado, `doctor` (com `--probe-ai`
  para **certificar que a IA responde**, incluindo Ollama local), zero-config por padrão.

<sub><b>Ferramentas que executam hoje —</b> <b>Red:</b> nmap · nmap-nse · naabu · nuclei ·
subfinder · amass · dnsx · dig (DNS/AXFR) · httpx · whatweb · katana · ffuf · gowitness · nikto ·
testssl · sqlmap · dalfox · wpscan · enum4linux · ldapsearch + sondagem de exposição/segredos.
<b>Blue:</b> análise de logs (→ MITRE ATT&CK) · trivy · grype. Módulos avançados (Windows/AD,
cloud, exploitation, feroxbuster, password-audit, wireless; SIEM/threat-hunting/IR/malware;
simulação de ataque Purple) entram como <b>scaffold honesto</b>: aparecem no <code>doctor</code>,
<i>sugeridos — não executados</i>, até serem implementados (§3.6).</sub>

## 🎬 Demonstração

**Menu interativo** (`python3 eigan.py` ou `eigan`):

```
╔══════════════════════════════════════════════════════════╗
║  EIGAN · Plataforma de Operações de Segurança            ║
╚══════════════════════════════════════════════════════════╝
  1) Novo Scan      2) Dashboard   3) Histórico   4) Configuração
  5) Doctor         6) Atualizar Ferramentas      7) Sair
```

**Timeline de raciocínio do agente** (o que a IA decide, ao vivo — CLI e dashboard):

```text
#0 [planned] plano por IA: subdomain-enum, http-probe, port-scan   ← estratégia de «attack-surface»
#0 [stop-hint] IA sugere encerrar quando: cobertura de portas e web esgotada
#1 [selected]  port-scan · agente=network · nmap   ← naabu indisponível; nmap cobre serviço+versão
#1 [executed]  port-scan · nmap · 4 finding(s)
#1 [replan:cascade] +smb-enumeration   ← cascata: porta 445/Samba (via enum4linux)
#2 [executed]  smb-enumeration · enum4linux · 2 finding(s)
#2 [replan:ai]  +web-vuln-scan   ← IA (adaptativo): HTTP 200 + tech WordPress observado
#3 [stop] no_new_evidence
```

**Dashboard web (SOC)** (`eigan serve` → `http://127.0.0.1:8000`): tema claro/escuro, gráficos
(donut de severidade + gauge de score), scan **ao vivo** via WebSocket (tempo decorrido · ETA ·
ferramenta atual · timeline de raciocínio · feed de descobertas) e tabela de findings com
busca/filtro/ordenação/paginação/drill-down — export de relatório com escolha de classificação.

<!-- 📸 Para um GIF/screenshot ao vivo, grave o dashboard e salve em web/assets/demo.gif;
     depois troque este bloco por:  ![Demo do EIGAN](web/assets/demo.gif)
     Enquanto isso, veja a prévia visual em web/index.html (a landing) ou rode `eigan serve`. -->

> A landing page ([`web/index.html`](web/index.html)) traz a prévia visual com a identidade do
> produto — abra-a local com `python -m http.server -d web 5500`.

## 🏗️ Arquitetura

Camadas com dependências apontando **para dentro** (Clean/Hexagonal): o domínio não conhece
banco, rede nem ferramentas.

```
Interfaces │ CLI & Wizard  ·  API REST /api/v1 + WebSocket  ·  Dashboard  ·  Landing
           ▼
Aplicação  │ Núcleo cognitivo (Planner → Selection → Execution → Feedback → Stop)
           │ Orchestrator · Pipeline · Enricher · Correlação · Risk Engine
           ▼
Domínio    │ Finding · Scope/Consent · Perspective · Capability          (sem I/O)
           ▲
Infra      │ plugins (red/blue/purple) · Store (SQLite/Postgres) · IA multi-provedor
           │ Report (PDF/HTML/JSON/CSV/SARIF) · feeds (EPSS/KEV) · Policy Engine
```

**Pipeline do Core (event-driven, cada estágio testável isolado):**

```
Discovery → Fingerprint → Execução (plugins) → Normalização → Correlação
   → Enriquecimento (ATT&CK · CVSS · CWE · CAPEC · EPSS/KEV) → Remediação
   → Priorização (Risk) → Dashboard / Reporting → API
```

Adicionar uma ferramenta = criar uma pasta de plugin; **o Core não muda**. Detalhes em
[docs/architecture.md](docs/architecture.md) e nos [ADRs](docs/adr/) (o *porquê* de cada decisão).

## 📦 Instalação

**Requisitos:** Python **3.11+** (e `python3-venv` no Debian/Ubuntu/Kali — o launcher avisa se
faltar). Um provedor de IA (chave de nuvem **ou** Ollama local) para escanear.

<table>
<tr><th>Opção A — Launcher (recomendado)</th><th>Opção B — pip (como comando)</th></tr>
<tr valign="top"><td>

```bash
git clone https://github.com/tue3306/EIGAN.git
cd EIGAN
python3 eigan.py     # cria .venv, instala e abre o menu
```

Um comando do clone ao menu — sem conhecer a estrutura.

</td><td>

```bash
pip install -e ".[pdf,tui]"   # extras: pdf · ai · tui · dev
eigan                         # abre o mesmo menu
eigan --version
```

Instala o comando `eigan` (headless/CI amigável).

</td></tr>
</table>

Ferramentas externas (nmap, nuclei, subfinder, …) são detectadas no `PATH`; as ausentes são
**puladas com aviso** (não quebram o scan). Rode **`eigan doctor`** para ver exatamente o que
falta e o comando de instalação. Caminho recomendado com sandbox:
[`docker/`](docker/) (`docker compose up`). PDF é opcional — sem WeasyPrint, o relatório
**degrada para HTML**.

## 🚀 Quick Start

```bash
# 1) Clone e abra o menu (cria o ambiente e instala tudo)
git clone https://github.com/tue3306/EIGAN.git
cd EIGAN && python3 eigan.py

# 2) Configure a IA (obrigatório):  menu → Configuração → escolha o provedor → cole a chave
#    (gravada em .env, chmod 600, nunca exibida)   — ou use Ollama local, offline e sem custo

# 3) Novo Scan:  menu → Novo Scan → alvo (site/IP/URL) → CONFIRME a autorização
#    Modo unificado: um só scan avalia público E privado e documenta o que achar.
#    Acompanhe a IA planejar/reagir em tempo real e gere o relatório (PDF/HTML/JSON/CSV/SARIF)
```

Sem provedor de IA, o scan é **recusado** com uma mensagem que diz como resolver — a IA é a
ferramenta ([ADR-0012](docs/adr/0012-ai-native-mandatory.md)). Prefere a interface web?
`python3 eigan.py --serve` sobe o dashboard e abre o navegador.

### 🔑 Chaves de ferramenta — cobertura completa (opcional)

Além da chave de IA (obrigatória), **algumas ferramentas rendem muito mais com uma chave de
API** — sem ela rodam com **cobertura parcial**, e o EIGAN avisa o que ficou de fora (nunca
finge cobertura, §3.1). Configure em **menu → Configuração → chaves de ferramenta** (grava no
`.env`, chmod 600, sem exibir a chave) ou veja o estado com **`eigan doctor`**:

| Ferramenta | Chave | Sem a chave |
|---|---|---|
| `wpscan` | `WPSCAN_API_TOKEN` ([obter](https://wpscan.com/api)) | enumera WordPress, mas **não consulta CVEs** de plugins/temas |
| `subfinder` | Shodan · Censys · VirusTotal · SecurityTrails | acha só uma **fração** dos subdomínios (o setup gera o `provider-config.yaml`) |

Ferramentas **pagas/GUI** (ex.: Burp Suite Pro) aparecem no `doctor` como *💳 paga — não
automatizada*: são declaradas para transparência de cobertura, nunca fingindo rodar (§3.6).
Ver [ADR-0013](docs/adr/0013-tool-credential-management.md).

### 🔐 Privilégios (sudo) — opcional, recomendado para scan de rede

**Você NÃO precisa de `sudo` para usar o EIGAN** — o scan roda como usuário normal (a IA,
o web recon com `httpx`/`nuclei`/`katana`, o `naabu` em connect scan, tudo funciona sem root).
O `sudo` só deixa o **`nmap`** mais poderoso, porque algumas técnicas exigem *raw sockets*:

| Com root (`sudo`) | Sem root (usuário normal) |
|---|---|
| SYN scan (`-sS`) — mais rápido e discreto | TCP connect scan (`-sT`) — funciona, um pouco mais lento/ruidoso |
| **Detecção de SO** (`nmap -O`) ligada automaticamente | detecção de SO indisponível (pulada com aviso) |
| scripts NSE que usam pacote cru | demais scripts NSE rodam normalmente |

Só `nmap` se beneficia de root aqui; `naabu`, `httpx`, `nuclei`, `subfinder`, `dnsx`, `whatweb`,
`katana`, `testssl` **não precisam**. Duas formas de dar o privilégio:

```bash
# A) Recomendado (só o nmap ganha o poder; o resto roda sem privilégio):
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)"
python3 eigan.py           # roda normal; o nmap já faz SYN + OS detection

# B) Simples (a ferramenta toda roda como root — cuidado: arquivos e .env podem
#    ficar de posse do root):
sudo -E python3 eigan.py   # -E preserva seu ambiente/.env
```

O EIGAN **detecta o privilégio em runtime** e liga o `nmap -O` só quando é root — então
`sudo` de fato entrega mais, sem quebrar o modo sem privilégio.

## 🧪 Exemplos de uso

O usuário final não precisa da CLI (o menu/dashboard cobre tudo); ela existe para **dev, CI e
power users**.

```bash
# Scan direto (exige provedor de IA). Modo unificado por padrão: avalia público E
# privado e documenta o que encontrar — a autorização é o consent gate inline.
eigan scan example.com --profile standard
eigan scan 10.0.0.5    --profile standard

# Guardrail estrito (opt-in, para quem quer): external recusa privado, internal recusa
# público; e --scope arquivo.yaml é a trava dura por allowlist (times/CI).
eigan scan example.com --perspective external --profile standard
eigan scan 10.0.0.5    --perspective internal --scope meu-escopo.yaml

# Planner por objetivo: mostra a IA escolhendo/justificando capacidades (dry-run seguro)
eigan plan example.com --goal attack-surface        # não executa nada
eigan plan 10.0.0.5    --goal network-assessment --execute   # roda (passa pelo consent gate)

# Certifica que a IA responde de verdade (Ollama local, nuvem, etc.) — chamada real
eigan doctor --probe-ai

# ── Red · Blue · Purple ponta a ponta ────────────────────────────────────────
# Red: a IA planeja e ESCANEIA o que descobre (subdomínio→IP→portas→web→segredos);
#      o exposure prober sonda .git/.env/backups/chaves vazadas (mascaradas).
eigan scan empresa.com --profile deep

# Blue: análise defensiva de LOGS — detecta ataques e mapeia MITRE ATT&CK
eigan blue /var/log/auth.log /var/log/nginx/

# Purple: correlaciona Red×Blue → cobertura e PONTOS CEGOS (atacado sem detecção)
eigan purple 1 2 --ai            # 1=scan Red, 2=análise Blue; --ai narra a priorização

# Relatório corporativo de um scan salvo — estilos: technical | executive
eigan report --scan 1 --format pdf --style executive --classification confidential
eigan report --scan 1 --format pdf --style technical --show-sensitive   # NÃO mascara segredos
eigan report --scan 1 --format sarif                # para GitHub code scanning / SIEM

# Memória entre execuções: o que mudou desde o scan anterior do alvo
eigan diff --scan 7

# Playbooks de remediação (Ansible) revisáveis — SUGESTÃO, nunca auto-aplicada
eigan remediate --scan 7

# API + dashboard
eigan serve                                         # http://127.0.0.1:8000  (/docs, /api/v1/…)

# CI: falha o pipeline se houver finding acima do limiar
eigan scan --target-list examples/targets.example.txt --profile web-only \
  --yes --fail-on high
```

**Perfis:** `quick` · `standard` · `deep` · `network-only` · `web-only`. Mais exemplos e um
laboratório local em [`examples/`](examples/).

<details>
<summary><b>Referência rápida da CLI</b> (clique para expandir)</summary>

| Comando | O que faz |
|---|---|
| `eigan` | Abre o menu interativo (porta de entrada de produto) |
| `eigan scan ALVO…` | Scan direto contra alvos autorizados (headless/CI) |
| `eigan plan ALVO --goal …` | Planner cognitivo por objetivo (dry-run por padrão; `--execute` roda) |
| `eigan report --scan N` | Relatório corporativo (`--format` pdf/html/json/csv/sarif · `--style` technical/executive · `--classification` public/internal/confidential/restricted · `--show-sensitive`) |
| `eigan diff --scan N` | Diff determinístico contra o scan anterior do alvo |
| `eigan remediate --scan N` | Gera playbooks Ansible revisáveis (sugestões) |
| `eigan serve` | Sobe API + dashboard SOC (tema claro/escuro, tempo real) |
| `eigan doctor [--install] [--probe-ai]` | Diagnóstico do ambiente; `--probe-ai` faz uma chamada real p/ certificar a IA |
| `eigan feeds update` | Atualiza o catálogo CISA KEV (fonte oficial, com cache) |

</details>

## 🗂️ Estrutura do projeto

```
src/eigan/
├─ capability.py  perspective.py    conceitos de 1ª classe do domínio
├─ findings/                        schema normalizado · store (SQLite) · dedup/correlação
├─ engine/                          orchestrator · pipeline · registry · cascade · risk · feeds
│  └─ cognitive/                    núcleo agêntico: goal · planner · selection · agent · engine
├─ analysis/                        inventário · MITRE ATT&CK · conformidade · diff
├─ report/                          determinístico (HTML/PDF) + exporters (JSON/CSV/SARIF)
├─ ai/                              provider multi-fornecedor (pré-requisito de execução)
├─ policy/                          Policy/Guardrail Engine (ImpactClass + vet)
├─ security/                        scope guardrail · consent gate · onboarding
├─ api/                             FastAPI (/api/v1 + WS) + static/ (dashboard SPA)
└─ cli/                             Click: scan · plan · report · serve · doctor · feeds + wizard

plugins/<red|blue|purple>/…         capabilities intercambiáveis (auto-discovery)
config/                             profiles.yaml · tools.yaml · ai.yaml (zero-config por padrão)
knowledge/                          base determinística: skills/ · attack/ · compliance/
web/                                landing page + design tokens + logo/favicon
docs/                               architecture · adr/ · design/ · roadmap/ · DECISIONS · internal/
examples/  docker/  tests/          alvos de exemplo · sandbox · unit + integração local
```

Os diretórios principais têm o seu próprio `README.md`; o **mapa do código-fonte**
(camadas, módulos e onde adicionar coisas) está em
[`src/eigan/README.md`](src/eigan/README.md).

## 🗺️ Roadmap

**Já funciona hoje (pré-alfa `0.0.0`):** núcleo agêntico (a IA comanda o scan fim a fim) · Recon Red
real (arsenal de 20+ ferramentas) + **exposição/segredos vazados** (`.git`/`.env`/backups/chaves, mascarados) ·
cascata adaptativa · perspectivas Outside-In/Inside-Out · Risk Engine (CVSS/EPSS/KEV) · correlação +
inventário + ATT&CK · **Blue real** (`eigan blue` — detecção em logs mapeada a ATT&CK) · **Purple
real** (correlação ataque×detecção + pontos cegos, na CLI/API/dashboard) · **plano de remediação por
IA** (o que/como arrumar, no dashboard e nos PDFs) · **relatórios corporativos** em 5 formatos ·
**dashboard SOC** (tema claro/escuro, tempo real) · multi-provedor de IA (com `doctor --probe-ai`) ·
"baixa e roda" · Policy Engine (Fase 0).

**Próximo (scaffold honesto → real):**

- 🔴 **Red** — Windows/AD, Cloud (buckets/APIs), password-audit.
- 🔵 **Blue** — SIEM ingest, threat-hunting, incident-response, malware-analysis.
- 🟣 **Purple** — control/detection validation (attack simulation), purple loop contínuo.
- ⚙️ **Policy Engine — Fase 3**: submeter cada *tool-call* ao `vet()` (arbitragem por
  `ImpactClass`, HITL) no loop de execução ([ADR-0011](docs/adr/0011-policy-guardrail-engine.md)).
- 🧠 Memória de longo prazo, attack paths.

Visão completa e faseada em [docs/ROADMAP.md](docs/ROADMAP.md). Itens comerciais são **apenas
documentados** ([docs/roadmap/commercial.md](docs/roadmap/commercial.md)), sem código.

## 🤝 Contribuição

Contribuições são muito bem-vindas! O ponto forte da arquitetura é que **adicionar uma
ferramenta é criar uma pasta** — o Core não muda.

```
plugins/red/minha-ferramenta/
├─ metadata.yaml   nome · capabilities · perspectivas · impact_class · triggers_on
├─ runner.py       execução segura (lista de args, NUNCA shell=True)
├─ parser.py       normaliza a saída para o schema único de Finding
├─ ai.py           enriquecimento por IA
└─ tests/          unit + fixtures de saída real da ferramenta
```

Passo a passo ("plugin em ~5 min"), a Definition of Done e o fluxo de PR em
[CONTRIBUTING.md](CONTRIBUTING.md). Antes do PR: **`ruff` + `mypy` + `pytest` verdes** e
mudanças de comportamento com teste. Todos seguem o [Código de Conduta](CODE_OF_CONDUCT.md).
Vulnerabilidades no próprio EIGAN: veja [SECURITY.md](SECURITY.md) (divulgação responsável).

## ❓ FAQ

<details>
<summary><b>Preciso mesmo de uma chave de IA?</b></summary>

**Sim.** O EIGAN é um agente de IA (AI-native): sem um provedor configurado, o scan é recusado
com uma mensagem acionável. Use um provedor de nuvem (Claude/GPT/Gemini/Groq/…) **ou o Ollama
local** — sem chave, sem custo, 100% offline. Ver [docs/ai-providers.md](docs/ai-providers.md).
</details>

<details>
<summary><b>É legal usar?</b></summary>

Depende de **você** ter autorização. Só escaneie o que possui ou tem permissão escrita para
testar. O produto **bloqueia alvos fora do escopo por padrão** e exige confirmação — trate isso
como recurso, não obstáculo. Veja o aviso legal acima e o [SECURITY.md](SECURITY.md).
</details>

<details>
<summary><b>A IA vê minhas credenciais/segredos?</b></summary>

Não sem *redaction*. Segredos e PII são removidos **antes** de qualquer envio a um provedor
externo; chaves de API só vivem em variáveis de ambiente / `.env` (`chmod 600`, fora do git).
Para privacidade máxima, use **Ollama local** — nada sai da máquina.
</details>

<details>
<summary><b>Meus dados de CVE/EPSS/KEV são confiáveis?</b></summary>

Sim — vêm de **fonte oficial** (NVD/OSV, FIRST.org, CISA KEV) com cache. Sinal não confirmado
sai `UNVERIFIED`; o EIGAN **nunca fabrica** score, CVE ou versão.
</details>

<details>
<summary><b>Como adiciono uma ferramenta?</b></summary>

Criando uma pasta em `plugins/` com `metadata.yaml` + `runner.py` + `parser.py` — o Core faz
auto-discovery. Ver [Contribuição](#-contribuição) e o [CONTRIBUTING.md](CONTRIBUTING.md).
</details>

<details>
<summary><b>Funciona no Windows/macOS?</b></summary>

O core (Python 3.11+) é multiplataforma; as ferramentas externas seguem o seu SO. O caminho
recomendado e reprodutível é **Docker** (`docker compose up`), que isola as ferramentas.
</details>

## 📄 Licença

Distribuído sob a licença **[Apache-2.0](LICENSE)**. © 2026 EIGAN contributors.

## 🙏 Créditos

Construído sobre o trabalho de uma comunidade enorme:

- **Ferramentas orquestradas** — [Nmap](https://nmap.org/), a suíte
  [ProjectDiscovery](https://projectdiscovery.io/) (naabu · nuclei · subfinder · dnsx · httpx),
  enum4linux e os projetos do roadmap (whatweb, wpscan, testssl, sqlmap, …). O EIGAN os
  **orquestra**; todo o crédito das ferramentas é de seus autores.
- **Padrões e feeds** — MITRE [ATT&CK](https://attack.mitre.org/) · [CAPEC](https://capec.mitre.org/)
  · [CWE](https://cwe.mitre.org/), [OWASP](https://owasp.org/), [NIST](https://www.nist.gov/)
  (SP 800-115 · CSF), [FIRST.org EPSS](https://www.first.org/epss/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  e [NVD](https://nvd.nist.gov/) / [OSV](https://osv.dev/).
- **Stack** — [Python](https://www.python.org/), [FastAPI](https://fastapi.tiangolo.com/),
  [Pydantic](https://docs.pydantic.dev/), [Click](https://click.palletsprojects.com/),
  [Uvicorn](https://www.uvicorn.org/), [Jinja2](https://jinja.palletsprojects.com/),
  [WeasyPrint](https://weasyprint.org/), [ruff](https://docs.astral.sh/ruff/),
  [mypy](https://mypy-lang.org/) e [pytest](https://pytest.org/).
- **Comparações com outras ferramentas** só por características verificáveis — nunca alegação
  depreciativa.

<p align="center"><sub>
  Feito para aguentar auditoria de especialistas e uso por grandes empresas —
  segurança e legalidade antes de conveniência. · <a href="#índice">▲ topo</a>
</sub></p>
