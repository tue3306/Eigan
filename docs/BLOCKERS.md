# Bloqueios conhecidos

Itens que não podem ser resolvidos de dentro do build autônomo. Cada bloqueio é
**isolado** (não impede o resto do trabalho).

| # | Bloqueio | Impacto | Contorno |
|---|---|---|---|
| 1 | **Push para o remoto exige PAT do GitHub.** Autenticação por senha está desativada no remoto. | O passo final (`git push`) não roda sem credencial. | Cada push usa o PAT que o dono fornece, via `GIT_ASKPASS` efêmero (token só em variável de ambiente do comando, **nunca** gravado em repo/config/URL). Em 2026-07-12 os commits até `0f61688` foram empurrados assim. **Atualização 2026-07-30:** no ambiente do dono os pushes para `github.com/tue3306/eigan.git` passaram a funcionar **direto** (credencial git já configurada); o fluxo de PAT efêmero deixou de ser necessário aqui. |
| 2 | **Binários das ferramentas externas** (nmap, nuclei, httpx…) podem não estar instalados no host. | Scans reais dependem das ferramentas. | O engine **pula** ferramenta ausente com aviso; `eigan doctor` lista o que falta e como instalar; Docker roda cada ferramenta em container efêmero. Testes usam fixtures de saída real, sem executar binários. |
| 3 | **Feeds EPSS/KEV** exigem rede na primeira atualização. | Sem `feeds update`, priorização usa só CVSS. | Offline-first: campos saem `UNVERIFIED`; `eigan feeds update` popula o cache quando houver rede (ver ADR-0002). |
| 4 | **Executor em container (§15)** — rodar cada ferramenta em container efêmero exige refatorar o executor dos runners + **revalidar as tags** das imagens oficiais + testes de integração com Docker. Não verificável offline nesta iteração; não fabrico tag/imagem (§3.1). | Ferramentas ProjectDiscovery ausentes no host seguem sendo **puladas** no scan. | ADR-0006: entra na próxima missão com a porta `ToolExecutor` (Local/Docker), sem mudar o caminho local. Enquanto isso, `doctor --install` / `python3 eigan.py --with-tools` provisiona o que é seguro e o engine pula o que falta (com aviso no `doctor`). |
| 5 | **Publicação no PyPI (`eigan`)** exige que o **dono** registre o projeto no PyPI e configure o *trusted publisher* (OIDC). Não executável no build autônomo. | Sem `pipx install eigan`; instalação do núcleo segue por `git clone` + `python3 eigan.py`. | `.github/workflows/publish.yml` pronto (trusted publishing). O job `build` valida o pacote em todo Release; o job `publish` fica **PULADO** (não falha o deploy) até o dono ligar a variável `PYPI_TRUSTED_PUBLISHER=true`. Passos exatos abaixo. |
| 6 | ~~**Renome do repositório no GitHub para `EIGAN`**~~ (ADR-0009) — **RESOLVIDO**: o dono renomeou o repo; o remoto agora é `github.com/tue3306/EIGAN.git`. | — | Feito. Badges/links do README, `web/`, `CONTRIBUTING` e templates apontam para `tue3306/EIGAN`. |
| 7 | ~~**"About" do repositório**~~ — **RESOLVIDO em 2026-07-12**: descrição + 14 tópicos definidos via API (token do dono, efêmero, não gravado). | — | Feito. Os comandos abaixo ficam como referência para reeditar quando quiser. |
| 8 | **Suíte de integração/detecção (DVWA/Juice Shop/WebGoat)** exige Docker rodando + os containers de alvo — indisponível no ambiente atual. Não fabrico resultado nem gabarito (§P1). | A afirmação de "testes de integração" no README/`tests/README.md` era sem lastro executável (corrigida para **política**, §0.1). | Implementar `@pytest.mark.integration` (opt-in, job de CI separado) + `docker-compose.integration.yml` com **gabarito versionado** das vulns conhecidas quando houver Docker (TIER 22.1 do roadmap). Até lá, a política de alvos vale e a suíte é 100% unitária/contrato, verde offline. |

### Ativar a publicação no PyPI (rode você mesmo, uma vez)

Enquanto isso não é feito, o Release **não falha** — o job `publish` fica pulado.
Quando quiser publicar no PyPI:

1. Registre/possua o projeto `eigan` em <https://pypi.org>.
2. Em **PyPI → Manage → Publishing → Add a new pending publisher**, preencha:
   - **Owner:** `tue3306`
   - **Repository name:** `EIGAN`
   - **Workflow name:** `publish.yml`
   - **Environment name:** `pypi`
3. No GitHub, crie a variável de repositório (não é segredo):
   **Settings → Secrets and variables → Actions → Variables → New variable** →
   `PYPI_TRUSTED_PUBLISHER` = `true`.
4. O próximo Release publica sozinho (ou rode `publish` manualmente em **Actions →
   publish → Run workflow**). Sem token/segredo no repo (§5).

### Definir o "About" do repositório (rode você mesmo)

Com **gh** (`gh auth login` antes):

```bash
gh repo edit tue3306/EIGAN \
  --description "EIGAN — scanner de vulnerabilidades dirigido por IA (Red/Blue/Purple): a IA planeja, executa e narra o pentest, com dashboard em tempo real e relatórios Técnico/Executivo." \
  --add-topic security --add-topic cybersecurity --add-topic pentesting \
  --add-topic vulnerability-scanner --add-topic ai-agent --add-topic red-team \
  --add-topic blue-team --add-topic osint --add-topic devsecops \
  --add-topic python --add-topic fastapi --add-topic nuclei --add-topic nmap
```

Sem gh, via **API** (defina `GITHUB_TOKEN` com escopo `repo`; o token nunca vai para o repo):

```bash
curl -sf -X PATCH -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/repos/tue3306/EIGAN \
  -d '{"description":"EIGAN — scanner de vulnerabilidades dirigido por IA (Red/Blue/Purple): a IA planeja, executa e narra o pentest, com dashboard em tempo real e relatórios Técnico/Executivo."}'

curl -sf -X PUT -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/tue3306/EIGAN/topics \
  -d '{"names":["security","cybersecurity","pentesting","vulnerability-scanner","ai-agent","red-team","blue-team","osint","devsecops","python","fastapi","nuclei","nmap"]}'
```
