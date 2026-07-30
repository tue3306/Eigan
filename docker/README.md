# docker/ — Empacotamento e sandbox

Docker é o caminho **preferido** (CLAUDE.md §15): cada ferramenta externa roda
em container efêmero (sandbox), evitando poluir o host e aplicando menor
privilégio.

## Subir tudo

```bash
docker compose -f docker/docker-compose.yml up --build
```

Isso sobe a API + dashboard (`eigan serve`) e imprime a URL. Para **escanear** é
preciso um provedor de IA (o EIGAN é AI-native, [ADR-0012](../docs/adr/0012-ai-native-mandatory.md)):
use Ollama local (sem chave, sem custo) ou uma chave de nuvem.

## Arquivos

- `Dockerfile` — imagem do EIGAN (Python 3.11+, instala o pacote e extras).
- `docker-compose.yml` — serviço da aplicação; ponto de extensão para adicionar
  um **alvo de teste local** (DVWA / Juice Shop) e um Postgres opcional.

## Alvo de teste local

Para experimentar com valor real **sem tocar em produção**, rode um alvo
vulnerável local (ex.: `bkimminich/juice-shop`) na mesma rede do compose e
escaneie-o com perspectiva `internal`. Veja [../examples/README.md](../examples/README.md).

> ⚠️ Só escaneie alvos que você controla. O guardrail de escopo bloqueia o resto.
