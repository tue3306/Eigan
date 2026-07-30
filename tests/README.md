# tests/ — Testes do EIGAN

Testes unitários e de integração. Rode a suíte completa com:

```bash
pytest -q
```

## Organização

- `tests/` — testes de domínio e aplicação: guardrail de escopo/perspectiva,
  schema e fingerprint de finding, dedup/correlação, store SQLite, Risk Engine,
  exporters (JSON/CSV/SARIF), análises (inventário/ATT&CK/compliance).
- `plugins/<...>/tests/` — cada plugin traz seus testes de parser com **fixtures
  de saída real** da ferramenta. O `pyproject.toml` inclui `plugins` em
  `testpaths` e usa `--import-mode=importlib` (parsers com mesmo basename não
  colidem).

## Política de alvos (inegociável)

Qualquer teste de integração roda **exclusivamente contra alvos vulneráveis
locais** (DVWA / OWASP Juice Shop em container), **nunca** contra terceiros.
Testes que dependeriam de rede externa ou de uma ferramenta ausente são marcados
`skip` com motivo — a suíte permanece verde offline.

> **Estado atual (honesto):** ainda **não há** uma suíte de integração versionada
> (`@pytest.mark.integration` + `docker-compose.integration.yml`). Ela está
> planejada (ver `docs/BLOCKERS.md`); quando existir, seguirá esta política. Até
> lá, a suíte é 100% unitária/de contrato e roda offline.

## Definition of Done

Antes de abrir PR: `ruff format .`, `ruff check src plugins tests`, `mypy src` e
`pytest -q` — todos verdes. Toda mudança de comportamento vem com teste.
