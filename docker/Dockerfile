# Imagem da aplicação EIGAN (API/CLI). As ferramentas externas de scan
# rodam idealmente em containers efêmeros próprios (sandbox); esta imagem traz
# o núcleo Python + WeasyPrint. Ver docker-compose.yml.
FROM python:3.14-slim

# Dependências de sistema do WeasyPrint (render PDF) — versões resolvidas pelo
# apt da distro base (não fixadas de memória).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY config/ ./config/
COPY knowledge/ ./knowledge/

RUN pip install --no-cache-dir ".[pdf]"

# Menor privilégio: não roda como root.
RUN useradd -m eigan
USER eigan

EXPOSE 8000
# Exposto na rede (--expose → 0.0.0.0): a API EXIGE o token do EIGAN (ADR-0014).
# Defina EIGAN_API_TOKEN no ambiente do container (docker-compose/`-e`); se ausente,
# o EIGAN gera um e o imprime no log de inicialização. Sem token, toda /api/v1 → 401.
ENTRYPOINT ["eigan"]
CMD ["serve", "--expose"]
