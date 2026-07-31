"""Interface de linha de comando (headless/CI) + wizard interativo.

`eigan` sem subcomando abre o **wizard** (§F). Subcomandos: ``scan`` (zero-
config: external+standard por padrão), ``report`` (HTML/PDF/JSON/CSV/SARIF ×
técnico/executivo), ``serve`` (API+dashboard), ``doctor`` (diagnóstico) e
``feeds`` (atualização de EPSS/KEV).

Implementada com ``click``. Erros são **acionáveis** (dizem o que falta), nunca
stack trace cru.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from ..engine.cognitive import GoalKind
from ..engine.feeds import FeedCache
from ..findings.schema import Severity
from ..findings.store import FindingStore
from ..perspective import Perspective
from ..security.scope import ScopeViolation
from . import doctor as doctor_mod
from .reporting import TOOL_VERSION, write_report
from .session import SessionAborted, execute_scan, feeds_meta, plan_scan


@click.group(invoke_without_command=True)
@click.version_option(TOOL_VERSION, prog_name="eigan")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """EIGAN — plataforma modular de operações de segurança (uso autorizado).

    Sem argumentos, abre o **menu interativo** (Novo Scan, Dashboard, Histórico,
    Configuração, Doctor, Atualizar Ferramentas). Veja `eigan doctor` para
    checar o ambiente e `eigan scan ALVO` para um scan direto (headless/CI).
    """
    # Carrega o .env (chaves de IA gravadas pelo onboarding) no início de TODO
    # comando — sem isso a chave ficava só no arquivo e o scan era recusado por
    # "falta de provedor". O ambiente real vence (override=False).
    from ..envfile import load_dotenv
    from ..logging_setup import configure_logging

    load_dotenv()
    configure_logging()  # logging estruturado (texto ou JSON via EIGAN_LOG_FORMAT)
    if ctx.invoked_subcommand is None:
        from .menu import run_frontend

        sys.exit(run_frontend())


@cli.command()
@click.argument("targets", nargs=-1)
@click.option("--target-list", type=click.Path(exists=True), help="Arquivo com um alvo por linha.")
@click.option(
    "--perspective",
    type=click.Choice([p.value for p in Perspective]),
    default=None,
    help="unified (padrão) avalia público+privado; external/internal aplicam o "
    "guardrail estrito para quem quer.",
)
@click.option("--profile", default="standard", show_default=True)
@click.option(
    "--scope",
    "scope_path",
    type=click.Path(exists=True),
    default=None,
    help="scope.yaml (trava dura, opcional). Sem ele, usa consent inline.",
)
@click.option("--db", default="eigan.db", show_default=True)
@click.option("--yes", is_flag=True, help="Consent + termo não-interativos (CI autorizado).")
@click.option("--online-enrich", is_flag=True, help="Buscar EPSS (FIRST.org) para os CVEs achados.")
@click.option(
    "--override-perspective",
    is_flag=True,
    help="Libera a regra público×privado da perspectiva (auditado).",
)
@click.option(
    "--fail-on",
    type=click.Choice([s.value for s in Severity]),
    default=None,
    help="Sai !=0 se houver finding >= esta severidade (gate de CI).",
)
@click.option(
    "--max-tokens",
    "max_tokens",
    type=click.IntRange(min=1),
    default=None,
    help="Teto de tokens de IA do scan (§2.1): ao atingir, o scan encerra em paz.",
)
@click.option(
    "--max-cost",
    "max_cost",
    type=click.FloatRange(min=0, min_open=True),
    default=None,
    help="Teto de custo de IA em USD (só com preço verificado; senão use --max-tokens).",
)
def scan(
    targets,
    target_list,
    perspective,
    profile,
    scope_path,
    db,
    yes,
    online_enrich,
    override_perspective,
    fail_on,
    max_tokens,
    max_cost,
):
    """Executa um scan contra ALVOS autorizados (ex.: `eigan scan example.com`)."""
    tlist = list(targets)
    if target_list:
        tlist += [ln.strip() for ln in Path(target_list).read_text().splitlines() if ln.strip()]
    if not tlist:
        raise click.UsageError("Informe ao menos um alvo (posicional) ou --target-list.")

    if override_perspective:
        click.secho("[AUDIT] override de perspectiva ATIVO", fg="yellow", err=True)

    try:
        outcome = execute_scan(
            targets=tlist,
            perspective=Perspective(perspective) if perspective else None,
            profile=profile,
            scope_path=scope_path,
            db=db,
            assume_yes=yes,
            override_perspective=override_perspective,
            online_enrich=online_enrich,
            max_ai_tokens=max_tokens,
            max_ai_cost_usd=max_cost,
            progress=lambda m: click.echo(f"  {m}"),
        )
    except SessionAborted as exc:
        click.secho(f"Cancelado: {exc}", fg="yellow", err=True)
        sys.exit(1)
    except ScopeViolation as exc:
        click.secho(f"BLOQUEADO: {exc}", fg="red", err=True)
        sys.exit(2)

    report = outcome.report
    click.secho(
        f"\nScan #{report.scan_id} [{report.perspective.value}]: {len(report.findings)} findings",
        fg="green",
    )
    for f in report.findings:
        risk = f"{f.risk.score:.0f}" if f.risk else "—"
        click.echo(
            f"  [{f.severity.value.upper():8}] risco {risk:>3}  {f.title}  ({f.affected_asset})"
        )
    if report.skipped_tools:
        click.secho(
            f"Ferramentas indisponíveis: {', '.join(report.skipped_tools)} (rode `eigan doctor`).",
            fg="yellow",
        )

    if fail_on:
        threshold = Severity(fail_on).rank
        worst = max((f.severity.rank for f in report.findings), default=-1)
        if worst >= threshold:
            click.secho(f"Gate CI: finding >= {fail_on} encontrado.", fg="red", err=True)
            sys.exit(1)


@cli.command()
@click.argument("scan_ids", nargs=-1, required=True, type=int)
@click.option("--db", default="eigan.db", show_default=True)
@click.option("--ai", is_flag=True, help="Narrativa da IA priorizando os pontos cegos.")
def purple(scan_ids, db, ai):
    """Correlação Purple: técnicas ATT&CK atacadas (Red) × detectadas (Blue).

    Ex.: `eigan purple 1 2` (um scan Red e um Blue). Mostra a % de cobertura e os
    PONTOS CEGOS (técnica atacada SEM detecção) — onde a defesa está cega.
    """
    from ..analysis.purple import (
        DEFAULT_DETECTION_TOOLS,
        correlate_findings,
        purple_context,
    )
    from ..capability import Category
    from ..engine.registry import PluginRegistry

    store = FindingStore(db)
    try:
        findings = []
        for sid in scan_ids:
            if store.get_scan(sid) is None:
                click.secho(f"Scan #{sid} não encontrado.", fg="red", err=True)
                sys.exit(2)
            findings.extend(store.get_findings(sid))
    finally:
        store.close()

    tools = set(DEFAULT_DETECTION_TOOLS)
    try:
        tools |= {
            s.name for s in PluginRegistry.discover().all() if s.metadata.category == Category.BLUE
        }
    except Exception:  # noqa: BLE001 — registry indisponível não quebra a correlação
        pass
    report = correlate_findings(findings, detection_tools=frozenset(tools))

    click.secho(
        f"\nPurple — cobertura {report.coverage_pct:.0f}% "
        f"({len(report.covered)} coberta(s) / {len(report.gaps)} ponto(s) cego(s))",
        fg="green" if not report.gaps else "yellow",
        bold=True,
    )
    click.echo(
        f"  Red: {report.red_findings} finding(s), {report.red_techniques} técnica(s)  ·  "
        f"Blue: {report.blue_findings} detecção(ões), {report.blue_techniques} técnica(s)"
    )
    if report.gaps:
        click.secho("\n  PONTOS CEGOS (atacado sem detecção):", fg="red")
        for t in report.gaps:
            click.echo(f"    ✗ {t}")
    if report.covered:
        click.secho("\n  Cobertas (atacado E detectado):", fg="green")
        for t in report.covered:
            click.echo(f"    ✔ {t}")
    if ai:
        from ..ai.conversation import purple_analysis
        from ..ai.provider import AIProviderRequired, require_provider

        try:
            require_provider()
        except AIProviderRequired as exc:
            click.secho(str(exc), fg="red", err=True)
            sys.exit(3)
        click.secho("\nNarrativa da IA (priorização dos pontos cegos):", fg="cyan")
        click.echo(purple_analysis(purple_context(report)))


@cli.command()
@click.argument("paths", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--db", default="eigan.db", show_default=True)
@click.option("--online-enrich", is_flag=True, help="Buscar EPSS (FIRST.org) p/ CVEs, se houver.")
@click.option(
    "--fail-on",
    type=click.Choice([s.value for s in Severity]),
    default=None,
    help="Sai !=0 se houver detecção >= esta severidade (gate de CI).",
)
def blue(paths, db, online_enrich, fail_on):
    """Análise defensiva (Blue) de LOGS — detecta ataques e mapeia MITRE ATT&CK.

    Ex.: `eigan blue /var/log/auth.log /var/log/nginx/`. ALVO = arquivo ou
    diretório de logs (SSH/PAM, acesso web CLF/Combined, sudo). As detecções
    entram no mesmo dashboard/relatórios do Red e alimentam a correlação Purple.
    AI-native (§3.4): exige um provedor — a IA analisa e prioriza as detecções.
    """
    from ..ai.provider import AIProviderRequired, require_provider
    from ..engine.blue import run_log_analysis
    from ..engine.risk import RiskScorer

    try:
        provider = require_provider()
    except AIProviderRequired as exc:
        click.secho(str(exc), fg="red", err=True)
        sys.exit(3)

    feeds = FeedCache.load()
    risk = RiskScorer(feeds, online=online_enrich)
    store = FindingStore(db)
    click.echo(f"  Analisando {len(paths)} fonte(s) de log…")
    try:
        report = run_log_analysis(list(paths), store=store, risk=risk, provider=provider)
    finally:
        store.close()

    click.secho(
        f"\nBlue #{report.scan_id}: {len(report.findings)} detecção(ões) "
        f"em {len(report.sources)} fonte(s) de log",
        fg="green",
    )
    for f in report.findings:
        click.echo(
            f"  [{f.severity.value.upper():8}] {f.title}  "
            f"ATT&CK={f.attack_technique or '—'}  ({f.affected_asset})"
        )
    if report.analysis:
        click.echo(
            "\nAnálise + plano de remediação da IA gerados. "
            "Veja no dashboard (`eigan serve`) ou gere o relatório (`eigan report`)."
        )
    if fail_on:
        threshold = Severity(fail_on).rank
        worst = max((f.severity.rank for f in report.findings), default=-1)
        if worst >= threshold:
            click.secho(f"Gate CI: detecção >= {fail_on} encontrada.", fg="red", err=True)
            sys.exit(1)


@cli.command()
@click.argument("targets", nargs=-1)
@click.option(
    "--goal",
    default=GoalKind.ATTACK_SURFACE.value,
    show_default=True,
    help="Objetivo (aceita hífen ou underscore): " + " | ".join(g.value for g in GoalKind),
)
@click.option(
    "--perspective",
    type=click.Choice([p.value for p in Perspective]),
    default=None,
    help="external|internal. Padrão: o da perspectiva do objetivo.",
)
@click.option("--profile", default="standard", show_default=True)
@click.option("--scope", "scope_path", type=click.Path(exists=True), default=None)
@click.option("--db", default="eigan.db", show_default=True)
@click.option(
    "--dry-run/--execute",
    default=True,
    show_default=True,
    help="dry-run: só mostra o plano e a seleção justificada (não executa, sem consent).",
)
@click.option(
    "--ai/--no-ai", default=False, help="IA prioriza capacidades (fallback determinístico)."
)
@click.option("--yes", is_flag=True, help="Consent + termo não-interativos (execução autorizada).")
@click.option("--online-enrich", is_flag=True, help="Buscar EPSS (FIRST.org) na execução.")
@click.option("--override-perspective", is_flag=True, help="Libera público×privado (auditado).")
def plan(
    targets,
    goal,
    perspective,
    profile,
    scope_path,
    db,
    dry_run,
    ai,
    yes,
    online_enrich,
    override_perspective,
):
    """Núcleo cognitivo: dado um OBJETIVO, o Planner escolhe capacidades e o
    Selection Engine escolhe a ferramenta — tudo justificado (ADR-0007).

    Ex.: `eigan plan example.com --goal attack-surface` (dry-run, seguro).
    Adicione `--execute` para rodar de verdade (passa pelo consent gate).
    """
    tlist = list(targets)
    if not tlist:
        raise click.UsageError("Informe ao menos um alvo (posicional).")
    try:
        goal_kind = GoalKind.from_str(goal)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    try:
        outcome = plan_scan(
            goal_kind=goal_kind,
            targets=tlist,
            perspective=Perspective(perspective) if perspective else None,
            profile=profile,
            scope_path=scope_path,
            db=db,
            assume_yes=yes,
            override_perspective=override_perspective,
            online_enrich=online_enrich,
            dry_run=dry_run,
            use_ai=ai,
            echo=lambda m: click.echo(m),
        )
    except SessionAborted as exc:
        click.secho(f"Cancelado: {exc}", fg="yellow", err=True)
        sys.exit(1)
    except ScopeViolation as exc:
        click.secho(f"BLOQUEADO: {exc}", fg="red", err=True)
        sys.exit(2)

    mode = "PLANO (dry-run, nada executado)" if dry_run else "EXECUÇÃO"
    ai_txt = "IA" if outcome.ai_used else "determinístico"
    click.secho(
        f"\n{mode} · objetivo «{outcome.goal.kind.label}» "
        f"[{outcome.goal.perspective.value}] · planner={outcome.planner_name} ({ai_txt})",
        fg="cyan",
        bold=True,
    )
    for d in outcome.decisions:
        color = {
            "selected": "green",
            "executed": "green",
            "suggested": "yellow",
            "scaffold": "yellow",
            "skipped": "yellow",
            "failed": "red",
            "stop": "blue",
        }.get(d.action, None)
        click.secho(f"  {d.render()}", fg=color)

    if outcome.report is not None:
        r = outcome.report
        click.secho(
            f"\nScan #{r.scan_id}: {len(r.findings)} findings · parada: {r.stop_reason.value}",
            fg="green",
        )
    if outcome.suggestions:
        tools = ", ".join(s.tool for s in outcome.suggestions)
        click.secho(f"Sugeridas (não executadas): {tools}", fg="yellow")
    if dry_run:
        click.echo("\nPara executar de verdade: repita com --execute (exige autorização).")


@cli.command()
@click.option("--scan", "scan_id", required=True, type=int)
@click.option("--db", default="eigan.db", show_default=True)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["pdf", "html", "md", "json", "csv", "sarif"]),
    default="html",
    show_default=True,
)
@click.option(
    "--style", type=click.Choice(["technical", "executive"]), default="technical", show_default=True
)
@click.option("--out", default=None)
@click.option("--ai/--no-ai", default=False, help="Enriquecer narrativa com IA (se houver chave).")
@click.option(
    "--classification",
    type=click.Choice(["public", "internal", "confidential", "restricted"]),
    default="confidential",
    show_default=True,
    help="Classificação da informação (destaque na capa/cabeçalho/rodapé + aviso).",
)
@click.option(
    "--show-sensitive",
    is_flag=True,
    help="NÃO mascarar segredos/credenciais no relatório (padrão: mascarado). Use com cuidado.",
)
def report(scan_id, db, fmt, style, out, ai, classification, show_sensitive):
    """Gera relatório de um scan em HTML/PDF/JSON/CSV/SARIF (técnico ou executivo)."""
    store = FindingStore(db)
    fmeta = feeds_meta(FeedCache.load())
    try:
        path, ai_used = write_report(
            store,
            scan_id,
            fmt=fmt,
            style=style,
            out=out,
            use_ai=ai,
            feeds_meta=fmeta,
            classification=classification,
            show_sensitive=show_sensitive,
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    except RuntimeError as exc:  # PDF indisponível → degrada para HTML (§13), sem stack trace
        if fmt == "pdf":
            click.secho(f"PDF indisponível: {exc}", fg="yellow", err=True)
            click.secho("Gerando HTML equivalente…", fg="yellow", err=True)
            path, ai_used = write_report(
                store,
                scan_id,
                fmt="html",
                style=style,
                out=None,
                use_ai=ai,
                feeds_meta=fmeta,
                classification=classification,
                show_sensitive=show_sensitive,
            )
            click.secho(
                f"Relatório HTML gerado: {path}. Para PDF, habilite o WeasyPrint "
                "(rode `eigan doctor`).",
                fg="green",
            )
            return
        click.secho(f"Erro ao gerar {fmt}: {exc}", fg="red", err=True)
        sys.exit(1)
    click.secho(f"Relatório gerado: {path}  (IA: {'sim' if ai_used else 'não'})", fg="green")


@cli.command()
@click.option("--scan", "scan_id", required=True, type=int)
@click.option("--db", default="eigan.db", show_default=True)
@click.option(
    "--out",
    "out_dir",
    default="remediation",
    show_default=True,
    help="Diretório onde gravar os playbooks (sugestões revisáveis).",
)
def remediate(scan_id, db, out_dir):
    """Gera artefatos de correção (Ansible) revisáveis para um scan (Pilar 6).

    SUGESTÕES — nunca aplicadas automaticamente. Findings sem template são
    listados honestamente como pendentes.
    """
    from ..report.remediation import generate_all

    store = FindingStore(db)
    if store.get_scan(scan_id) is None:
        raise click.UsageError(f"Scan #{scan_id} não encontrado no banco {db!r}.")
    findings = store.get_findings(scan_id)
    artifacts, uncovered = generate_all(findings)

    if not artifacts:
        click.secho(
            "Nenhum finding deste scan tem template de remediação ainda "
            "(nada foi fabricado). Veja o roadmap para os tipos cobertos.",
            fg="yellow",
        )
        return

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    click.secho(f"Artefatos de remediação (SUGESTÕES revisáveis) em {out}/:", fg="green", bold=True)
    for art in artifacts:
        (out / art.filename).write_text(art.content)
        click.echo(f"  [{art.format}] {art.filename}  — {art.title}  ({art.applies_to})")
    click.secho(
        "\nRevise cada playbook (variáveis/escopo) antes de aplicar. "
        "O EIGAN NÃO executa remediação automaticamente.",
        fg="yellow",
    )
    if uncovered:
        click.secho(
            f"\nSem template ainda ({len(uncovered)}): "
            + ", ".join(sorted({f.title for f in uncovered}))[:200],
            fg="yellow",
        )


@cli.command()
@click.option("--scan", "scan_id", required=True, type=int, help="Scan atual (mais recente).")
@click.option(
    "--against",
    "baseline_id",
    type=int,
    default=None,
    help="Scan-base para comparar. Padrão: o scan anterior do mesmo alvo (automático).",
)
@click.option("--db", default="eigan.db", show_default=True)
@click.option("--ai/--no-ai", default=False, help="IA narra a mudança (fallback determinístico).")
def diff(scan_id, baseline_id, db, ai):
    """Memória entre scans: o que mudou desde a última execução do alvo (Pilar 2).

    Diff determinístico (novos/corrigidos/persistentes + novos ativos/serviços).
    Ex.: `eigan diff --scan 7`  ·  `eigan diff --scan 7 --against 3`.
    """
    from ..analysis.diff import diff_findings

    store = FindingStore(db)
    if store.get_scan(scan_id) is None:
        raise click.UsageError(f"Scan #{scan_id} não encontrado no banco {db!r}.")
    if baseline_id is None:
        baseline_id = store.find_previous_scan(scan_id)
    previous = store.get_findings(baseline_id) if baseline_id is not None else []
    current = store.get_findings(scan_id)
    result = diff_findings(previous, current, previous_scan_id=baseline_id, current_scan_id=scan_id)

    narrative = _narrate_diff(result) if ai else result.summary()
    click.secho(f"\n{narrative}", fg="cyan", bold=True)

    def _list(label: str, items, color: str) -> None:
        if not items:
            return
        click.secho(f"\n{label}:", fg=color, bold=True)
        for f in items:
            risk = f"{f.risk.score:.0f}" if f.risk else "—"
            click.echo(
                f"  [{f.severity.value.upper():8}] risco {risk:>3}  {f.title}  ({f.affected_asset})"
            )

    _list("Novos", result.new, "red")
    _list("Corrigidos", result.resolved, "green")
    if result.new_services:
        click.secho("\nNovos serviços/portas:", fg="yellow", bold=True)
        for s in result.new_services:
            click.echo(f"  {s}")
    if result.new_assets:
        click.secho("\nNovos ativos:", fg="yellow", bold=True)
        for a in result.new_assets:
            click.echo(f"  {a}")


def _narrate_diff(result) -> str:
    """Narrativa por IA do diff, com **fallback determinístico** (§3.4). A IA só
    recebe contagens + títulos já normalizados (grounding); nunca inventa."""
    base = result.summary()
    try:
        from ..ai.provider import default_provider

        provider = default_provider()
        if provider is None or not provider.available():
            return base
        counts = result.counts()
        titles = "; ".join(f.title for f in result.new[:5]) or "nenhum"
        system = (
            "Você resume mudanças entre dois scans de segurança para um gestor. "
            "Baseie-se SOMENTE nos dados fornecidos. NUNCA invente CVE, número ou "
            "severidade. 2-3 frases, direto."
        )
        user = (
            f"Contagens: {counts}. Novos findings (títulos): {titles}.\nBase determinística: {base}"
        )
        text = provider.complete(system, user).strip()  # type: ignore[attr-defined]
        return text or base
    except Exception:  # noqa: BLE001 — IA nunca quebra o diff
        return base


@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8000, type=int, show_default=True)
@click.option("--db", default="eigan.db", show_default=True)
@click.option(
    "--expose",
    is_flag=True,
    default=False,
    help="Expor na rede (0.0.0.0). Exige e imprime o token do EIGAN. Sem isto: só loopback.",
)
@click.option(
    "--open/--no-open",
    "open_browser",
    default=None,
    help="Abrir o navegador no dashboard (padrão: sim em terminal interativo).",
)
def serve(host, port, db, expose, open_browser):
    """Sobe a API + dashboard, imprime a URL e (opcional) abre o navegador.

    Por segurança (ADR-0014) o bind é loopback (127.0.0.1) por padrão. Use
    ``--expose`` para ouvir em 0.0.0.0 — aí a API exige o token do EIGAN."""
    from .menu import serve_app

    if expose and host in ("127.0.0.1", "localhost", "::1"):
        host = "0.0.0.0"  # nosec B104 — só com --expose explícito; a API então exige token (ADR-0014)
    if open_browser is None:
        open_browser = sys.stdout.isatty()
    serve_app(host=host, port=port, db=db, open_browser=open_browser, echo=click.echo)


@cli.command("menu")
@click.option("--db", default="eigan.db", show_default=True)
def menu_cmd(db):
    """Abre o menu interativo (porta de entrada de produto: TUI ou menu numerado)."""
    from .menu import run_frontend

    sys.exit(run_frontend(db))


@cli.command()
@click.option(
    "--install",
    "do_install",
    is_flag=True,
    help="Provisiona (com confirmação) as ferramentas com runner real que faltam.",
)
@click.option("--yes", is_flag=True, help="Confirma sem interação (automação autorizada).")
@click.option(
    "--probe-ai",
    "probe_ai",
    is_flag=True,
    help="Testa de verdade se a IA responde (chamada real ao provedor ativo).",
)
def doctor(do_install, yes, probe_ai):
    """Diagnostica o ambiente (Python, ferramentas, IA, Docker, PDF, feeds).

    Com --install, lista exatamente o que vai rodar e, após sua confirmação
    (consent gate), instala as ferramentas reais ausentes — nunca de fonte não
    oficial, nunca com shell. Com --probe-ai, faz uma chamada real ao provedor de
    IA configurado para certificar que ele responde (Ollama, nuvem, etc.).
    """
    report_ = doctor_mod.gather()
    doctor_mod.render(report_, click.echo, click.secho)
    if probe_ai:
        doctor_mod.probe_ai(click.echo, click.secho)
    if do_install:
        actions = doctor_mod.plan_install(report_)
        doctor_mod.run_install(actions, assume_yes=yes, echo=click.echo)
        return
    level, _ = report_.verdict()
    sys.exit(0 if level != "error" else 1)


@cli.group()
def feeds():
    """Feeds de risco (EPSS/KEV) — fonte oficial, com cache (ADR-0002)."""


@feeds.command("update")
def feeds_update():
    """Atualiza o catálogo CISA KEV (rede). EPSS é enriquecido sob demanda no scan."""
    fc = FeedCache.load()
    click.echo("Baixando CISA KEV…")
    try:
        meta = fc.update_kev()
    except Exception as exc:  # noqa: BLE001 — rede/parse: mensagem acionável, sem stack trace
        click.secho(
            f"Falha ao atualizar KEV: {exc}\n"
            "Verifique a conexão; sem o feed, KEV sai UNVERIFIED (não fabricado).",
            fg="red",
            err=True,
        )
        sys.exit(1)
    click.secho(
        f"KEV atualizado: {meta['count']} CVEs · versão {meta.get('catalogVersion', '?')} "
        f"· {meta.get('dateReleased', '?')}",
        fg="green",
    )
    click.echo(f"Cache: {fc.cache_dir}")


def main() -> None:
    from ..ai.provider import AIProviderRequired

    try:
        cli()
    except AIProviderRequired as exc:
        # Gate AI-native (§3.4/ADR-0012): mensagem acionável, nunca stack trace.
        click.secho("\n✗ IA obrigatória — scan recusado.\n", fg="red", bold=True, err=True)
        click.secho(str(exc), fg="yellow", err=True)
        sys.exit(3)


def deprecated_alias() -> None:
    """Entry-point de transição do comando antigo ``vulnforge`` → ``eigan``.

    Emite um aviso de depreciação em stderr (não polui stdout/JSON de CI) e
    delega para a mesma CLI. Será removido numa versão futura.
    """
    click.echo(
        "aviso: 'vulnforge' foi renomeado para 'eigan'. Use o comando 'eigan'. "
        "Este alias será removido numa versão futura.",
        err=True,
    )
    cli()


if __name__ == "__main__":
    main()
