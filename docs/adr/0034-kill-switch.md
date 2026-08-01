# ADR-0034 — Kill switch / parada de emergência

- **Status:** aceito
- **Data:** 2026-08-01
- **Contexto do roadmap:** §18.2

## Contexto

O `ScanManager` já tem cancelamento **cooperativo por evento** (`request_cancel` →
`ScanCancelled` no próximo `emit`). Isso é suficiente para parar entre ondas, mas **não
encerra uma ferramenta externa longa em execução** (um nmap de vários minutos seguiria
rodando até o próximo ponto de emissão). Um engajamento profissional precisa de uma
parada **imediata e segura**: se algo deu errado no alvo do cliente, para agora, com
limpeza — e o requisito vale tanto no CLI quanto na API.

## Decisão

Introduzir `eigan.engine.killswitch.KillSwitch`: um sinal thread-safe e compartilhável
(um mesmo objeto entre CLI e API). Ao ser acionado (`trigger(reason)`), ele:

1. registra **motivo** e **instante** (para a trilha §18.3);
2. executa os **cleanups** registrados — em particular `register_process(proc)`, que
   encerra a ferramenta com `terminate` → espera `grace` → `kill` (`terminate_process`);
3. faz os checkpoints cooperativos `check()` levantarem `ScanAborted`, para o engine
   persistir estado resume-safe (§12.1) e encerrar.

Fail-safe por design: o **primeiro** motivo vence, os cleanups rodam **uma única vez**
(idempotência garantida por `threading.Event` + lock), um cleanup que falhe **não**
impede os demais (melhor esforço para encerrar tudo), e um processo registrado **depois**
do trigger é encerrado na hora (registro tardio de ferramenta que subiu logo após).

O `terminate_process` opera sobre um `Terminable` (Protocol compatível com
`subprocess.Popen`), o que o torna testável com um processo falso — sem spawnar
processos reais no CI.

## Consequências

- **Positivas:** parada imediata e segura de ferramentas em execução, complementando o
  cancelamento cooperativo existente; thread-safe e compartilhável CLI+API; testável de
  forma determinística; motivo/instante prontos para a trilha (§18.3).
- **Custos/limites:** o *wiring* (o runner registrar seus `Popen` no switch, o engine
  chamar `check()` nos checkpoints, o CLI/API exporem o gatilho) é um incremento
  seguinte; este ADR entrega o primitivo. A persistência resume-safe em si é o §12.1.
- **Originalidade (P7):** implementação própria com primitivos stdlib
  (`threading`, `subprocess`); nenhum código de terceiro copiado.
