# Monitor externo do Tesemetria

[![Monitor externo](https://github.com/ruytuler05-ctrl/tesemetria-monitor/actions/workflows/monitor.yml/badge.svg)](https://github.com/ruytuler05-ctrl/tesemetria-monitor/actions/workflows/monitor.yml)

Monitor publico executado em runner hospedado pelo GitHub e independente da VPS
de producao do [Tesemetria](https://www.tesemetria.com.br).

## O que e verificado

- resolucao DNS dos seis hostnames da marca;
- abertura TCP da porta 443, com limite de seis segundos;
- handshake TLS com SNI, cadeia confiavel e ao menos 30 dias de validade;
- HSTS por pelo menos um ano nas respostas HTTPS;
- saude da aplicacao, conexao com PostgreSQL e release publicado;
- processamento assincrono e recuperacao externa operacionais;
- paginas publicas essenciais e tempo de resposta;
- dominio canonico `www.tesemetria.com.br`;
- redirecionamentos permanentes dos dominios `.com.br`, `.com` e `.tech`.

O workflow e solicitado a cada cinco minutos, mas o agendamento do GitHub Actions
e de melhor esforco e pode atrasar em periodos de fila. Quando detecta uma
falha, abre ou atualiza uma issue publica com a etapa exata (`DNS`, `TCP`, `TLS`,
`HTTP` ou redirecionamento), o codigo de rede e o link da execucao externa.
Depois da recuperacao, encerra automaticamente o incidente.

O repositorio nao contem credenciais, tokens, codigo privado, dados financeiros
ou informacoes pessoais. O ultimo estado de cada transicao fica em
[`status/latest.json`](status/latest.json).
