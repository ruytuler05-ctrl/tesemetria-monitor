# Monitor externo do Tesemetria

[![Monitor externo](https://github.com/ruytuler05-ctrl/tesemetria-monitor/actions/workflows/monitor.yml/badge.svg)](https://github.com/ruytuler05-ctrl/tesemetria-monitor/actions/workflows/monitor.yml)

Monitor publico e independente da VPS de producao do
[Tesemetria](https://www.tesemetria.com.br).

## O que e verificado

- saude da aplicacao, conexao com PostgreSQL e release publicado;
- processamento assincrono e recuperacao externa operacionais;
- paginas publicas essenciais;
- HTTPS e validade dos certificados;
- dominio canonico `www.tesemetria.com.br`;
- redirecionamentos permanentes dos dominios anteriores;
- tempo de resposta de cada verificacao.

O monitor roda em um runner hospedado pelo GitHub a cada cinco minutos. Quando
detecta uma falha, abre ou atualiza uma issue publica neste repositorio. Depois
da recuperacao, encerra automaticamente o incidente.

O repositorio nao contem credenciais, tokens, codigo privado, dados financeiros
ou informacoes pessoais. A prova externa mais recente fica em
[`status/latest.json`](status/latest.json).

