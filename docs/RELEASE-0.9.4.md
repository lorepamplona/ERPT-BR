## ERPT-BR 0.9.4 — instalação reativada

Esta versão corrige o incidente de áudio das versões 0.9.1 e 0.9.2 e volta a
instalar a dublagem no Elden Ring 1.17.1, Steam BuildID `25080141`.

### Download

Baixe somente **`ERPT-BR-v0.9.4-Windows.zip`**, extraia todo o conteúdo e dê
dois cliques em `ERPT-BR.cmd`. Não use os ZIPs automáticos **Source code** do
GitHub: eles não contêm o pacote completo.

### Correções e melhorias

- bancos Wwise reconstruídos sobre os bancos originais do jogo atual;
- cliques do menu, eventos e mídias introduzidos pelo jogo preservados;
- 8.969 WEMs e 272 aliases BNK autenticados, total de 9.241 arquivos;
- instalação, reinstalação e restauração transacionais verificadas;
- instalador de um clique em código-fonte, sem `.exe` próprio;
- detecção da pasta e do BuildID pela Steam;
- diagnóstico local com erro explícito e compartilhamento manual.

Payload interno: 588.468.447 bytes, SHA-256
`430e9693a9b3313826e9f7c890cf592eb5b468d145bb405e8a4586002b877680`.

### Online

A versão foi testada em uma sessão real iniciada normalmente pela Steam, com
Easy Anti-Cheat e conexão online ativos. Os sons de clique funcionaram e o jogo
permaneceu online durante o teste. O instalador não desativa nem modifica o EAC.

Limitação conhecida: o método modifica dados nos BDTs sem regravar ou reassinar
os índices BHD. Os 8.973 recursos modificados divergem dos hashes salted
originais; o instalador aceita somente as divergências exatas do plano e do
payload autenticados e recusa qualquer outra. O teste online não elimina essa
limitação técnica.

O resultado vale para a versão e a sessão testadas; não é uma garantia de risco
zero contra mudanças futuras no jogo, no EAC ou nas regras do serviço.

### Para quem instalou uma versão afetada

Use primeiro **Corrigir áudio (restaurar)**. Se não houver backup válido, faça a
verificação de integridade pela Steam. Depois de confirmar o áudio original,
instale a 0.9.4.

Não use 0.8.4, 0.9.1 ou 0.9.2 como fallback.
