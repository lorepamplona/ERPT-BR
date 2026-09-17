## ERPT-BR 0.9.5 — pacote plano para Windows

Esta versão mantém a correção de áudio para Elden Ring 1.17.1, Steam BuildID
`25080141`, e muda a estrutura do download para reduzir falsos positivos de
scanners automatizados.

### Download

Baixe somente **`ERPT-BR-v0.9.5-Windows.zip`**, extraia todo o conteúdo e dê
dois cliques em `ERPT-BR.cmd`. Não use os ZIPs automáticos **Source code** do
GitHub: eles não contêm o áudio nem as dependências completas.

### O que mudou

- um único download e uma única entrada para o usuário;
- áudio distribuído diretamente na pasta `patch_data`;
- remoção do ZIP grande que antes ficava aninhado dentro do download;
- sem `.exe` próprio do projeto e sem Mod Engine;
- interface, detecção da Steam e instalação guiada preservadas;
- inventário e SHA-256 canônico de toda a árvore de áudio conferidos antes da
  instalação;
- 8.969 WEMs e 272 aliases BNK, total de 9.241 arquivos autenticados.

A árvore de áudio possui 605.706.607 bytes e SHA-256 canônico
`8544e551832c929eecad0cf9898204fd673bd4a37a0a6f37433865afbb3556cb`.

### Áudio e modo online

O conteúdo é o mesmo payload corrigido e autenticado da 0.9.4. Ele preserva os
cliques do menu, eventos e mídias do Elden Ring 1.17.1 e foi validado em uma
sessão real iniciada normalmente pela Steam, com Easy Anti-Cheat e conexão
online ativos. A 0.9.5 altera a embalagem desse conteúdo, não o método aplicado
ao jogo.

O patcher não desativa nem modifica o EAC. Limitação conhecida: o método altera
dados nos BDTs sem regravar ou reassinar os índices BHD. Os 8.973 recursos
modificados divergem dos hashes salted originais; o instalador aceita somente
as divergências exatas do plano e do payload autenticados. O teste realizado
não é garantia de risco zero contra mudanças futuras no jogo, no EAC ou nas
regras do serviço.

### Para quem instalou 0.8.4, 0.9.1 ou 0.9.2

Use primeiro **Corrigir áudio (restaurar)**. Se não houver backup válido, faça
a verificação de integridade pela Steam. Confirme o áudio original e só então
instale a 0.9.5. Essas versões antigas não são um fallback seguro.
