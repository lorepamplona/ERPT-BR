# Política de segurança

## Modelo de distribuição

- O projeto não publica executável próprio.
- O único download destinado ao usuário é
  `ERPT-BR-v0.9.4-Windows.zip`. Ele contém o código-fonte do patcher, scripts
  `.cmd` transparentes, dependências travadas e o payload de áudio autenticado.
- Os ZIPs automáticos **Source code** do GitHub não são instaladores e não
  contêm o pacote completo.
- O PyCryptodome inclui código nativo verificado, mas nada é copiado ou injetado
  como DLL no jogo.
- A etapa interna `interno/INSTALAR_AMBIENTE.cmd` prepara o ambiente usando
  somente os wheels incluídos e verificados. Não existe `exec`, `eval` ou
  download de código Python a partir de `main`.
- A única entrada pública, `ERPT-BR.cmd`, pode instalar exatamente o Python
  3.13.15 x64 oficial no perfil do usuário. Ela tenta primeiro o pacote
  `Python.Python.3.13`, versão `3.13.15`, fonte `winget`, escopo `user` e
  arquitetura `x64`, sem ignorar a verificação de hash do WinGet.
- Somente quando o WinGet está ausente, o bootstrap baixa o instalador oficial
  de `python.org`. Antes de executá-lo, exige 29.452.944 bytes, SHA-256
  `edec09c4853aeae9ac36efb8c9f95b6b8e2fee65eee56d9767a8b7c69c574403`,
  assinatura Authenticode válida e o publicador Python Software Foundation.
- O Python é instalado no perfil atual, não é adicionado ao `PATH` e não há
  tentativa de autoelevação. O executável oficial não é incluído no ZIP do mod.

## Integridade do payload 0.9.4

O payload foi reconstruído sobre os bancos originais do Elden Ring 1.17.1,
Steam BuildID `25080141`. O patcher valida antes do uso:

- nome interno: `patch_data_v094.zip`;
- tamanho: `588468447` bytes;
- SHA-256: `430e9693a9b3313826e9f7c890cf592eb5b468d145bb405e8a4586002b877680`;
- SHA-256 canônico da árvore:
  `8544e551832c929eecad0cf9898204fd673bd4a37a0a6f37433865afbb3556cb`;
- inventário: 8.969 WEMs e 272 aliases BNK, total de 9.241 arquivos;
- tamanho descompactado: `605706607` bytes;
- maior arquivo: `74956066` bytes.

Qualquer diferença de tamanho, hash, estrutura, inventário ou caminho faz o
patcher recusar o payload antes de escrever no jogo.

## Easy Anti-Cheat e modo online

O patcher não usa Mod Engine 3, não inicia Elden Ring, não injeta bibliotecas,
não altera o Easy Anti-Cheat e não muda a forma de iniciar o jogo pela Steam. A
versão 0.9.4 foi validada em uma sessão real com EAC e conexão online ativos.

Os dados modificados nos BDTs não são acompanhados de regravação ou reassinatura
dos índices BHD. Consequentemente, 8.973 recursos deixam de corresponder aos
hashes salted originais. No modo de produção, o patcher permite apenas essas
divergências quando elas pertencem exatamente aos slots do plano autenticado;
uma divergência fora desse escopo interrompe a instalação. O teste online não
transforma essa limitação em garantia de compatibilidade ou de ausência de risco.

Um teste bem-sucedido não equivale a garantia permanente de risco zero. Uma
atualização do jogo, do EAC ou das regras do serviço pode mudar o resultado. O
suporte é limitado ao jogo e BuildID declarados no release.

## Integridade do release

Cada release desta linha publica um único ZIP próprio destinado ao usuário. O
GitHub registra o digest SHA-256 do asset e gera um atestado de proveniência pelo
GitHub Actions. Para verificar o pacote com a CLI do GitHub:

```text
gh attestation verify ERPT-BR-v0.9.4-Windows.zip --repo lorepamplona/ERPT-BR
```

O workflow usa dependências travadas por SHA de commit e não deve sobrescrever
um asset de release existente. O hash final do pacote Windows é publicado
somente depois de sua montagem e verificação.

## Dados locais e privacidade

O programa não coleta telemetria nem envia arquivos do usuário. O payload de
áudio acompanha o pacote completo e é validado localmente. O bootstrap pode
acessar WinGet ou `python.org` para instalar o Python oficial.

Os botões **Detalhes** e **Abrir chamado** só pedem ao navegador padrão que abra
o GitHub depois de um clique explícito. O diagnóstico é processado localmente,
usa uma lista fechada de campos e remove padrões conhecidos de caminhos,
identidades, e-mails, SteamID e segredos. Ele não abre, enumera nem calcula hash
dos arquivos do jogo. O usuário deve revisar e enviar o conteúdo manualmente.

Backups, ambientes isolados e cache ficam no perfil local. Árvores abandonadas
ou transações interrompidas são preservadas e reportadas; o programa não tenta
exclusão recursiva por um caminho que possa ter sido trocado por junction ou
outro reparse point.

Esses controles partem de uma sessão normal do Windows, sem outro processo
malicioso já executando como o mesmo usuário. Um processo com essa autoridade já
poderia alterar o fonte extraído, o ambiente local, os backups e o jogo.

## Reportar vulnerabilidade

Não publique detalhes exploráveis em uma issue. Use **Security > Report a
vulnerability** no repositório quando disponível ou entre em contato
privadamente com o mantenedor listado no perfil do projeto.
