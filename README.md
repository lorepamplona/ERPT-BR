# ERPT-BR — Elden Ring Dublagem PT-BR

Projeto de dublagem em Português Brasileiro para Elden Ring no PC.

> [!IMPORTANT]
> A versão **0.9.4** volta a instalar a dublagem no Elden Ring **1.17.1**
> (Steam BuildID `25080141`). Os bancos de áudio foram reconstruídos sobre os
> bancos originais dessa versão para preservar sons adicionados pelo jogo,
> inclusive os cliques da interface que desapareciam nas versões 0.9.1 e 0.9.2.

## Download correto

Na página [Releases](https://github.com/lorepamplona/ERPT-BR/releases), baixe
somente:

`ERPT-BR-v0.9.4-Windows.zip`

Esse é o pacote completo para o usuário: instalador em código-fonte,
dependências verificadas e payload de áudio. Não baixe os ZIPs automáticos
**Source code** do GitHub e não tente executar separadamente arquivos internos
do payload.

## Instalação no Windows

1. Feche Elden Ring e Easy Anti-Cheat.
2. Extraia **todo** o conteúdo de `ERPT-BR-v0.9.4-Windows.zip` para uma pasta
   normal.
3. Dê dois cliques em `ERPT-BR.cmd`.
4. Confirme a pasta `ELDEN RING\Game` detectada pela Steam ou selecione-a.
5. Clique em **Instalar dublagem** e aguarde a confirmação final.
6. Abra o jogo normalmente pela Steam.

O usuário vê uma única entrada: `ERPT-BR.cmd`. No primeiro uso, ela verifica o
pacote e prepara um ambiente isolado. Se necessário, instala o CPython 3.13.15
x64 oficial no perfil do usuário. Nos próximos usos, o mesmo arquivo abre a
interface sem refazer uma instalação válida.

Não execute o patcher como administrador. Se o Windows negar gravação, feche o
jogo e o EAC e use uma biblioteca Steam gravável pela sua conta ou ajuste
somente a permissão da pasta do jogo.

## Modo online

A correção 0.9.4 foi testada em uma sessão real iniciada normalmente pela Steam,
com Easy Anti-Cheat e conexão online ativos. O teste concluiu com sucesso e os
sons de clique permaneceram funcionando. O patcher não desativa nem modifica o
EAC, não injeta DLL e não muda a forma de iniciar o jogo.

O método direto altera dados dentro dos BDTs, mas não regrava nem reassina os
índices BHD. Assim, 8.973 recursos modificados não correspondem mais aos hashes
salted originais. O instalador aceita somente as divergências exatas do plano e
do payload autenticados; qualquer diferença adicional é recusada. A sessão
online bem-sucedida não remove essa limitação técnica.

Esse resultado comprova a versão e a sessão testadas; ele não representa
garantia de risco zero nem de compatibilidade com futuras atualizações do jogo,
do EAC ou das regras do serviço. Se a Steam atualizar o Elden Ring, restaure ou
verifique os arquivos e aguarde a confirmação de suporte ao novo BuildID.

## O que mudou na 0.9.4

- bancos Wwise reconstruídos usando a estrutura original do Elden Ring 1.17.1;
- mídias e eventos novos do jogo preservados durante a incorporação das falas;
- cliques de menu e demais sons originais ausentes no pacote antigo restaurados;
- instalação, reinstalação idempotente e restauração verificadas;
- validação do jogo repetida imediatamente antes de qualquer gravação;
- instalação de um clique sem executável próprio do projeto.

O payload autenticado contém 9.241 arquivos: 8.969 WEMs e 272 aliases BNK,
correspondentes a 136 bancos físicos reconstruídos. O ZIP interno possui
588.468.447 bytes e SHA-256
`430e9693a9b3313826e9f7c890cf592eb5b468d145bb405e8a4586002b877680`.

## Quem usou 0.9.1 ou 0.9.2

Essas versões substituíam bancos atuais por bancos antigos e podiam remover
cliques do menu e sons de cutscenes. A versão 0.8.4 usa o mesmo payload antigo e
não é um fallback seguro.

Antes de instalar a 0.9.4:

1. Abra o pacote atual e use **Corrigir áudio (restaurar)** se existir um backup
   transacional válido.
2. Se a restauração não estiver disponível ou falhar, use **Steam > Elden Ring >
   Propriedades > Arquivos instalados > Verificar integridade**.
3. Confirme o áudio original e então instale a 0.9.4.

Consulte também a [migração do executável antigo](MIGRACAO.md) e o
[relatório do incidente](docs/INCIDENTE-0.9.1.md).

## Diagnóstico de compatibilidade e travamentos

Uma versão fora do alvo, como a 1.17.0, não fica parecendo uma instalação
parada. O patcher mostra o BuildID encontrado, o BuildID suportado, a etapa em
que interrompeu e um código estável como `ERPT-COMPAT-001`. A recusa acontece
antes de carregar ou alterar o áudio.

O botão **Diagnóstico** gera localmente um relatório JSON com versão do patcher,
BuildID identificado, etapa, tempo, progresso, sistema e registros recentes. O
relatório não inclui intencionalmente nome do usuário, pasta completa, SteamID,
saves ou conteúdo do manifesto, e não abre nem calcula hash dos arquivos do
jogo. Ainda assim, revise o conteúdo antes de publicá-lo.

Nada é enviado automaticamente. O botão **Abrir chamado** apenas copia o
diagnóstico e abre o
[formulário de compatibilidade](https://github.com/lorepamplona/ERPT-BR/issues/new?template=compatibilidade.yml);
o envio continua manual e a issue será pública.

## Backup, restauração e atualizações

O backup fica em `%LOCALAPPDATA%\ERPT-BR\backups` e é vinculado ao fingerprint
do BHD e ao BuildID do jogo. O patcher autentica o backup, prepara cópias
temporárias, registra um journal transacional e relê o resultado antes de
anunciar sucesso. Um backup de outro build nunca é restaurado sobre o jogo
atual.

Restaure o áudio original antes de mover ou renomear a biblioteca Steam. Use a
mesma conta do Windows para instalar e restaurar. Em caso de atualização do
jogo, faça a verificação de integridade da Steam e aguarde uma versão do ERPT-BR
que reconheça o novo BuildID.

Arquivos de transação interrompida são preservados para diagnóstico; o programa
não apaga recursivamente um caminho que possa ter sido substituído por link ou
junction.

## Limites atuais

- Windows x64 e versão Steam do Elden Ring;
- Elden Ring 1.17.1, Steam BuildID `25080141`;
- áudio WEM/BNK; o pacote opcional antigo de cutscenes `.bk2` continua recusado
  por não possuir manifesto criptográfico público;
- futuras versões do jogo precisam de validação e release específicos.

## Desenvolvimento e testes

```text
python -m pip install --require-hashes --only-binary=:all: -r patcher/requirements-win64.lock
python -m unittest discover -s tests -v
```

O CI rejeita launcher dinâmico, `exec(compile(...))`, `taskkill` e builds
PyInstaller/Nuitka. Releases são montados por lista permitida, com SHA-256 e
atestado de proveniência registrados pelo GitHub.

Relatos e código: [GitHub](https://github.com/lorepamplona/ERPT-BR)

Página do mod: [Nexus Mods](https://www.nexusmods.com/eldenring/mods/4295)

## Licença

[MIT](LICENSE)
