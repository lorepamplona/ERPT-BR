# Incidente de áudio nas versões 0.9.1 e 0.9.2

## Estado

**Resolvido na versão 0.9.4** para Elden Ring 1.17.1 (Steam BuildID
`25080141`). As versões 0.8.4, 0.9.1 e 0.9.2 continuam afetadas e não devem ser
usadas como fallback.

## Sintoma

Foram relatados sons ausentes na interface, incluindo cliques do menu, depois da
instalação da dublagem.

## O que fazer se uma versão afetada foi instalada

1. Feche Elden Ring e Easy Anti-Cheat.
2. Baixe e extraia `ERPT-BR-v0.9.4-Windows.zip`.
3. Abra `ERPT-BR.cmd` e clique em **Corrigir áudio (restaurar)**.
4. Se o backup não estiver disponível ou a restauração falhar, use **Steam >
   Elden Ring > Propriedades > Arquivos instalados > Verificar integridade dos
   arquivos**.
5. Confirme o áudio original e então use **Instalar dublagem** na versão 0.9.4.

## Diagnóstico técnico

A instalação auditada não sofreu uma falha aleatória de cópia: os 9.105 slots
gravados coincidiam com o plano do patcher e os bytes fora deles permaneceram
iguais ao backup. O problema estava no conteúdo antigo:

- as versões 0.9.1 e 0.9.2 reutilizavam o payload `v0.8.1`;
- `enus/cs_main.bnk` removia três mídias e 234 objetos HIRC presentes no banco
  original do Elden Ring 1.17.1;
- `enus/cs_m41.bnk` removia outras cinco mídias;
- os BNKs incompatíveis explicam a perda de cliques e de sons; as divergências
  de hash BHD, descritas abaixo, são uma limitação separada do método direto.

## Correção

Os 136 bancos físicos da 0.9.4 foram reconstruídos usando os bancos originais da
versão 1.17.1 como autoridade estrutural. Somente objetos e mídias de dublagem
compatíveis foram incorporados; eventos e sons atuais do jogo foram preservados.

O payload final passou por validação integral, duas compactações determinísticas,
instalação, reinstalação, comparação dos bytes fora dos slots e restauração. O
usuário responsável pelo teste real confirmou os sons de clique e uma sessão
online iniciada normalmente pela Steam com Easy Anti-Cheat ativo.

A 0.9.4 corrige o conteúdo dos BNKs, mas não regrava nem reassina os índices BHD.
Por isso, os 8.973 recursos modificados continuam divergindo dos hashes salted
originais. O patcher aceita somente esse conjunto exato de divergências, vinculado
ao payload autenticado e ao plano de instalação; qualquer divergência adicional
interrompe a operação. O teste online bem-sucedido não elimina essa limitação.

Esse teste documenta o ambiente verificado, mas não constitui garantia de risco
zero para futuras versões do jogo, do EAC ou das regras do serviço.
