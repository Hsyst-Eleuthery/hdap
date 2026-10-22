# Federação, Réplicas e Sucessão

**HDAP v1.0 — Themelio · Veritas Aeterna**

**Escrito por Thaís (op3n/op3ny)**

---

**Leia primeiro:** [userguide4.md](userguide4.md) (Banda, Economia e Reputação)
**Próximo:** [userguide6.md](userguide6.md) (Aplicativos e Operação)

---

## O que significa ser descentralizado de verdade

Muitos sistemas se dizem descentralizados porque têm vários servidores. Mas se todos obedecem a uma mesma empresa, um mesmo banco de dados ou uma mesma chave de administração, a descentralização é apenas geográfica: o controle continua em um lugar só. O HDAP tenta algo mais difícil. Cada pyle é um nó independente, com o seu próprio disco, as suas próprias chaves e a sua própria autoridade sobre as sessões que emite. Não existe um servidor mestre, um banco central de identidades nem uma senha que abra todos os nós.

Isso não significa que os nós sejam ilhas. Eles conversam, trocam digests, replicam conteúdo e convergem para o mesmo estado. A diferença é que a convergência acontece por acordo verificável, não por obediência a um coordenador. Dois pyles podem discordar por alguns segundos, e a rede não quebra; eles se sincronizam e voltam ao mesmo ponto. Essa tolerância à divergência temporária é o que torna a federação robusta.

A federação também é assimétrica em relação ao poder. Um operador pode recusar conteúdo, pode cobrar caro, pode desligar o servidor. O que ele não pode é falsificar uma assinatura, apagar a história de outro nó ou impedir que você leve a sua identidade para outro lugar. O poder de cada operador é real, mas é local e limitado. É exatamente o oposto de uma plataforma central, em que o poder é global e ilimitado.

---

## O livro global e a bolha

Para que os nós concordem, eles precisam de uma memória comum que não dependa de confiança cega. O HDAP mantém um **livro global** de documentos públicos, uma lista ordenada e assinada de tudo o que aconteceu na rede. Cada nó guarda a sua visão do livro e troca digests com os pares para descobrir o que está faltando.

A sincronização usa um mecanismo chamado **bolha**. Periodicamente, o nó calcula um digest do seu estado e o compara com o dos vizinhos. Se os digests são iguais, não há nada a fazer. Se divergem, o nó pede os documentos que faltam e aplica. O nome "bolha" vem da ideia de que a diferença entre duas visões é uma bolha de divergência que se propaga e se resolve quando os estados se encontram.

O merge é **idempotente**: aplicar o mesmo documento duas vezes tem o mesmo efeito que aplicar uma vez. Isso é essencial em uma rede com quedas, retransmissões e mensagens fora de ordem. Sem idempotência, uma simples repetição poderia duplicar uma permissão ou corromper um contador. Com ela, o nó pode reaplicar sem medo e convergir para o mesmo resultado.

A bolha também é o que permite que um nó entre na rede depois de ficar offline por muito tempo. Ele não precisa baixar tudo de novo nem confiar em um snapshot de um terceiro: ele pede os documentos que faltam, verifica as assinaturas e reconstrói o estado. A história é a fonte da verdade, e qualquer nó pode reconstruí-la a partir dos documentos assinados.

---

## Réplicas: cópias que sobrevivem à queda

Uma réplica é uma cópia de um conteúdo em outro pyle, autorizada pelo dono. Ela existe para que a queda de um servidor não signifique a perda do arquivo, e para que leitores distantes possam baixar de um nó mais próximo. A réplica não é um backup secreto nem uma cópia não autorizada: é uma operação registrada e verificável.

Para replicar, o dono edita a `adeia` com uma diretiva `REPLICA=<id-do-pyle-destino>`. O pyle de destino precisa permitir réplicas de terceiros, o que ele declara no `timi`. Quando as duas condições se encontram, o conteúdo é copiado, verificado por hash e assinatura, e registrado na matriz de origem. A partir daí, o destino pode servir leituras, mas não pode alterar nem apagar o conteúdo original.

O destino precisa de `read` sobre o conteúdo para poder servi-lo. Isso parece óbvio, mas é uma fonte comum de confusão: uma réplica autorizada sem permissão de leitura falha, e o erro nem sempre é claro. Se você está configurando réplicas, confira as duas pontas: a diretiva no pyle de origem e a permissão de leitura para a identidade do pyle de destino.

Quando o dono apaga um arquivo, as réplicas são notificadas e devem remover a cópia. O registro da deleção é um **tombstone**, uma lápide assinada que impede que uma réplica antiga ressuscite o conteúdo. Um nó que se recusa a apagar pode ser penalizado reputacionalmente e tem a divergência registrada, mas o protocolo não invade o disco de ninguém. Essa é uma limitação honesta: a federação não tem polícia, tem transparência.

---

## Transferência de posse

Às vezes você quer passar um arquivo para outra pessoa de forma definitiva. Não é uma cópia, é uma cessão: o novo dono passa a controlar o conteúdo, e você perde a escrita sobre ele. No HDAP, isso é feito com o documento **`metabibasis`**, que registra a oferta e o aceite.

O fluxo tem três passos. Primeiro, o dono propõe a transferência, assinando uma oferta com o hash do conteúdo e o ID do destinatário. Segundo, o destinatário aceita, assinando o aceite. Terceiro, o pyle verifica as duas assinaturas, atualiza a posse e grava uma **cessão** (`ceession`). A cessão é a parte mais importante, porque ela garante que o cedente mantém `read` irrevogável sobre o que cedeu, mesmo que a `adeia` mude depois.

Por que o cedente mantém leitura? Porque a transferência não deve ser uma forma de apagar o passado. Se você publicou um documento e depois o cedeu, faz sentido que você ainda possa consultá-lo, mas não alterá-lo. A cessão torna isso um fato gravado, não uma promessa que a próxima edição da `adeia` pode desfazer.

A transferência é irreversível do ponto de vista do cedente. Uma vez aceita, a escrita pertence ao novo dono. Se você se arrepender, o caminho é pedir que o novo dono transfira de volta, o que depende da boa vontade dele. O protocolo garante o direito, não o arrependimento. Por isso a interface pede confirmação explícita e mostra o hash e o destinatário antes de assinar.

---

## Sucessão: quando o operador desaparece

O cenário mais delicado de qualquer sistema descentralizado é a morte do operador. Se o pyle desaparece e ninguém pode assumir a casa, os arquivos ficam inacessíveis, mesmo que existam réplicas. O HDAP trata isso com um mecanismo de sucessão chamado **`diadosi`**, uma procuração assinada que indica quem pode assumir a casa se o pyle original sumir.

A procuração nomeia um **fallback** e fixa os hashes das edições vigentes de `adeia` e `prosopeion`. Quando o pyle original fica indisponível por tempo suficiente, o fallback assume com uma prova de vida. A prova de vida é uma declaração assinada de que o pyle original está fora do ar; ela é verificada por outros nós e registrada publicamente. Não é uma decisão unilateral do fallback.

O detalhe dos hashes é o que impede o abuso. Se o fallback pudesse usar uma procuração antiga depois de você editar as permissões, ele ressuscitaria um estado que você já revogou. Ao fixar os hashes, a procuração vale apenas para o estado que você aprovou. Qualquer edição posterior exige uma nova procuração, o que mantém o controle nas suas mãos.

A sucessão não é automática nem instantânea. Ela exige que o fallback esteja configurado, que a prova de vida seja verificável e que os pares aceitem a mudança. Se você não configurar um fallback, a casa não tem sucessor, e a recuperação depende de réplicas e de uma nova identidade. O guia recomenda configurar a sucessão no primeiro dia, não no dia em que o servidor cai.

---

## Portabilidade: mudar de casa sem perder a identidade

A identidade é global; a casa é local. Essa frase resume a portabilidade do HDAP. Você pode registrar a mesma identidade em outro pyle e continuar sendo você, com o mesmo ID, as mesmas chaves e o mesmo histórico de assinaturas. O que muda é o endereço onde a casa está apoiada.

A mudança é feita com uma mensagem assinada que aponta o novo pyle. Não é necessário recuperar a chave nem pedir permissão ao pyle antigo para que ele esteja no ar. Se o pyle antigo estiver fora, melhor ainda: a mensagem prova que a decisão é sua, e o novo pyle pode aceitá-la. A continuidade da identidade é garantida pela assinatura, não pela disponibilidade do servidor.

Os arquivos não são teleportados. O que muda é a autoridade; o conteúdo precisa ser replicado ou reenviado conforme as permissões. Na prática, você planeja a migração: replica o que puder, verifica os hashes, publica a nova casa e só então desativa a antiga. O guia de execução traz o passo a passo operacional, e a GUI mostra o status de cada etapa.

---

## O que a federação não promete

É tão importante dizer o que a federação não faz quanto dizer o que ela faz. Ela não garante que todos os nós estarão no ar o tempo todo. Ela não impede que um operador mal-intencionado leia o conteúdo que serve, porque o servidor precisa decifrar para entregar. Ela não obriga ninguém a hospedar o seu conteúdo. E ela não resolve o problema de quem não tem réplicas nem fallback: nesse caso, a queda do pyle é uma perda real.

O que ela promete é mais modesto e mais útil. Promete que nenhum operador pode falsificar a sua assinatura. Promete que o conteúdo é verificável por hash. Promete que você pode levar a identidade para outro lugar. Promete que a história é auditável e que a divergência é registrada. Promete, em suma, que o poder de cada nó é local e que a sua soberania não depende da boa vontade de um único servidor.

---

## Termos importantes

| Termo | Definição simples |
|---|---|
| **livro global** | Memória comum de documentos públicos, assinada e ordenada. |
| **bolha** | Mecanismo de troca de digests que resolve divergências. |
| **digest** | Resumo do estado usado para comparar visões. |
| **réplica** | Cópia autorizada de um conteúdo em outro pyle. |
| **tombstone** | Registro assinado de deleção que impede ressurreição. |
| **`metabibasis`** | Documento de oferta e aceite de transferência de posse. |
| **`ceession`** | Cessão irrevogável de leitura ao cedente. |
| **`diadosi`** | Procuração de sucessão da casa. |
| **fallback** | Identidade autorizada a assumir a casa. |
| **prova de vida** | Declaração verificável de que o pyle original está fora do ar. |

---

## Perguntas frequentes

**Preciso de réplicas para estar seguro?** Para conteúdo importante, sim. Réplicas protegem contra a queda de um nó. Sem elas, a disponibilidade depende de um único servidor.

**Uma réplica pode alterar meu arquivo?** Não. Ela serve leitura, mas não tem `write` sobre o original. O hash e a assinatura detectariam qualquer alteração.

**O que acontece se o pyle cair para sempre?** Se houver fallback configurado, ele assume com prova de vida. Se houver réplicas, o conteúdo pode ser recuperado. Se não houver nenhum dos dois, a casa se perde, mas a identidade continua sua.

**Posso mudar de pyle sem avisar o antigo?** Sim. A mensagem assinada prova que a decisão é sua, e o novo pyle pode aceitá-la independentemente do antigo.

**A federação é uma blockchain?** Não. Não há consenso global por mineração nem uma cadeia única de blocos. Há um livro de documentos assinados, sincronizado por digests, e a convergência é idempotente.

**Quem paga pelas réplicas?** O dono do conteúdo, em banda, conforme o `timi` do pyle de destino. Réplica não é gratuita para ninguém.

**Posso recusar uma réplica?** Sim. A diretiva `REPLICA` é sua, e o pyle de destino também pode recusar. A réplica exige consentimento dos dois lados.

**O que impede um pyle de mentir sobre ter o conteúdo?** A verificação por hash e assinatura no momento da leitura. Um nó que mente falha na verificação e perde reputação.

---

**Leia agora:** [userguide6.md](userguide6.md) — Aplicativos e Operação
