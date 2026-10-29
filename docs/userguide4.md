# Banda, Economia e Reputação

**HDAP v1.001 — Themelio · Epoptia**

**Escrito por Thaís (op3n/op3ny)**

---

**Leia primeiro:** [userguide3.md](userguide3.md) (Arquivos, Documentos e Permissões)
**Próximo:** [userguide5.md](userguide5.md) (Federação, Réplicas e Sucessão)

---

## Por que existe banda

Guardar e servir arquivos custa dinheiro. Disco, energia, rede e o tempo de quem opera um servidor não são gratuitos, e um sistema que finge que são acaba sustentado por alguém que se cansa ou por um modelo de negócio que cobra de outro jeito. O HDAP escolhe dizer isso com clareza: armazenar e servir consome um recurso escasso, a **banda**, e esse recurso é contabilizado.

A palavra não significa apenas tráfego de rede. Ela designa a capacidade de publicar e manter conteúdo em um pyle. Cada upload consome banda; cada cópia replicada também. O consumo é medido e registrado, e o registro é público. O operador não inventa um número no fim do mês; o protocolo define como a banda é gerada, quanto custa e como ela circula.

A banda resolve dois problemas ao mesmo tempo, e é útil enxergá-los separados. O primeiro é o custo real de armazenamento: sem um preço, o serviço é gratuito no ponto de uso e insustentável no ponto de operação. O segundo é o problema de Sybil: se criar uma identidade fosse gratuito e ilimitado, um atacante poderia criar milhares de contas e inundar a rede com conteúdo inútil. A banda encarece a criação de identidades e o abuso, sem impedir o uso legítimo.

Há ainda um terceiro efeito, menos óbvio e mais interessante: a banda dá aos operadores um motivo econômico para manter o conteúdo disponível. Um nó que serve bem ganha banda e reputação; um nó que some perde as duas coisas. A economia não é um apêndice do protocolo, é parte do mecanismo de disponibilidade.

---

## De onde vem a banda

A banda nasce de dois lugares. O primeiro é o **faucet** do operador, uma concessão inicial que o pyle faz a novas identidades para que elas possam começar. O segundo é a **prova de trabalho**, que qualquer pessoa pode resolver e que gera banda a uma taxa definida pelo operador. Os dois caminhos existem para que a rede não dependa de um único mecanismo de entrada.

O faucet é a porta de entrada. Quando você se registra, o pyle pode creditar uma quantidade inicial de banda, suficiente para os primeiros uploads e para as primeiras operações. Esse crédito é uma decisão do operador, registrada no `timi` e limitada por parâmetros do protocolo. Ele não é uma promessa de banda infinita; é um empurrão inicial para que a identidade comece a funcionar.

A prova de trabalho é o caminho sustentável. O cliente calcula um hash com um nonce escolhido até encontrar um valor abaixo de um alvo, e publica o resultado em um documento `mochthos`. O pyle verifica o hash, confere se o desafio é atual e se o resultado é válido, e credita a banda correspondente. Como o trabalho custa energia, ele limita a criação de banda em massa sem exigir que o operador conheça a pessoa.

O equilíbrio entre faucet e prova de trabalho é ajustável. Um operador que quer atrair usuários pode ser generoso no faucet; um operador que sofre abuso pode aumentar a dificuldade da prova ou reduzir o faucet. Os parâmetros ficam públicos no `timi`, e o cliente mostra a taxa antes de você decidir resolver ou não. Não há letras miúdas: o que a rede cobra está escrito.

---

## O `mochthos` e o `syngraphe`

Dois documentos materializam a economia. O **`mochthos`** é a prova de trabalho: registra o desafio, o nonce, o hash resultante e a banda creditada. O **`syngraphe`** é o tratado de consumo: registra a operação de upload, o hash do conteúdo, a banda gasta e a assinatura do dono. Um gera banda; o outro a gasta.

Essa separação tem uma consequência prática agradável. Você pode resolver prova de trabalho quando quiser e acumular banda, e só depois usá-la para publicar. A banda é um saldo, não uma promessa de uso imediato. Se você não tiver saldo no momento do upload, o cliente tenta resolver a prova automaticamente, e o pyle sabe que pode cobrar mais por isso. O `syngraphe` que acompanha o upload é o recibo dessa operação.

O preço da banda não é fixo entre pyles. Cada operador publica sua tabela no `timi`, e o cliente pode comparar. Essa comparação é o que dá sentido à Federação: se um pyle cobra caro demais ou serve mal, você pode mover a sua casa para outro, levando a identidade e, conforme as permissões, o conteúdo. O mercado de operadores é real, ainda que discreto.

---

## O `timi` e a tabela de preços

O **`timi.hdap`** é o documento que publica os parâmetros econômicos do pyle. Ele contém o preço por unidade de banda, o tamanho do faucet inicial, a dificuldade da prova de trabalho, a cota de armazenamento por usuário (`moira`) e os limites de upload. É um documento público, assinado pelo operador, e é a fonte da verdade para qualquer cálculo de custo.

Como todo documento do protocolo, o `timi` é versionado por edição. Mudanças de preço são edições assinadas, com histórico verificável. Isso importa porque ninguém quer descobrir no meio do mês que o preço do armazenamento triplicou sem registro. Você pode auditar quando o preço mudou, quanto mudou e quem assinou a mudança.

O `timi` também define a `moira`, a cota de armazenamento por identidade. Diferente da banda, que é um saldo que se gasta, a `moira` é um limite de espaço ocupado. Um pyle pode ter uma `moira` generosa e uma banda cara, ou o contrário. Os dois mecanismos coexistem porque medem coisas diferentes: banda é o custo de publicar e servir; `moira` é o custo de ocupar disco.

---

## O que acontece quando a banda acaba

Se a banda acabar no meio de um upload, o pyle recusa a operação com um erro claro. Não há degradação silenciosa nem "quase gravado": ou a operação inteira é autorizada e persistida, ou nada acontece. Essa atomicidade é uma escolha de projeto que evita estados meio-verdadeiros, nos quais o cliente acha que publicou e o servidor tem um blob órfão.

Se o saldo estiver baixo, você tem três caminhos. Pode resolver mais prova de trabalho, o que aumenta o saldo ao custo de energia. Pode pedir banda a outra identidade, se o pyle permitir transferências entre contas. Ou pode mudar de casa para um pyle com preço melhor, levando o que tem. Os três caminhos são legítimos, e nenhum exige permissão de uma autoridade central.

O que não existe é banda infinita. Um sistema que promete armazenamento ilimitado e gratuito está escondendo o custo em outro lugar, geralmente na venda dos seus dados ou no encerramento abrupto do serviço. O HDAP prefere cobrar de forma transparente a prometer o impossível.

---

## Reputação: os sinais `pheme`

A economia mede recurso; a reputação mede confiança. Elas são relacionadas mas não idênticas. Um nó pode ser rico em banda e pobre em reputação, ou o contrário. O HDAP mantém os dois sinais separados de propósito, porque dinheiro não compra confiança e confiança não paga disco.

Os sinais de reputação são chamados de **`pheme`**. Um sinal é uma afirmação assinada sobre a qualidade de um pyle ou de uma identidade: um elogio, uma reclamação, um registro de disponibilidade ou uma nota de comportamento. Os sinais são públicos e associados a quem os emitiu, de modo que a opinião de uma identidade com histórico vale mais do que a de uma recém-criada.

O documento que carrega um sinal é o **`pheme_candidate`**. Ele registra o alvo, o delta de reputação, a razão e uma lista de evidências, como hashes de documentos ou de arquivos que sustentam a afirmação. O nó que recebe o candidato verifica as assinaturas e as evidências antes de aplicar o delta. Um identificador de operação impede que a mesma atualização seja aplicada duas vezes, mesmo que ela chegue por caminhos diferentes da federação.

A reputação não é um número mágico que resolve todos os problemas. Ela é um sinal, e sinais podem ser manipulados, especialmente por identidades criadas em massa. Por isso o protocolo combina a reputação com a prova de trabalho e com a idade da identidade, e trata o valor acumulado como uma informação a ser lida com contexto, não como um veredito. O cliente mostra a origem dos sinais em vez de um número opaco, e você pode discordar de um sinal consultando as evidências que o acompanham.

---

## Espaço, cota e preço

O espaço em um nó não é infinito, e o protocolo não finge que seja. Cada pyle publica no `timi` a sua cota por identidade (`moira`), o preço da banda e os limites de upload. Quando a cota de uma identidade se esgota, o nó recusa novas gravações com um erro claro. Quando o disco do nó se aproxima do limite, o operador precisa decidir como continuar: aumentar a capacidade, rever a cota ou encerrar o serviço para novos usuários.

O HDAP não esconde essa decisão atrás de um algoritmo de leilão que o operador pode contornar. A escolha de quem fica e quem sai é do operador, mas ela é limitada por dois fatos verificáveis: a cota publicada e o preço publicado. Se o operador muda a cota ou o preço, a mudança é uma nova edição do `timi`, assinada e registrada. Você pode comparar o antes e o depois, e pode mudar de pyle se a nova política não lhe serve.

Se o seu conteúdo não cabe na cota de um nó, você não perde os bytes. Eles continuam na sua posse, podem ser replicados em outro pyle ou mantidos localmente. O que se perde é o espaço naquele nó específico, não o arquivo. Essa distinção é importante: o protocolo garante a posse e a prova, não a hospedagem gratuita em um lugar específico.

---

## Federação de pagamento entre pyles

Quando você usa um pyle que não é o seu, ou quando uma réplica serve conteúdo de outra casa, a banda precisa circular entre operadores. O HDAP permite que pyles se paguem mutuamente por meio de tratados e de transferências de banda, sempre com documentos assinados. Não há uma câmara de compensação central; há acordos bilaterais registrados e verificáveis.

Esse desenho tem a vantagem de não exigir uma moeda global nem uma autoridade monetária. Cada par de operadores pode acordar as suas condições, e o protocolo apenas registra e verifica. A desvantagem é que a liquidez é fragmentada: um pyle pode ter crédito com outro e não conseguir usá-lo com um terceiro. O modelo é mais parecido com uma rede de correspondentes do que com um banco central, e isso é uma escolha deliberada de descentralização.

Para o usuário comum, isso raramente aparece. Você vê o preço do seu pyle, paga em banda e pronto. A federação de pagamento é um assunto de operadores, e está documentada no guia de execução e no modelo econômico. Mencionamos aqui porque é honesto dizer que a economia tem várias camadas, e que a camada visível é só a ponta.

---

## Termos importantes

| Termo | Definição simples |
|---|---|
| **banda** | Recurso escasso que mede a capacidade de publicar e manter conteúdo. |
| **faucet** | Crédito inicial de banda dado pelo pyle a novas identidades. |
| **prova de trabalho** | Cálculo custoso que gera banda de forma sustentável. |
| **`mochthos`** | Documento que registra a prova de trabalho e a banda creditada. |
| **`syngraphe`** | Tratado que registra o consumo de banda em um upload. |
| **`timi`** | Tabela pública de preços e parâmetros econômicos do pyle. |
| **`moira`** | Cota de armazenamento por identidade. |
| **`pheme`** | Sinal assinado de reputação. |
| **`pheme_candidate`** | Documento que propõe um delta de reputação com evidências. |

---

## Perguntas frequentes

**Preciso pagar para usar o HDAP?** Depende do pyle. O faucet inicial pode ser suficiente para começar, e a prova de trabalho permite gerar mais banda sem dinheiro. Operadores podem cobrar, e o preço está no `timi`.

**A prova de trabalho gasta muita energia?** O custo é ajustável pelo operador e pelo seu hardware. O cliente mostra a dificuldade antes de começar, e você pode recusar. Não há mineração contínua: você resolve quando precisa de banda.

**Minha banda expira?** Os parâmetros de expiração ficam no `timi`. Saldos antigos podem ser reduzidos conforme a política do pyle, e o cliente mostra o prazo. Não há surpresa escondida no rodapé.

**Posso transferir banda para outra pessoa?** Se o pyle permitir, sim, com um documento assinado. A transferência é registrada e auditável.

**A reputação pode ser comprada?** Sinais podem ser emitidos, mas a ponderação considera idade e histórico, e sinais isolados valem pouco. Não há garantia matemática contra manipulação; há custo e transparência.

**O operador pode liberar o espaço do meu arquivo?** Pode deixar de hospedá-lo, respeitando a política publicada no `timi` e a cota vigente. O arquivo continua seu, com a mesma assinatura e o mesmo hash, e pode ir para outro pyle. Você não perde a posse.

**O que é a `moira`?** É o limite de espaço que a sua identidade pode ocupar naquele pyle, separado do saldo de banda.

**Se eu mudar de pyle, perco a banda?** A banda é local ao pyle. Mudar de casa não transfere automaticamente o saldo. Planeje a migração com antecedência.

---

**Leia agora:** [userguide5.md](userguide5.md) — Federação, Réplicas e Sucessão
