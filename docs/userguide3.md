# Arquivos, Documentos e Permissões

**HDAP v1.0 — Themelio · Veritas Aeterna**

**Escrito por Thaís (op3n/op3ny)**

---

**Leia primeiro:** [userguide2.md](userguide2.md) (Identidade e a Casa)
**Próximo:** [userguide4.md](userguide4.md) (Banda, Economia e Reputação)

---

## O que é um arquivo no HDAP

Em uma nuvem comum, um arquivo é uma linha em um banco de dados: um nome, um dono, uma data e um ponteiro para os bytes. Quando você pede o arquivo, o sistema olha a linha, confere se você tem permissão e entrega o conteúdo. Tudo depende de o banco estar correto e de o operador ser honesto. Se a linha for alterada, o arquivo muda; se o dono for trocado, a autoria muda; se o ponteiro for apagado, o arquivo some, mesmo que os bytes ainda existam em algum lugar.

No HDAP, um arquivo é definido por três fatos independentes, e nenhum deles depende da palavra do operador. O primeiro é o **hash**: uma impressão digital calculada sobre os bytes do conteúdo. O segundo é a **assinatura**: uma prova de quem publicou aqueles bytes. O terceiro é a **história**: um registro de onde o arquivo nasceu e quais cópias existem. O nome do arquivo é apenas uma conveniência de navegação; ele não identifica o conteúdo e não concede nada.

Essa separação é o que permite que o HDAP seja verificável. Você pode receber um arquivo de um nó que não confia, calcular o hash e comparar com o que foi assinado. Você pode receber uma cópia de um réplica e verificar a assinatura da origem. Você pode consultar a história e saber se aquela cópia veio de onde diz vir. O nome pode ser igual ao de outro arquivo, mas o hash e a assinatura não deixam dúvida.

Tudo o mais no protocolo existe para proteger esses três fatos. A identidade protege a assinatura. As permissões protegem o acesso. A banda protege o recurso de quem guarda. A replicação protege o arquivo contra a queda de um servidor. A transferência de posse e a sucessão de casa protegem você contra o desaparecimento do operador. Se você entender hash, assinatura e história, entenderá a espinha dorsal de todo o resto.

---

## Hash: o endereço que vem do conteúdo

O hash é calculado com SHA-256 sobre os bytes crus do arquivo. O resultado é uma sequência hexadecimal de 64 caracteres, e é o endereço lógico do conteúdo. Dois arquivos iguais, publicados por pessoas diferentes, compartilham o mesmo hash; um arquivo alterado por um único byte ganha outro completamente diferente. Não existe "quase igual": o hash é uma impressão digital, e impressões digitais não se parecem.

Essa propriedade tem três consequências práticas que valem a pena entender. A primeira é a **integridade verificável**: ao baixar, o cliente recalcula o hash e compara. Se divergir, o download é descartado, mesmo que o servidor tenha respondido com sucesso. A segunda é a **deduplicação natural**: o mesmo conteúdo não precisa ser guardado várias vezes dentro de um nó, porque o hash é o mesmo. A terceira é a **independência do nome**: renomear o arquivo não muda a identidade do conteúdo, e dois arquivos com o mesmo nome mas conteúdos diferentes são coisas distintas.

O hash público é sempre o do conteúdo em claro. No disco do servidor, o blob fica cifrado com ChaCha20-Poly1305 sob a chave mestra do nó, e o hash esperado fica guardado no banco. A verificação de integridade acontece depois da decifragem; o cifrado não é confundido com o arquivo original. Essa distinção é importante porque o hash do ciphertext seria diferente do hash do conteúdo, e o protocolo não finge que são a mesma coisa.

Quando você vê uma URI com `?hash=...`, aquele hash não é decoração. Ele permite que o cliente confirme que o arquivo recebido é exatamente o que foi assinado, mesmo que o nó tenha sido comprometido ou esteja servindo uma versão antiga. É uma âncora de integridade que viaja junto com o endereço.

---

## Assinatura: quem publicou isto

Ao subir um arquivo, o cliente assina os bytes crus com a chave Ed25519 da identidade. O pyle verifica a assinatura contra o `prosopeion.hdap` do dono antes de gravar. Se a assinatura não conferir, o upload é recusado. Não há "modo de confiança" nem exceção para conteúdo antigo: a assinatura é o que separa um arquivo de um monte de bytes.

Repare na separação de papéis, porque ela explica muitas decisões do protocolo. A assinatura prova autoria e integridade. O hash dá o endereço. A permissão, a `adeia`, decide quem pode ler. Nenhuma dessas três coisas depende da outra. Você pode ter o hash de um arquivo e não ter permissão para lê-lo; pode ter permissão e ainda assim o hash servir para detectar que o conteúdo foi trocado no caminho; pode ter a assinatura e não ter a posse, porque a posse é transferível separadamente.

Há uma sutileza na assinatura de documentos que vale conhecer, mesmo que você nunca escreva um parser. A assinatura de um signatário é calculada sobre o texto antes de sua própria linha de assinatura ser inserida. Isso permite que um mesmo documento acumule assinaturas de várias partes sem invalidar as anteriores, como acontece em uma transferência de posse. O documento final contém todas as assinaturas, mas cada uma foi produzida sobre uma versão ligeiramente diferente do texto, de forma determinística e reproduzível.

---

## História: a matriz de origem

Um nó guarda não só os bytes, mas a procedência. Em que pyle o arquivo nasceu, quais réplicas foram autorizadas e quem avisou o quê. Esse registro é o `prytaneion`, a matriz de origem e réplicas. Ele é um documento como os outros, assinado e verificável, e é a memória da casa.

Sem procedência, não haveria como saber se uma cópia é autêntica ou inventada, nem como avisar as réplicas quando o dono apaga a origem, nem como distinguir uma réplica legítima de um nó que apenas afirma ter o conteúdo. A matriz resolve esses três problemas de uma vez: ela registra a origem, as réplicas e as operações de posse, sempre com prova. Quando um nó recebe uma deleção, ele consulta a matriz para saber se quem mandou é realmente a origem; quando um leitor busca um hash, ele consulta a matriz para saber quem tem o conteúdo.

A matriz não é um cadastro central. Cada nó mantém a sua visão, e as visões convergem por troca de digests e merge idempotente. Isso significa que dois nós podem ter visões ligeiramente diferentes em um dado instante, mas acabam convergindo para o mesmo estado quando se sincronizam. É a mesma lógica da bolha e do livro global, que você verá no capítulo sobre federação.

---

## O documento `.hdap`

Quase todo objeto do protocolo é um documento de texto canônico com a extensão `.hdap`. Texto, e não uma estrutura binária opaca, por uma razão simples: humanos conseguem ler e auditar; máquinas conseguem verificar sem ambiguidade. Um documento que você não consegue ler é um documento que você não consegue contestar.

Um exemplo simplificado de uma permissão ajuda a fixar a forma:

```
# HSYST DESCENTRALIZED ARCHIVE PROTOCOL
## DOC: adeia
### HEAD:
# VERSION: 1
# TYPE: adeia
# EDITION: 1
# CREATED_AT: 1737500000
### :END HEAD
### BODY:
# PERM all / read
### :END BODY
### SIGS:
# SIGNER: thais_a3f9c2d1e0b7aa11
# SIGNATURE: <base64>
### :END SIGS
## :END DOC
```

O documento tem três blocos. O `HEAD` contém a versão do formato, o tipo, a edição, a data de criação e, a partir da segunda edição, o `PREV_HASH`. O `BODY` contém o conteúdo específico do tipo: chaves, permissões, alvos, hashes. O `SIGS` contém um ou mais pares `SIGNER`/`SIGNATURE`, na ordem exigida pelo tipo.

Canônico significa que existe uma única forma válida de representar cada documento. As regras são rígidas de propósito: ordem fixa de seções e chaves, uma chave por linha, sem duplicatas, nenhum campo implícito ou inferido, e a assinatura cobrindo os bytes exatos do documento. Qualquer ambiguidade é tratada como erro, não como conveniência. Isso elimina uma classe inteira de bugs em que dois clientes concordam sobre um objeto mas o representam de formas diferentes, e o servidor discorda dos dois.

---

## Os tipos de documento

O protocolo reconhece vários tipos, cada um com uma semântica própria. O `prosopeion` é a identidade pública: nickname, sufixo, chaves e âncora OTP. A `adeia` é a lista de permissões e o filtro de propagação. O `diadosi` é a procuração de sucessão da casa. O `kerux` guarda os aliases DDNS. O `timi` publica a tabela de preços do módulo econômico. O `prytaneion` é a matriz de origem e réplicas. O `mochthos` é a prova de trabalho que gera banda. O `syngraphe` é o tratado que consome a banda no upload. O `metabibasis` é o pedido e o aceite de transferência de posse. O `pheme` e o `pheme_candidate` carregam sinais de reputação. O `exousia` é uma capacidade delegada em cadeia. E o `link` é um ponteiro simbólico reservado.

Talvez você nunca crie um `mochthos` ou um `pheme` à mão: esses documentos são produzidos pelos fluxos do cliente e do servidor. Mas os seis documentos que definem sua casa aparecem no painel de Configuração da GUI, e vale conhecê-los: `prosopeion`, `adeia`, `diadosi`, `kerux`, `timi` e `prytaneion`. Eles são a constituição da sua casa, e cada um tem um papel distinto.

Os nomes gregos não são enfeite. Eles evitam colisões com termos genéricos e deixam explícito que cada objeto tem uma semântica própria. Um "contrato" pode significar qualquer coisa; um `syngraphe` é especificamente um tratado que consome banda. O glossário completo está em [lexico-grego.md](lexico-grego.md).

---

## Edições e a corrente de hashes

Documentos são versionados por edição. A primeira edição tem `EDITION: 1`; a partir da segunda, o `HEAD` inclui `PREV_HASH`, o hash do documento anterior. Essa corrente serve a dois propósitos que se complementam.

O primeiro é o histórico. O pyle guarda a evolução, não só o estado atual, e é possível auditar como uma permissão mudou ao longo do tempo. O segundo é a sucessão segura. A procuração `diadosi` fixa os hashes das edições vigentes de `adeia` e `prosopeion`. Se você editar qualquer um deles, a procuração antiga deixa de valer até ser reassinada, porque os hashes já não batem. Isso impede que um fallback ressuscite um estado antigo de permissões, o que seria uma catástrofe silenciosa.

Editar um documento é, portanto, publicar uma nova edição assinada. Não existe "alterar no lugar". A edição anterior continua verificável, mas deixa de ser a vigente. Essa imutabilidade é o que permite que terceiros confiem no histórico: se o passado pudesse ser reescrito, a prova não valeria nada.

---

## Permissões: a `adeia`

A `adeia.hdap` é a lista de permissões da sua casa. Ela é um documento público e assinado por você, e cada linha é uma regra. Um exemplo:

```
PERM all / read
PERM user:<id-da-maria> docs/ write
PERM user:<id-do-joao> docs/segredo.txt deny
```

A primeira linha concede leitura da raiz a qualquer pessoa autenticada. A segunda concede escrita na pasta `docs/` a uma identidade específica. A terceira nega explicitamente o arquivo `docs/segredo.txt` a outra identidade. O sujeito é sempre o ID global, com sufixo; o caminho pode ser a raiz `/`, uma pasta ou um arquivo; os direitos são `read`, `write` e `own`; e `deny` nega explicitamente.

A busca é sempre do caminho mais específico para o mais geral. Por isso é possível liberar a pasta inteira e negar um único arquivo dentro dela. O sujeito `user:<id>` vence `all`, e `deny` vence os direitos positivos no mesmo nível de especificidade. Na ausência de qualquer regra que conceda o direito pedido, a resposta é negativa. Esse desenho é deliberadamente conservador: o padrão é negar, e cada exceção precisa ser escrita de forma explícita.

Os três direitos têm significados precisos. `read` permite baixar, listar e resolver o conteúdo. `write` permite enviar, editar e apagar dentro do escopo. `own` permite transferir posse e conceder permissões. Um detalhe que costuma surpreender é que `write` não implica `read`. Isso é intencional: pode ser útil permitir que alguém grave em uma pasta sem expor o conteúdo dela, como um balcão de entregas em que a pessoa pode deixar um pacote mas não pode abrir os pacotes dos outros.

---

## O filtro por pyle: `DIADOSI`

Além de decidir quem pode fazer o quê, a `adeia` pode decidir onde a casa pode circular. Duas diretivas controlam a propagação. A primeira é `DIADOSI=white:pyle-A;pyle-C;`, que permite replicação e leitura apenas pelos pyles listados. A segunda é `DIADOSI=black:pyle-B;`, que nega os pyles listados.

Isso permite, por exemplo, manter a casa pública mas impedir que ela seja espelhada em um pyle específico em que você não confia. Também permite o contrário: manter a casa restrita e liberar apenas os pyles que você escolheu como parceiros. O filtro vale tanto para replicação quanto para leitura, porque não faria sentido permitir a cópia e negar a leitura do mesmo conteúdo.

Há uma exceção que parece contraintuitiva mas é necessária: os documentos de identidade `prosopeion.hdap`, `adeia.hdap` e `diadosi.hdap` são isentos do filtro de leitura. A razão é prática. Sem esses três documentos, um pyle não consegue nem verificar uma assinatura nem saber quais são as regras. O filtro protegeria a casa tornando-a inauditável, o que seria o oposto do objetivo. A isenção é limitada a esses três documentos públicos; o conteúdo continua sujeito ao filtro.

---

## Quem decide o acesso

A pergunta que o servidor responde é objetiva: a identidade autenticada nesta sessão tem o direito para este caminho? Quem responde é o pyle, sempre. A autenticação vem da sessão, do `symbolon`, não de um campo que o cliente enviou no corpo da requisição. O cliente até pode esconder um botão que sabe que vai falhar, mas a autoridade é do servidor: se ele negar, a interface não contorna, mostra o erro real.

Essa separação entre interface e autoridade é importante. Um cliente malicioso pode tentar enviar um `owner` diferente, um caminho com `..` ou uma permissão inventada; o servidor não confia em nada disso. Ele olha a sessão, olha a `adeia` vigente e decide. A interface é uma conveniência, não uma fronteira de segurança.

Quando você conclui uma transferência, o pyle grava uma cessão (`ceession`) antes de copiar os bytes. A partir daí, a checagem de cessão é independente do texto da `adeia`. Você mantém `read` irrevogável sobre o que cedeu, e nem uma edição posterior da `adeia` pode devolver sua escrita. Sem isso, o read-only do cedente seria apenas uma promessa que daria para desfazer. Com a cessão, ele é um fato gravado.

---

## O caminho de um upload

Vale acompanhar o fluxo completo, porque ele mostra todas as peças trabalhando juntas. O cliente calcula o hash SHA-256 do arquivo e assina os bytes crus com a chave Ed25519. Em seguida, anexa o tratado de banda obtido via prova de trabalho. O pyle verifica a assinatura contra o `prosopeion` do dono, confere o hash declarado contra os bytes recebidos, chama a autorização para saber se a sessão tem `write` para o caminho, verifica a banda disponível e a cota `moira`, cifra o blob e grava antes de responder sucesso. Só então registra a origem no `prytaneion` e devolve o hash.

Se o disco falhar na gravação, você não recebe um `200` que o nó não cumpriu. Persistência antes da resposta é uma regra de projeto, não um detalhe. Ela significa que o servidor só confirma o que já está no disco, e que uma queda de energia não deixa o cliente achando que publicou algo que não foi publicado.

O caminho de leitura é o espelho disso. O cliente pede o arquivo, o pyle verifica a sessão, consulta a `adeia`, decifra o blob, confere o hash e entrega. Se qualquer etapa falhar, o cliente recebe um erro claro em vez de um conteúdo suspeito. E se o arquivo vier de uma réplica, o cliente verifica a assinatura de origem e o hash antes de aceitar.

---

## Termos importantes

| Termo | Definição simples |
|---|---|
| **blob** | O conteúdo cifrado guardado no disco do pyle. |
| **hash** | Impressão digital SHA-256 do conteúdo em claro. |
| **`.hdap`** | Documento textual canônico e assinado. |
| **edição** | Versão de um documento, encadeada por `PREV_HASH`. |
| **`adeia`** | Documento de permissões da casa. |
| **`prytaneion`** | Matriz de origem e réplicas. |
| **`ceession`** | Cessão irrevogável de leitura após transferência. |
| **`moira`** | Cota de armazenamento por usuário. |
| **DIADOSI** | Filtro de propagação por pyle. |

---

## Perguntas frequentes

**Preciso criar todos os documentos manualmente?** Não. A GUI cria modelos assinados quando o tipo permite, e os fluxos de permissões, aliases, sucessão e transferência escrevem os documentos por você. Você pode editá-los no editor de texto canônico se quiser controle total.

**Posso editar um documento já assinado?** Não no lugar. Você publica uma nova edição, que aponta para a anterior pelo `PREV_HASH`. A edição antiga continua existindo como história, mas deixa de ser a vigente.

**O que impede alguém de forjar um arquivo com o mesmo nome do meu?** O nome não identifica nada. O que vale é a assinatura ligada à sua chave e o hash do conteúdo. Um arquivo com o mesmo nome e bytes diferentes terá outro hash e outra assinatura, e o cliente verificará ambos.

**Um pyle pode alterar meu arquivo sem eu saber?** Não sem invalidar o hash e a assinatura. O cliente verifica o hash ao baixar, e a origem é registrada na matriz. Uma alteração seria detectada.

**Meu conteúdo é privado por padrão?** O acesso depende da `adeia`. Sem regras, o padrão é negar. Documentos de identidade, que não contêm conteúdo sensível, são públicos por necessidade de verificação.

**Posso apagar para valer?** Você pode apagar sua cópia e notificar as réplicas. Um nó que já copiou o conteúdo pode tentar retê-lo; o protocolo registra e permite penalizar reputacionalmente, mas não invade o disco de ninguém. Essa é uma limitação honesta da federação.

**Qual a diferença entre `read`, `write` e `own`?** `read` permite ver e baixar; `write` permite alterar o conteúdo; `own` permite transferir a posse e conceder permissões. `write` não implica `read`, e `own` é o direito mais forte.

---

**Leia agora:** [userguide4.md](userguide4.md) — Banda, Economia e Reputação
