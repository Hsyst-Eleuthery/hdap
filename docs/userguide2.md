# Identidade e a Casa

**HDAP v1.001 — Themelio · Epoptia**

**Escrito por Thaís (op3n/op3ny)**

---

**Leia primeiro:** [userguide.md](userguide.md) (visão geral)
**Próximo:** [userguide3.md](userguide3.md) (Arquivos, Documentos e Permissões)

---

## Quem é você no HDAP

No mundo real, sua identidade é aquilo que outras pessoas e instituições reconhecem. Seu nome, seus documentos, sua história e sua reputação formam um conjunto de sinais que permitem que alguém diga "esta pessoa é a Thaís". A maior parte desses sinais depende de terceiros: um cartório reconhece um documento, um governo emite um passaporte, uma empresa confirma um endereço. Você não é dono da sua identidade; você a aluga de instituições que podem, em tese, deixar de reconhecê-la.

No HDAP, sua identidade é matemática. Ela é um par de chaves criptográficas: uma pública, que pode ser mostrada a qualquer pessoa, e uma privada, que nunca sai do seu computador. A chave pública funciona como o número do seu apartamento em um prédio de correspondência: qualquer um pode saber o número e mandar uma carta. A chave privada funciona como a chave física do apartamento: só quem a tem consegue entrar. E, ao contrário de um prédio, não existe síndico com uma cópia mestra. Se você perder a chave, não há como pedir uma nova.

Essa mudança parece pequena, mas altera tudo. Em um sistema comum, você prova quem é mostrando uma senha a um servidor, e o servidor guarda (ou deveria guardar) um registro dessa senha. No HDAP, você prova quem é assinando um desafio com a chave privada; o servidor verifica a assinatura com a chave pública, que ele já conhece. A chave privada nunca viaja pela rede, nunca é enviada ao pyle e nunca é armazenada no servidor. O que viaja é uma prova de que você a possui, e uma prova não pode ser reutilizada por outra pessoa.

Na primeira vez que você abre o HDAP, o aplicativo gera esse par de chaves no seu dispositivo. A chave pública vai para o servidor quando você se registra. A chave privada fica em um cofre local, cifrada por uma senha que só você conhece. A partir daí, toda ação relevante é assinada no seu computador antes de ser enviada. O pyle não assina por você, não guarda sua chave e não pode agir em seu nome. Ele apenas verifica.

---

## Por que não usar e-mail e senha

Sistemas de e-mail e senha concentram uma fragilidade que costuma passar despercebida: a prova de identidade fica com outra pessoa. Sua senha é guardada no servidor, ou em um hash dela, e a recuperação depende de um atendimento humano que talvez não exista amanhã. Se o banco de dados vaza, sua senha vaza. Se a empresa decide suspender a conta, sua identidade some com ela. Se o serviço fecha, você perde o acesso a tudo o que construiu.

O HDAP troca esse modelo por chaves. Não há senha no servidor, porque não há senha: há uma chave privada que nunca sai do seu dispositivo. Não há banimento da rede inteira, porque não há uma autoridade central que mande em todos os pyles. Não há censura silenciosa de conteúdo, porque o arquivo é assinado e verificável. E não há dependência de uma plataforma, porque você pode mudar de pyle sem mudar de identidade.

Mas há um preço, e é importante dizê-lo em voz alta. Não existe "esqueci minha senha". Se você perder o cofre e a senha, a identidade se vai, e nenhum suporte técnico consegue reverter isso. Não há e-mail de recuperação, não há pergunta secreta, não há atendimento humano com poder de redefinir seu acesso. Essa é a contrapartida da soberania. O HDAP não promete que você nunca vai perder nada; promete que ninguém além de você pode decidir o que você perde.

Na prática, isso significa que a segurança da sua identidade depende de duas coisas que estão inteiramente sob seu controle: uma senha forte e um backup do cofre. O restante do sistema foi desenhado para que essas duas coisas sejam suficientes.

---

## A chave pública e a chave privada

A chave privada é o dado mais importante que você terá no HDAP. Ela fica no arquivo `krypte.hdap`, cifrada com sua senha. Quem tem a chave privada é a identidade; não há distinção entre "a conta" e "a chave". Se alguém copiar o cofre e souber a senha, essa pessoa é você para todos os efeitos do protocolo. Se alguém copiar o cofre e não souber a senha, o cofre é um bloco de dados inútil, porque a cifra é forte o suficiente para tornar a tentativa de quebra inviável.

A chave pública é o seu endereço. Ela fica no arquivo `prosopeion.hdap`, que é público e auto-assinado. Qualquer pessoa pode lê-la, e é assim que deve ser: sem a chave pública, ninguém consegue verificar suas assinaturas. Ela não revela a chave privada e não permite que ninguém aja em seu nome. Compartilhar a chave pública é seguro e necessário; compartilhar a chave privada é entregar a identidade.

Entre as duas existe a assinatura digital, que é o mecanismo que liga uma à outra. Assinar, no HDAP, é uma operação em três passos. Primeiro, o sistema pega os bytes exatos do conteúdo ou do documento. Depois, calcula um resumo desses bytes, o hash. Por fim, cifra esse resumo com a chave privada. Qualquer pessoa com a chave pública pode conferir o resultado. Como a assinatura é feita sobre os bytes crus, não existe a ambiguidade de "o mesmo objeto representado de duas formas diferentes": ou os bytes são idênticos, ou a assinatura não confere.

Essa escolha de assinar os bytes crus, e não uma serialização intermediária, é uma das decisões mais importantes do protocolo. Ela elimina uma classe inteira de bugs em que dois sistemas concordam sobre o significado de um documento mas discordam sobre a sua representação. Se a assinatura cobre os bytes, não há espaço para interpretação.

---

## Os arquivos do seu cofre

O cofre é a pasta que guarda a sua identidade. Por padrão, no Linux, ele fica em `~/.local/share/hdap/<nickname>/`; no Windows, em `%APPDATA%\hdap\<nickname>\`. A pasta final inclui o nickname, então duas identidades nunca compartilham o mesmo cofre por acidente, mesmo que você use a mesma máquina para várias pessoas.

Dentro dela, você encontra três arquivos. O `krypte.hdap` é o cofre cifrado propriamente dito: contém as chaves privadas e a seed OTP, tudo protegido pela sua senha. O `prosopeion.hdap` é a identidade pública assinada: nickname, sufixo, chaves públicas e âncora OTP. E o `omphalos.step` é o contador local do OTP, usado no login para saber em que ponto da cadeia de hash você está. Os três são necessários para uma experiência tranquila, mas apenas o `krypte.hdap` e a senha são indispensáveis para recuperar a identidade; o contador pode ser reconstruído com a ajuda do servidor.

Você pode mudar a base do diretório com a variável de ambiente `HDAP_HOME`. O nickname continua sendo anexado, de modo que a variável muda o lugar onde os cofres ficam, mas não mistura cofres de pessoas diferentes. Esse detalhe é útil para testes, para manter identidades separadas e para colocar o cofre em um disco que você faz backup com mais frequência.

É importante não confundir o cofre local com a casa no pyle. O cofre é seu e fica no seu dispositivo; a casa é o seu espaço dentro de um servidor e fica no disco do operador. O cofre contém as chaves; a casa contém os arquivos e os documentos públicos. Perder o cofre é perder a identidade; perder um pyle é perder uma casa, o que é grave mas recuperável se você tiver réplicas ou uma procuração de sucessão.

---

## Os algoritmos, em linguagem humana

Você não precisa decorar os nomes dos algoritmos, mas vale saber o que cada peça faz, porque isso ajuda a entender o que está protegido e o que não está.

O **Ed25519** é o algoritmo de assinatura. Ele prova autoria e integridade. Gera assinaturas pequenas e rápidas de verificar, e é o que aparece em todos os documentos assinados do protocolo. Pense nele como um carimbo que ninguém consegue falsificar sem a chave privada.

O **X25519** é usado na etapa de transporte do login. Ele permite que o cliente demonstre conhecer um segredo derivado sem revelá-lo explicitamente. É uma camada adicional contra ataques de replay e contra a tentativa de se passar por você com uma assinatura capturada.

O **Argon2id** é a fechadura do cofre. Sua senha não é guardada em lugar nenhum; ela é transformada em uma chave por uma função lenta e resistente a hardware especializado. Isso significa que, mesmo que alguém copie o `krypte.hdap`, quebrar a senha exige um esforço enorme. Quanto mais longa e imprevisível for a senha, maior o custo para quem tentar.

O **ChaCha20-Poly1305** é a cifra que protege o conteúdo. Ele não apenas cifra, mas autentica: se um byte for alterado, a decifragem falha. É como um lacre que denuncia qualquer violação. Ele é usado tanto no cofre local quanto nos blobs guardados pelo servidor.

O **SHA-256** é a impressão digital. Produz o hash dos arquivos e dos documentos, e é o que dá endereço ao conteúdo. Se o arquivo mudar, o endereço muda. Se o endereço mudar sem que o conteúdo mude, alguma coisa está errada.

Há ainda o **OTP em cadeia de hash**, que é o segundo fator do login. Ele funciona como uma lista de senhas de uso único que só avança: cada login revela o próximo elo, e o servidor recusa elos já usados. Assim, uma senha capturada não pode ser reutilizada, porque o próximo passo é sempre diferente.

---

## Seu ID global

Seu identificador no HDAP tem a forma `nickname_sufixo`. O nickname é a parte legível, escolhida por você; o sufixo é derivado da sua chave e garante que não existam duas identidades com o mesmo nome. Por exemplo, `thais_a3f9c2d1e0b7aa11`. O ID global é o que aparece nas permissões, nas URIs e nos documentos; o nickname sozinho é apenas um apelido conveniente.

É comum que iniciantes usem só o nickname ao pedir uma permissão e depois estranhem um `403`. A regra é simples: sempre que outra pessoa for conceder algo a você ou referenciar seus arquivos, use o ID global completo. O comando `whoami` do CLI imprime esse valor, e a GUI o exibe no painel de identidade.

O ID global também é o que torna a identidade portável. Como o sufixo vem da chave, e não de um cadastro, a mesma identidade pode ser registrada em vários pyles sem que o nome mude. Você não é "usuário do pyle A"; você é você, e o pyle A é apenas uma das casas onde você mora.

---

## A casa e o pyle

Duas palavras aparecem o tempo todo no HDAP e é fácil confundi-las. Um **pyle** é o servidor. Ele guarda blobs, aplica permissões, participa da federação e oferece a porta de entrada HTTP/TLS. Uma **casa** é o seu espaço dentro de um pyle: o namespace `HDAP$/<seu-id>/`, onde vivem seus arquivos e seus documentos de configuração.

Sua identidade é global; sua casa é local a um pyle. Você pode registrar a mesma identidade em vários pyles e, se necessário, mudar de casa — assinando uma mensagem que aponta o novo pyle, sem precisar recuperar a chave nem depender do pyle antigo estar no ar. Essa distinção é o coração da portabilidade: a identidade não mora no servidor, mora com você. O servidor é apenas o lugar onde a casa está apoiada no momento.

Quando você muda de casa, os arquivos não são teleportados automaticamente. O que muda é a autoridade: o novo pyle passa a aceitar suas operações e a propagar a mudança aos pares. As réplicas que já existem continuam existindo, e o novo pyle pode sincronizá-las conforme as permissões. É por isso que a mudança de casa é uma operação de continuidade, não de cópia mágica.

---

## Onde ficam seus dados

É importante separar três lugares, porque cada um tem um risco diferente e uma estratégia de backup diferente.

O primeiro é o **seu cofre local**, a pasta com `krypte.hdap`, `prosopeion.hdap` e `omphalos.step`. Só você tem. Se ele desaparecer, a identidade desaparece. Faça backup com frequência e guarde a senha separadamente, em um gerenciador de senhas. Um backup do cofre sem a senha é inútil; a senha sem o cofre também.

O segundo é a **casa no pyle**, onde ficam os blobs cifrados, os documentos assinados, as permissões e a matriz de origem. Ela fica no disco do operador. Você não controla esse disco, mas controla as permissões e pode replicar o conteúdo para outros pyles. O operador consegue ler o conteúdo em claro enquanto o serve, porque o servidor precisa decifrá-lo para entregá-lo; a criptografia em repouso protege o disco roubado, não o administrador do servidor. Esse é um limite honesto, e ele está documentado no modelo de ameaça.

O terceiro são as **réplicas**, cópias em outros pyles autorizadas pela sua `adeia` e registradas na matriz de origem. Elas são somente-leitura para quem as espelha, mas garantem que o conteúdo sobreviva à queda do pyle principal. Uma réplica é verificada por hash e assinatura; uma cópia divergente é descartada.

---

## Login: as três provas

O login no HDAP se chama **3FA por nó** porque combina três fatores independentes, todos verificados pelo pyle. O primeiro é a assinatura de um desafio, que prova que o cliente possui a chave Ed25519. O segundo é um passo OTP, que revela o próximo elo de uma cadeia de hash e prova que o cliente está avançando a corrente, não repetindo uma mensagem antiga. O terceiro é uma prova de conhecimento da chave de transporte, um HMAC sobre o segredo derivado de X25519, que amarra a sessão ao canal.

O resultado é um **symbolon**: um token de sessão válido apenas naquele nó. A sessão não é global; a identidade é. Isso significa que você pode estar logado no pyle A e não no pyle B, e que um token vazado em um nó não serve para outro. É uma separação deliberada: cada operador é dono da sua sessão, mas nenhum é dono da sua identidade.

O pyle é a autoridade sobre o passo OTP. Se o seu contador local ficar dessincronizado, por exemplo após restaurar um backup antigo, o cliente pergunta ao servidor qual é o próximo passo e se ajusta. O caminho inverso não existe: um passo já visto pelo servidor é recusado, porque aceitá-lo abriria a porta para replay. Essa assimetria é o que torna o OTP útil mesmo em um cliente que pode ser restaurado de um estado antigo.

Existe um limite importante, e escondê-lo seria propaganda. Os três fatores vivem no mesmo cofre local. Isso protege contra o roubo de um fator isolado e contra replay, mas não protege contra um cofre comprometido. Se alguém tiver o cofre e a senha, terá os três fatores. A defesa, nesse caso, é a mesma de sempre: senha forte e backup seguro.

---

## Backup, perda e roubo

Fazer backup do HDAP é copiar a pasta do cofre para um lugar seguro e offline. O procedimento é banal, mas a consequência de não fazê-lo não é. Guarde o cofre e a senha em lugares diferentes, para que a perda de um não implique a perda do outro. Use um gerenciador de senhas para a senha e um disco ou serviço de sua confiança para o cofre.

Se você perder a senha, a identidade está perdida. Não há recuperação, e isso não é uma falha do software: é a consequência direta de não haver uma autoridade central. Se você perder o `krypte.hdap` sem backup, o resultado é o mesmo. Se você perder um pyle, a situação é diferente: a casa pode migrar com `house_move` ou ser assumida por um fallback previamente autorizado com `diadosi`. Se alguém copiar o cofre mas não souber a senha, o cofre permanece inútil. Se alguém copiar o cofre e souber a senha, a identidade foi comprometida, e a única resposta é criar uma nova identidade e migrar o conteúdo.

Vale repetir: o HDAP não tem "esqueci minha senha". Ele tem backup. A diferença entre um sistema que promete recuperação e um sistema que exige backup é a diferença entre confiar em alguém e confiar em você. O guia não vai fingir que a segunda opção é fácil; ele vai apenas deixar claro que é a que o protocolo oferece.

---

## Termos importantes

| Termo | Definição simples |
|---|---|
| **pyle** | O servidor que guarda a sua casa e participa da federação. |
| **casa** | O seu espaço de arquivos dentro de um pyle. |
| **identidade** | O par de chaves que prova quem você é. |
| **krypte.hdap** | O cofre cifrado com sua chave privada e a seed OTP. |
| **prosopeion.hdap** | Sua identidade pública, assinada. |
| **ID global** | `nickname_sufixo`, o identificador único da identidade. |
| **hash** | Impressão digital de um conteúdo. |
| **assinatura** | Carimbo matemático que prova autoria. |
| **symbolon** | Token de sessão local de um pyle. |
| **OTP** | Senha de uso único baseada em uma cadeia de hash. |
| **TOFU** | "Trust On First Use": confiar no certificado na primeira conexão e fixá-lo depois. |
| **pin** | A impressão digital do certificado TLS de um pyle. |

---

## Perguntas frequentes

**Meu nickname é minha identidade?** Não. O nickname é só a parte legível; quem identifica é o sufixo derivado da chave. Duas pessoas podem usar o mesmo nickname em pyles diferentes sem conflito, porque o ID global é diferente.

**Posso ter duas identidades?** Sim, cada cofre é independente. Use `--home` no CLI ou `HDAP_HOME` na GUI para apontar para cofres diferentes. Duas identidades podem até compartilhar o mesmo pyle, desde que tenham cofres separados.

**O pyle conhece minha chave privada?** Nunca. Ele só recebe a chave pública e as assinaturas. A chave privada é usada apenas no seu dispositivo, no momento de assinar.

**A mesma identidade funciona em qualquer pyle?** Sim, desde que esteja registrada nele. A sessão é por pyle; a identidade é global. Você pode ter sessões ativas em vários pyles ao mesmo tempo.

**Se eu apagar o `omphalos.step`, perco a conta?** Não, mas o login pode pedir um ajuste ao servidor. O pyle é a autoridade sobre o passo OTP, e o cliente se sincroniza com ele.

**Posso recuperar a identidade por e-mail?** Não existe esse mecanismo, e a ausência é intencional. Ninguém além de você pode redefinir sua identidade. Se você quer uma rede com recuperação central, o HDAP não é essa rede.

**O que acontece se eu usar uma senha fraca?** O cofre fica mais fácil de quebrar se alguém obtiver o arquivo. A escolha da senha é sua; o protocolo não pode tornar forte uma senha fraca. Use uma senha longa e exclusiva.

**Devo sincronizar o cofre em nuvem?** Só se você confiar no serviço e entender que está colocando o arquivo cifrado em um terceiro. O ideal é manter o cofre em um local que você controla e fazer backups offline.

---

**Leia agora:** [userguide3.md](userguide3.md) — Arquivos, Documentos e Permissões
