# Guia do Usuário — HDAP

**HDAP v2.0 — codinome de protocolo: Teleios (Téleia vási) · codinome de lançamento: Teleios**

**Escrito por Thaís (op3n/op3ny)**

---

## O que é o HDAP?

Imagine que hoje seus arquivos moram em um imóvel alugado. Você paga para usar, mas o imóvel não é seu: o dono decide quem entra, o que pode ser guardado e quando a porta será trancada. Se o contrato acaba, tudo que estava lá dentro vira uma negociação. Você pode ter a cópia de um documento, mas não tem o documento; pode pagar em dia, mas não tem garantia de que o serviço continuará amanhã; pode confiar no provedor, mas não tem como provar que confiou na coisa certa.

O **HDAP (Hsyst Descentralized Archive Protocol)** é uma tentativa de resolver esse problema de baixo para cima. Em vez de uma empresa dona dos arquivos, existe um protocolo. Em vez de uma conta que pode ser suspensa, existe uma identidade que fica com você. Em vez de uma promessa de backup, existem cópias que qualquer pessoa pode verificar. E em vez de uma autorização invisível escondida em um banco de dados, existem permissões assinadas que você mesmo publica e que qualquer um pode ler.

A ideia central é pequena o suficiente para ser entendida e forte o suficiente para ser conferida. Cada arquivo no HDAP é definido por três fatos independentes. O primeiro é um **hash**: uma impressão digital do conteúdo, de modo que o endereço de um arquivo vem do que ele é, e não do nome que alguém deu a ele. O segundo é uma **assinatura**: uma prova matemática de quem publicou, que qualquer pessoa pode verificar sem pedir licença a um servidor. O terceiro é uma **história**: o nó que guarda o arquivo registra onde ele nasceu, quais cópias existem e quem autorizou cada cópia. Se você entender esses três fatos, entenderá a espinha dorsal de todo o resto.

O resto do protocolo existe para proteger esses três fatos. A identidade protege a assinatura. As permissões protegem o acesso. A banda protege o recurso de quem guarda. A replicação protege o arquivo contra a queda de um servidor. A transferência de posse e a sucessão de casa protegem você contra o desaparecimento do operador. Nada disso é decoração: cada peça responde a uma pergunta concreta sobre o que acontece quando algo dá errado.

É importante dizer, desde já, o que o HDAP **não** é. Ele não é uma blockchain, não tem uma moeda própria no seu núcleo e não promete anonimato de rede. Ele não é uma rede social nem um substituto da internet inteira. Ele é uma camada de arquivamento com regras explícitas, pensada para quem quer possuir sua identidade e manter seus arquivos acessíveis mesmo quando o nó original sai do ar. Essa honestidade não é uma fraqueza; é o que permite que as garantias que existem sejam realmente confiáveis.

---

## Por que ele existe

Na internet de hoje, você não guarda seus arquivos: você aluga acesso a eles. A plataforma decide o formato, o limite, a política de remoção e o preço. Quando a conta é encerrada, o arquivo pode continuar existindo no disco de alguém, mas você perdeu o acesso, perdeu a prova de autoria e perdeu a capacidade de migrar. A relação é sempre assimétrica: a plataforma sabe tudo sobre você, e você não sabe quase nada sobre o que ela fará amanhã.

O HDAP inverte essa relação. A identidade é um par de chaves que fica no seu computador, não em um cadastro. O arquivo é identificado pelo conteúdo, não pelo nome de uma empresa. A permissão é um documento assinado por você, não uma configuração que alguém pode mudar sem avisar. A réplica é verificável por hash, não uma promessa de backup. E a casa — o seu espaço dentro de um servidor — pode mudar de lugar sem que a identidade mude de nome. Se o nó cair, o arquivo pode estar em outro lugar. Se o operador mudar as regras, você pode levar sua casa para outro pyle.

Essa inversão tem um custo, e o custo é a responsabilidade. Não existe "esqueci minha senha", não existe atendimento que redefina seu acesso e não existe autoridade central para consertar um cofre perdido. O que existe, em troca, é um conjunto de mecanismos que você pode entender, auditar e repetir. O HDAP troca a confiança cega por trabalho verificável, e assume que o usuário prefere ser dono a ser cliente.

---

## As cinco coisas que o HDAP faz

Para não se perder nos detalhes, vale fixar cinco ideias. Elas aparecem o tempo todo no restante do guia e explicam praticamente tudo o que o sistema faz.

A primeira é que **sua identidade é sua, literalmente**. Não existe e-mail, CPF ou conta central. Sua identidade é um par de chaves que fica no seu computador. A chave privada nunca é enviada a ninguém; o servidor conhece apenas a chave pública, e é com ela que ele verifica que foi você quem agiu. A consequência boa é que nenhum servidor pode te banir da rede inteira, porque não existe uma autoridade que mande em todos. A consequência difícil é que não existe recuperação de senha: se você perder o cofre e a senha, a identidade se vai. Essa é a parte do guia que você deve ler com mais atenção, e ela tem um capítulo inteiro dedicado a ela.

A segunda é que **cada arquivo tem prova de autoria**. Quando você publica algo, não é uma linha escondida em um banco de dados que só a empresa vê. É um documento assinado que qualquer pessoa pode ler e verificar: quem publicou, quando e a impressão digital exata dos bytes. Se alguém alterar o conteúdo, o hash muda e a fraude fica visível. No HDAP quase tudo é documento: a sua identidade, as permissões, um alias, uma oferta de transferência, uma procuração de sucessão. Aprender a ler um documento `.hdap` é aprender a ler o protocolo.

A terceira é que **publicar custa trabalho, não dinheiro**. O upload não é gratuito em termos de recurso: ele consome disco e banda. Em vez de cobrar uma tarifa escondida, o HDAP pede uma prova de trabalho leve. Seu cliente resolve um pequeno desafio matemático e recebe uma credencial de banda, que depois é consumida no momento de publicar. É como carimbar um selo antes de postar uma carta: o custo é pequeno para quem publica de verdade e proibitivo para quem tenta inundar a rede. O módulo econômico existe, mas é opcional; o arquivamento básico não depende de moeda nenhuma.

A quarta é que **a rede não tem dono único**. Não existe "o servidor do HDAP". Existem vários pyles, que se comunicam entre si, verificam as assinaturas uns dos outros e replicam conteúdo quando faz sentido. Se um pyle ficar malvado, você leva sua casa para outro, assinando a mudança sem pedir licença ao antigo. Se o pyle sumir enquanto você está offline, uma procuração previamente assinada pode permitir que um substituto de confiança assuma a casa. O sistema foi desenhado para sobreviver à perda de qualquer nó individual.

A quinta é que **você escolhe como usar**. O mesmo protocolo tem três portas de entrada. O aplicativo de desktop, `hdap-gui`, esconde a complexidade e oferece uma experiência parecida com a de um gerenciador de arquivos. A linha de comando, `hdap-cli`, serve para automatizar e operar servidores. E o próprio nó, `hdap-server`, é a peça que guarda conteúdo e participa da federação. As três falam o mesmo protocolo e compartilham o mesmo núcleo, então uma regra de documento nunca é reimplementada de um jeito no servidor e de outro no cliente.

---

## Onde a confiança é substituída por prova

Vale parar um instante na frase que resume a filosofia do projeto: **confiança não deveria ser exigida onde pode ser substituída por prova**. Toda vez que o HDAP precisa decidir algo, ele tenta responder a três perguntas. Quem assinou isto? Os bytes são os mesmos que foram assinados? Esta pessoa tem o direito de fazer isso agora? Se uma dessas respostas depende apenas da palavra de um operador, o desenho ainda não está pronto.

Na prática, isso significa que cada pergunta que você faria a uma nuvem comum ganha uma resposta verificável no HDAP. Quem publicou este arquivo? Uma assinatura sobre os bytes crus. O arquivo mudou? O hash do conteúdo faz parte do endereço. Eu posso ler? Uma permissão assinada pelo dono diz que sim, ou o nó recusa. Esta cópia é verdadeira? O nó verifica o hash ao receber e registra a origem. E se o servidor sumir? A casa pode migrar, ou ser assumida por um fallback previamente autorizado. E se o operador mentir? Você troca de pyle e leva sua identidade; a história assinada continua verificável.

Essa é a diferença entre um sistema em que você confia porque não tem escolha e um sistema em que você confia porque conferiu. O HDAP não pede fé; ele pede que você repita a sequência de provas, se quiser. E como as provas são matemáticas, qualquer cliente — inclusive um que você mesmo escreveu — chega à mesma conclusão.

---

## O que você pode fazer com o HDAP

Com uma identidade e um pyle, você pode guardar arquivos que qualquer pessoa verifica por hash e assinatura. Pode conceder leitura, escrita ou posse a outra identidade usando uma permissão assinada, e pode revogar essa permissão publicando uma nova edição do mesmo documento. Pode espelhar o espaço de alguém, com verificação de integridade a cada cópia, e ver exatamente quantos arquivos foram negados quando a permissão não alcança tudo. Pode transferir a posse de um arquivo ou de uma pasta sem perder a leitura do que cedeu, porque a cessão de leitura é gravada de forma independente das permissões. Pode mudar de casa quando o pyle atual fica indisponível, mesmo que ele esteja offline, assinando a mudança de outro lugar. Pode deixar uma procuração assinada para que um pyle de confiança assuma sua casa se a principal cair. Pode publicar aliases para não decorar endereços longos, minerar banda por prova de trabalho para publicar conteúdo, e auditar tudo isso lendo os documentos, sem depender da palavra de ninguém.

Perceba que quase todas essas capacidades vêm de documentos assinados, e não de botões administrativos. Isso é proposital. Um documento assinado pode ser verificado por qualquer implementação, guardado como prova e citado em uma auditoria; um botão administrativo é uma decisão de alguém em quem você teve que confiar.

---

## Você precisa ser especialista?

Não. Mas dois conceitos ajudam em tudo o que vem depois, e vale fixá-los agora. O primeiro é a **chave privada**, que funciona como a chave do seu apartamento: quem tem, entra, e não existe cópia na portaria. O segundo é o **hash**, que funciona como a impressão digital de um arquivo: se um único byte muda, ela muda por completo.

Com esses dois conceitos, a maior parte do HDAP se torna intuitiva. A assinatura é a chave privada carimbando uma impressão digital. O endereço de um arquivo é a sua impressão digital. A permissão é um documento que diz quem pode usar a chave de leitura. A réplica é uma cópia cuja impressão digital bate com a original.

O aplicativo `hdap-gui` foi feito justamente para esconder o resto. Você navega, sobe arquivos, edita permissões e acompanha a saúde da rede como faria em um gerenciador de arquivos comum. O CLI existe para quando você quiser automatizar ou operar um servidor. E o servidor existe para quando você quiser ser dono do armazenamento, e não apenas usuário dele.

---

## O que a geração v2 mudou para você

Se você já usava o HDAP na v1, a boa notícia vem primeiro: **seus documentos continuam valendo**. O `# VERSION: 1` não mudou, e um `prosopeion.hdap` ou `adeia.hdap` escrito antes da Teleios é lido sem conversão. O que mudou foi o que acontece por baixo e o que você vê na tela:

- **O tempo é UTC, sempre.** Todo instante do protocolo é um número de segundos desde 1970-01-01 às 00:00 UTC. Não existe fuso nem horário de verão no fio. No login, você devolve exatamente o instante que o servidor emitiu — o relógio do seu computador não decide se a prova é válida. O comando `health` mostra `time_utc` e `date_utc`, e o GUI exibe o horário em UTC.
- **A prova de login está amarrada ao desafio.** O terceiro fator agora cobre o `nonce` e o instante do desafio, então gravar uma prova antiga não serve para entrar de novo. A leitura da chave compartilhada passa por HKDF com rótulos separados para cifragem, sessão e OTP.
- **A âncora OTP pode ser rotacionada com segurança.** O comando `rotate TOKEN` (ou o botão 🔑 da GUI) troca a âncora **OMPHALOS** usando sua chave de identidade, não apenas o token da sessão. Um token vazado sozinho não pode tomar sua conta. Depois da rotação, você faz `auth` de novo para obter um token da nova cadeia.
- **Seu cofre ganhou versão.** O `krypte.hdap` v2 guarda os parâmetros Argon2 no cabeçalho (64 MiB por padrão) e continua lendo cofres v1. A senha continua sendo sua, local e nunca enviada ao servidor.
- **A Ángelma diz o que o nó está fazendo.** É o nome da mensagem do pyle: uptime, usuários, versão, protocolo e outros dados, exibida em `health`, no rodapé da GUI e na rota `/motd` do servidor.
- **A passphrase saiu da linha de comando.** O CLI prefere `--pass-env`, `--pass-file` ou um prompt no terminal com o eco desligado. `--pass` ainda funciona, mas avisa que a senha fica visível na lista de processos.

O [resumo da geração v2](VERSAO.md) explica cada mudança em detalhe e mantém a tabela do que era Themelio e o que é Teleios.

---

## Codenomes e versionamento

Todo lançamento do HDAP carrega **dois codinomes**. O **codinome de protocolo** dá nome a uma geração da linguagem do protocolo: é ele que muda quando a forma como os nós conversam ou como os documentos são interpretados muda. O **codinome de lançamento** dá nome ao pacote como um todo: é ele que muda em qualquer release, inclusive nas correções que não tocam o protocolo.

O marco inicial é o **HDAP v1.0**. O codinome de protocolo é **Themelio**, que significa "Marco Zero" em grego, e o codinome de lançamento é **Veritas Aeterna**, "verdade eterna". A v1.001 manteve **Themelio** e trouxe **Epoptia**, corrigindo a edição e a avaliação das permissões. A geração atual é a **v2.0 — Téleia vási · Teleios**: um novo codinome de protocolo porque a linguagem entre nós mudou, e **Teleios** também como codinome de lançamento.

As regras de versionamento são simples e valem para sempre. Atualizações que **não** mudam o protocolo — melhorias de interface, correções de bug, correções de segurança, mudanças de documentação ou de empacotamento — saem como `v2.001`, `v2.002`, `v2.003`, e assim por diante. Nesses lançamentos, **apenas o codinome de lançamento muda**; o codinome de protocolo continua **Teleios**. Já as atualizações que mudam a linguagem do protocolo abrem a próxima versão maior e trocam os dois codinomes. O formato dos documentos é independente dessa contagem: `# VERSION: 1` continua valendo na v2, e um `.hdap` da v1 é lido sem conversão.

Há ainda uma regra que não admite exceção: **toda release atualiza a documentação**. Não existe lançamento sem changelog, sem os dois codinomes declarados e sem as datas de revisão ajustadas. O registro completo de cada lançamento fica no [CHANGELOG](../CHANGELOG.md), o resumo desta geração em [VERSAO.md](VERSAO.md), e o procedimento de publicação está no [guia de execução](guia-de-execucao.md).

---

## Como este guia está organizado

O guia foi dividido em capítulos que podem ser lidos em ordem ou consultados separadamente. A visão geral que você está lendo é a porta de entrada. O segundo capítulo trata da identidade e da casa: como suas chaves funcionam, onde ficam seus dados, como o login prova quem você é e o que fazer para não perder tudo. O terceiro capítulo trata de arquivos, documentos e permissões: o que é um hash, como um documento `.hdap` é montado, como as permissões são avaliadas e como o acesso é decidido. O quarto capítulo trata de banda, economia e reputação: por que publicar custa trabalho, como a prova funciona, o que é a cota de armazenamento e o que a reputação significa em uma rede sem tribunal. O quinto capítulo trata da federação, das réplicas e da sucessão: como os pyles se descobrem, como as cópias são verificadas, como a deleção respeita a origem e como a casa sobrevive à queda do servidor principal. O sexto capítulo trata dos aplicativos e da operação: como usar a GUI e o CLI, como operar um pyle em produção e como resolver os problemas mais comuns.

Comece pelo [resumo da geração v2](VERSAO.md) se quiser um mapa do que mudou. Se o seu objetivo é entender o protocolo em profundidade, o [manual técnico](tecnico.md) e a [especificação](especificacao-hdap.md) são o caminho seguinte. Se o seu objetivo é auditar a segurança, o [modelo de ameaça](modelo-de-ameaca.md) lista cada ameaça e a mitigação correspondente. E se o seu objetivo é construir o HDAP a partir do código, o [guia de execução](guia-de-execucao.md) cobre compilação, testes e empacotamento.

Se você quer apenas o resumo básico, este capítulo basta. Se quer entender a identidade e a casa, siga para o [segundo capítulo](userguide2.md); se quer entender arquivos, documentos e permissões, o [terceiro](userguide3.md); se quer entender banda, economia e reputação, o [quarto](userguide4.md); se quer entender a rede, as réplicas e a sucessão, o [quinto](userguide5.md); e se quer usar a GUI, o CLI e operar um pyle, o [sexto](userguide6.md). Para compilar o código e empacotar releases, o caminho é o [guia de execução](guia-de-execucao.md); para a arquitetura e as decisões de engenharia, o [manual técnico](tecnico.md); para implementar outro cliente, a [especificação](especificacao-hdap.md) e o [RFC](rfc-hdap.md); e para a auditoria de segurança, o [modelo de ameaça](modelo-de-ameaca.md).

---

*HDAP — Descentralizado. Verificável. Soberano.*
