# HDAP — Hsyst Descentralized Archive Protocol

> **Arquivos com autoria. Memória com prova. Uma casa que não depende de um único servidor.**

oie, eu sou a **Thaís (op3n/op3ny)**. O HDAP nasceu de uma pergunta simples: como guardar arquivos de um jeito em que a posse, a autoria e a história não dependam da boa vontade de uma empresa? A resposta não foi criar mais uma nuvem — foi criar um protocolo pequeno o suficiente para ser entendido e forte o suficiente para ser verificado.

Esta é a versão **v2.0**, a geração **Téleia vási** do protocolo, com codinome **Teleios**. Ela sucede a v1.001 (**Themelio · Epoptia**) sem trocar o formato dos documentos: `# VERSION:` continua `1`. O que muda é a linguagem de interoperabilidade entre nós — tempo Unix UTC em todas as provas, derivação HKDF, sessões gravadas como hash, cofre versionado e autenticação ligada ao desafio emitido pelo servidor. A visão completa da geração está em [docs/VERSAO.md](docs/VERSAO.md).

[![CI](https://github.com/Hsyst-Eleuthery/hdap/actions/workflows/ci.yml/badge.svg)](https://github.com/Hsyst-Eleuthery/hdap/actions/workflows/ci.yml)
[![Licença: MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-blue.svg)](LICENSE)

**[Guia do Usuário](docs/userguide.md)** · **[Visão v2](docs/VERSAO.md)** · **[Manual Técnico](docs/tecnico.md)** · **[Especificação](docs/especificacao-hdap.md)** · **[RFC](docs/rfc-hdap.md)** · **[Modelo de Ameaça](docs/modelo-de-ameaca.md)** · **[Downloads](https://github.com/Hsyst-Eleuthery/hdap/releases)**

---

## O que é o HDAP

O **HDAP** é um protocolo federado de arquivamento. Cada nó — chamado de **pyle** — guarda arquivos assinados, mantém um registro verificável de origem e pode replicar conteúdo para outros nós sem pedir licença a uma autoridade central. Não existe um servidor mestre, um banco central de identidades ou uma senha que abra todos os nós. O que existe são vários operadores independentes que conversam, trocam provas e convergem.

Três fatos definem um arquivo, e nenhum deles depende da palavra do operador. O primeiro é um **hash**: uma impressão digital calculada sobre os bytes, de modo que o endereço do conteúdo vem do que ele é, e não do nome que alguém deu a ele. O segundo é uma **assinatura**: uma prova matemática de quem publicou, que qualquer pessoa pode verificar sem pedir licença a um servidor. O terceiro é uma **história**: o nó registra onde o arquivo nasceu, quais réplicas existem e quem autorizou cada cópia. O resto do protocolo existe para proteger esses três fatos. A identidade protege a assinatura, as permissões protegem o acesso, a banda protege o recurso de quem guarda, a replicação protege o arquivo contra a queda de um servidor, e a transferência de posse e a sucessão de casa protegem você contra o desaparecimento do operador.

É igualmente importante dizer o que o HDAP **não** é. Ele não é uma blockchain, não tem uma moeda própria no seu núcleo e não promete anonimato de rede. Não é uma rede social nem um substituto da internet inteira. É uma camada de arquivamento com regras explícitas, pensada para quem quer possuir sua identidade e manter seus arquivos acessíveis mesmo quando o nó original sai do ar. Essa honestidade não é uma fraqueza; é o que permite que as garantias que existem sejam realmente confiáveis.

---

## Por que ele existe

Na internet de hoje, você não guarda seus arquivos: você aluga acesso a eles. A plataforma decide o formato, o limite, a política de remoção e o preço. Quando a conta é encerrada, o arquivo pode continuar existindo no disco de alguém, mas você perdeu o acesso, perdeu a prova de autoria e perdeu a capacidade de migrar. A relação é assimétrica: a plataforma sabe tudo sobre você, e você não sabe quase nada sobre o que ela fará amanhã.

O HDAP inverte essa relação. A identidade é um par de chaves que fica no seu computador, não em um cadastro. O arquivo é identificado pelo conteúdo, não pelo nome de uma empresa. A permissão é um documento assinado por você, não uma configuração que alguém pode mudar sem avisar. A réplica é verificável por hash, não uma promessa de backup. E a casa — o seu espaço dentro de um servidor — pode mudar de lugar sem que a identidade mude de nome. Se o nó cair, o arquivo pode estar em outro lugar. Se o operador mudar as regras, você pode levar sua casa para outro pyle.

Essa inversão tem um custo, e o custo é a responsabilidade. Não existe "esqueci minha senha", não existe atendimento que redefina seu acesso e não existe autoridade central para consertar um cofre perdido. O que existe, em troca, é um conjunto de mecanismos que você pode entender, auditar e repetir. O HDAP troca a confiança cega por trabalho verificável, e assume que você prefere ser dono a ser cliente.

---

## O que já está implementado

A versão 1.0 entregou o protocolo completo e os três programas que o tornam utilizável. A **identidade criptográfica** usa Ed25519 para assinatura e X25519 para o transporte, com um cofre local `krypte.hdap` protegido por Argon2id e ChaCha20-Poly1305. O **login 3FA por nó** combina assinatura de desafio, OTP em cadeia de hash e prova de conhecimento da chave de transporte. Os **documentos `.hdap`** são canônicos, assinados e versionados por `PREV_HASH`. Os **arquivos** carregam hash, assinatura e uma matriz de origem chamada `prytaneion`. As **permissões** são declaradas em `adeia.hdap`, por arquivo, pasta ou identidade, com escopo e expiração.

A camada econômica existe e é funcional. A **banda** é gerada por prova de trabalho (`mochthos`), consumida por um tratado de cessão (`syngraphe`) e limitada por uma cota de armazenamento (`moira`). A **replicação federada** usa handshake assinado, TLS pinado e verificação de hash em cada cópia. A **busca por hash** consulta o cache local, o livro global, a origem e as réplicas. A **transferência de posse** (`metabibasis`) é assíncrona e garante leitura irrevogável ao cedente. A **mudança de casa** (`house_move`) é assinada pelo usuário e funciona mesmo com a origem offline. A **sucessão de casa** (`diadosi.hdap`) permite que fallbacks assumam quando o pyle principal morre. O **DDNS interno** (`kerux`) oferece aliases verificáveis para URIs `HDAP!`. E o **filtro de replicação e leitura por pyle** (`DIADOSI=white/black`) permite restringir onde a casa circula.

Na ponta, há três portas de entrada que falam o mesmo protocolo. O **hdap-gui** é o aplicativo de desktop, em português, inglês, espanhol e francês, com explorador de arquivos, editor de documentos, painel de configuração, busca por hash e resolução de alias na barra de endereço. O **hdap-cli** serve para automação e operação em servidores. E o **hdap-server** é o pyle, a peça que guarda conteúdo e participa da federação.

A **v2.0 (Teleios)** endurece o núcleo sem romper documentos. Todo tempo de protocolo é Unix UTC — o cliente nunca usa o próprio fuso para decidir validade. As chaves de sessão e a raiz da cadeia OTP passam por HKDF-SHA256, o passo OTP respeita o `otp_k` cadastrado (teto absoluto de 4096) e o terceiro fator assina o texto canônico do desafio emitido pelo servidor. Tokens de sessão são gravados apenas como `v2:{sha256(...)}`, e a chave mestra pode ficar fora do banco com `--master-key-file`. A autoria (`origin_user`) foi separada do dono do namespace (`namespace_owner`), e um upload idêntico ao existente não cobra banda. Handlers de rede não entram em pânico, limites de conexão e limpeza periódica são configuráveis, e `--time-tolerance` ajusta a tolerância de relógio apenas na federação. O MOTD — chamado **Ángelma** — aceita tags `HDAP{[tag]}`; CLI e GUI mostram Ángelma e UTC, e a rotação **OMPHALOS** passa a exigir assinatura da chave de identidade.

---

## Arquitetura em uma imagem

```
                    ┌──────────────────────────────┐
                    │        hdap-gui (egui)       │
                    │  explorador · editor · DDNS  │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │        hdap-cli (Rust)       │
                    │  fluxo de cliente · HTTP/1.1 │
                    └──────────────┬───────────────┘
                                   │  TLS + pin
                    ┌──────────────▼───────────────┐
                    │       hdap-server (pyle)     │
                    │  API · SQLite · federação    │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │        hdap-core (Rust)      │
                    │ docs · crypto · identidade   │
                    │ PoW · permissões · protocolo │
                    └──────────────────────────────┘
```

O `hdap-core` é deliberadamente **sem I/O**: ele não sabe que existe rede. O servidor, o CLI e a GUI compartilham o mesmo núcleo, então uma regra de documento ou de permissão nunca é reimplementada de forma divergente. O `hdap-tls` gera um certificado auto-assinado por nó, persiste a identidade TLS em disco e permite que clientes fixem o pin na primeira conexão, no modelo TOFU.

---

## Como a confiança funciona

O HDAP não pede que você confie no servidor; pede que você verifique. Quando você pergunta quem publicou um arquivo, a resposta é uma assinatura Ed25519 sobre os bytes crus. Quando pergunta se o arquivo mudou, a resposta é o hash do conteúdo, que faz parte do endereço. Quando pergunta se pode ler, a resposta é uma `adeia.hdap` assinada pelo dono, ou uma recusa explícita com `403`. Quando pergunta se uma cópia é verdadeira, o nó verifica o hash ao receber e registra a origem no `prytaneion`. Quando pergunta o que acontece se o pyle sumir, a resposta é a mudança de casa (`house_move`) ou a assunção por um fallback (`diadosi`). E quando pergunta o que acontece se o operador mentir, a resposta é que você troca de pyle e leva sua identidade, enquanto a história assinada continua verificável.

A confiança não é uma promessa: é uma sequência de provas que qualquer cliente pode repetir. É por isso que o protocolo é pequeno o suficiente para ser reimplementado e forte o suficiente para ser auditado.

---

## Começando

### Baixar uma versão pronta

Os pacotes de cada sistema ficam em **[Releases](https://github.com/Hsyst-Eleuthery/hdap/releases)**. A release **v2.0 (Teleios)** é empacotada como `2.0.0`. Para Linux x86_64 com biblioteca estática, baixe `hdap-2.0.0-x86_64-unknown-linux-musl.tar.gz`, que é a opção mais portátil e não depende da glibc do sistema. Para Linux x86_64 com glibc, baixe `hdap-2.0.0-x86_64-unknown-linux-gnu.tar.gz`. Para Windows x86_64, baixe `hdap-2.0.0-x86_64-pc-windows-gnu.zip`. Cada pacote inclui `hdap-server`, `hdap-gui` e `hdap-cli` — com a extensão `.exe` no Windows — e um checksum SHA-256. Confira o checksum antes de executar qualquer binário.

### Compilar do código

Os requisitos são **Rust 1.95+** e `cargo`. Clone o repositório, entre na pasta e compile o workspace em modo release:

```bash
git clone https://github.com/Hsyst-Eleuthery/hdap.git
cd hdap
cargo build --release --workspace
```

Os binários ficam em `target/release/`. O guia completo de compilação, testes e empacotamento está em **[docs/guia-de-execucao.md](docs/guia-de-execucao.md)**.

### Subir um nó local

No Linux ou macOS, suba o servidor apontando para um diretório de dados:

```bash
./target/release/hdap-server \
  --listen 127.0.0.1:8443 \
  --data ./hdap-node-data
```

No Windows, o comando equivalente em PowerShell é:

```powershell
.\hdap-server.exe --listen 127.0.0.1:8443 --data .\hdap-node-data
```

Na primeira execução, o nó cria o banco `hdap.db`, a identidade TLS `tls.identity` e exporta `tls.crt` e `tls.key` para inspeção. O `tls_pin` aparece no stderr e em `GET /health`. Guarde esse valor: é a impressão digital que o cliente usa para saber que está falando com o nó certo. Se o `tls.identity` for perdido, o pin muda e os clientes passam a recusar a conexão.

### Abrir a GUI

Execute `./target/release/hdap-gui`. No primeiro uso, informe o host (`127.0.0.1`), a porta (`8443`), o pin TLS — vazio na primeira conexão, para o TOFU, e depois o valor exibido pelo nó —, o nickname e a senha que protege o cofre local. A GUI cria a identidade, registra no nó e abre o explorador. A partir daí você pode subir arquivos, criar pastas, editar documentos `.hdap`, publicar aliases e configurar permissões.

### Usar o CLI

O CLI é a ferramenta de automação. Por segurança, ele não exige `--pass` na linha de comando: prefira `--pass-env`, `--pass-file` ou deixe que ele peça a passphrase no terminal, com eco desligado. O exemplo abaixo define uma função de conveniência, inicializa a identidade, registra no nó e obtém o token de sessão e o ID global:

```bash
export PIN='cole-o-pin-impresso-pelo-servidor'
export HDAP_PASS='uma-senha-forte'
hdap() {
  ./target/release/hdap-cli \
    --host 127.0.0.1 --port 8443 --tls-pin "$PIN" \
    --home ./minha-identidade --pass-env HDAP_PASS "$@"
}

hdap init thais
hdap register
ID=$(hdap whoami)
TOKEN=$(hdap auth | awk '{print $2}')
```

O comando `auth` imprime um token de sessão e `whoami` imprime o **ID global**, como `thais_a1b2c3d4`. Use os dois nos comandos seguintes:

```bash
hdap band "$TOKEN" 14
hdap upload "$TOKEN" "$ID" docs/nota.txt ./nota.txt
hdap list "$TOKEN" "$ID" docs
hdap download "$TOKEN" "$ID" docs/nota.txt ./copia.txt
```

O `OWNER` nos comandos de arquivo é o ID global (`$ID`), não apenas o nickname. O pin é obrigatório contra um nó TLS; sem `--tls-pin`, o CLI fala HTTP simples, o que só deve ser usado contra um nó iniciado com `--no-tls` em loopback. As opções globais podem vir antes ou depois do comando.

O comando `health` não pede identidade nem passphrase e mostra `protocol=v2 (Teleios)`, `time_utc`/`date_utc`, uptime, contadores e a Ángelma do nó. A rotação da âncora OTP usa o token da sessão atual e a chave de identidade — um token roubado sozinho não pode tomar a conta:

```bash
hdap health
hdap rotate "$TOKEN"
hdap auth   # atualize TOKEN com a nova cadeia OTP
```

`--pass` ainda funciona, mas imprime um aviso: a senha fica visível na lista de processos.

---

## Três pyles, três casas (teste local)

Para ver a federação funcionando na sua máquina, suba três nós em portas diferentes e três GUIs com cofres separados:

```bash
./target/release/hdap-server --listen 127.0.0.1:8443 --data ./.dev/nodeA &
./target/release/hdap-server --listen 127.0.0.1:8444 --data ./.dev/nodeB &
./target/release/hdap-server --listen 127.0.0.1:8445 --data ./.dev/nodeC &

HDAP_HOME=./.dev/guiA ./target/release/hdap-gui &
HDAP_HOME=./.dev/guiB ./target/release/hdap-gui &
HDAP_HOME=./.dev/guiC ./target/release/hdap-gui &
```

Registre uma identidade em cada nó e experimente replicação, permissões e mudança de casa. A federação é aberta por padrão: qualquer pyle pode fazer o primeiro contato e tem a chave que apresenta fixada nesse momento.

---

## Produção

Um nó de produção precisa de três coisas: TLS, persistência e uma política de acesso consciente. O comando abaixo sobe um nó em todas as interfaces, anuncia o endereço público, limita a cota por usuário, o tamanho de cada upload e a taxa de conexões:

```bash
./target/release/hdap-server \
  --listen 0.0.0.0:8443 \
  --advertise arquivo.exemplo.com:8443 \
  --data /var/lib/hdap \
  --moira 10737418240 \
  --max-upload 104857600 \
  --rate-limit 60 \
  --motd "HDAP Ángelma · uptime HDAP{[uptime]}" \
  --master-key-file /var/lib/hdap/master.key \
  --max-connections 256 \
  --cleanup-interval 60 \
  --time-tolerance 300
```

TLS é obrigatório fora de loopback: o nó se recusa a subir em claro em endereço não local. O diretório `--data` deve apontar para um disco persistente e com backup. A `--moira` limita o armazenamento por usuário, e `0` significa ilimitado. O `--max-upload` limita o tamanho de cada arquivo, e o `--rate-limit` reduz abuso de conexões. O `--advertise` é o endereço público que os pares usam para chegar até você e também define o id padrão do nó (`pyle-<base64(advertise)>`); sem ele, um bind em `0.0.0.0` geraria um id inalcançável. Um `--id` explícito vence o `--advertise`. A federação é sempre aberta: qualquer pyle pode se apresentar e passa a ser conhecido com a chave fixada no primeiro contato; entradas em `federation_peers` apenas reforçam o pin de um par já conhecido.

`--motd` (ou `--motd-file`) define a Ángelma exibida em `/health`, `/motd`, no CLI e na GUI; as tags usam a forma `HDAP{[tag]}` (por exemplo `uptime`, `users`, `protocol`). `--master-key-file` guarda a chave mestra dos blobs em um arquivo hexadecimal de 32 bytes com modo `0600`, fora do banco — o DB fica com a linha zerada, e uma chave v1 existente é migrada na primeira inicialização. `--max-connections` limita conexões simultâneas e responde `503` acima do limite; `--cleanup-interval` remove desafios e sessões expirados (`0` desativa); `--time-tolerance` é a tolerância de relógio para assinaturas de federação, sem afetar a validade das sessões. Todas as respostas carregam `X-HDAP-Server-Time` com o segundo Unix UTC do nó.

O processo não precisa de root. Rode com um usuário dedicado, mantenha o diretório de dados fora de `/tmp` e faça backup de `tls.identity` e da chave mestra junto com o banco, porque sem eles o pin do nó muda e os blobs ficam ilegíveis. Detalhes de operação, systemd, firewall e recuperação estão no **[Guia do Usuário](docs/userguide6.md)** e no **[Manual Técnico](docs/tecnico.md)**.

---

## Pyles oficiais

Estes são os nós públicos operados pelo projeto. Use-os para publicar, replicar ou simplesmente para alcançar a rede:

| Endereço | Id do pyle (derivado do endereço) |
| --- | --- |
| `pyle1.hdap.hsyst.org:8443` | `pyle-cHlsZTEuaGRhcC5oc3lzdC5vcmc6ODQ0Mw` |
| `pyle2.hdap.hsyst.org:8444` | `pyle-cHlsZTIuaGRhcC5oc3lzdC5vcmc6ODQ0NA` |
| `pyle3.hdap.hsyst.org:8445` | `pyle-cHlsZTMuaGRhcC5oc3lzdC5vcmc6ODQ0NQ` |
| `pyle.thais.fyi:8443` | `pyle-cHlsZS50aGFpcy5meWk6ODQ0Mw` |

Esses valores são **ids de pyle**, derivados do endereço anunciado — não são pins TLS. Um nó que se anuncia nesses endereços deve subir com `--listen 0.0.0.0:<porta> --advertise <endereço>`, para que o id derivado seja o endereço público, e não o bind curinga. Obtenha o pin de cada nó em `GET /health` (`tls_pin`) por um canal confiável e fixe-o no primeiro contato (`--tls-pin` na CLI); o pin TOFU é a proteção contra MITM, e conhecer o endereço de um pyle não prova quem responde ali.

---

## Qualidade e verificação

O HDAP é construído com testes antes de promessas. A suíte tem **250 testes automatizados** cobrindo núcleo, servidor, CLI, TLS e GUI, além de um teste manual de integração com nó real. A geração v2 acrescenta testes para F3 vinculado ao desafio, limites do OTP, cofre v1/v2, sessões hashadas, chave mestra externa, rotação OMPHALOS assinada e exibição da Ángelma/UTC na GUI. Há **testes adversariais** para replay, OTP, pin errado, CR isolado, request smuggling, permissão negada, réplica divergente e delete não autorizado. Há **fuzzing** dos parsers de documento e de requisição HTTP. O **modelo de ameaça** tem 48 entradas `AME-*`, cada uma ligada a uma mitigação e, quando aplicável, a um teste. E o CI exige formatação e lint (`cargo fmt --check`, `cargo clippy -D warnings`) antes de qualquer merge.

O objetivo não é dizer que o sistema é invulnerável — isso seria mentira. É garantir que cada garantia declarada tenha um mecanismo correspondente e um teste que tente quebrá-la.

---

## Limites honestos

Nenhum sistema é soberano sem custo. Não existe recuperação central de senha: se você perder o `krypte.hdap` ou a senha, a identidade está perdida, e a única defesa é o backup. A criptografia em repouso protege o disco, não o operador: o nó precisa da chave mestra para servir os arquivos, e um operador com acesso total ao processo consegue lê-los. Os metadados são públicos por design, porque nomes, hashes e tamanhos fazem parte da verificação. A deleção é incentivo e reputação, não garantia física: um nó que já copiou o conteúdo pode tentar retê-lo, e o protocolo registra e penaliza, mas não teleporta para dentro do disco alheio. A federação é aberta por design: o primeiro contato fixa a chave do par, e o conteúdo continua protegido por assinatura e hash. E não há consenso global: o HDAP é federado, não uma blockchain, e a convergência é por documentos assinados e sincronização, não por votação global. O token de sessão também é determinístico para `(chave compartilhada, servidor, expiração)` — dois logins no mesmo segundo podem produzir o mesmo valor; ele não é um nonce aleatório.

Esses limites estão documentados em detalhe no **[Modelo de Ameaça](docs/modelo-de-ameaca.md)**.

---

## Versionamento e codinomes

Todo lançamento do HDAP carrega dois codinomes. O **codinome de protocolo** dá nome a uma geração da linguagem do protocolo e muda apenas quando a forma como os nós conversam ou como os documentos são interpretados muda. O **codinome de lançamento** dá nome ao pacote como um todo e muda em qualquer release, inclusive nas correções que não tocam o protocolo. A versão 1.0 é o marco zero, com o protocolo **Themelio** e o lançamento **Veritas Aeterna**; a v1.001 manteve **Themelio** e trouxe **Epoptia**. A v2.0 abre a geração **Téleia vási**, com protocolo **Teleios** — também o codinome de lançamento desta release.

As regras valem para sempre. Correções e melhorias dentro da geração v2 saem como `v2.001`, `v2.002` e assim por diante: apenas o codinome de lançamento muda, e o protocolo permanece **Teleios**. Mudanças na linguagem do protocolo abrem uma versão maior com os dois codinomes novos. O formato dos documentos é independente: `# VERSION: 1` continua valendo na v2. Toda release atualiza a documentação, declara os dois codinomes e ajusta as datas de revisão. O histórico completo fica no **[CHANGELOG](CHANGELOG.md)** e o resumo da geração em **[docs/VERSAO.md](docs/VERSAO.md)**.

---

## Documentação

A [versão em inglês deste README](README.en.md) está disponível para quem prefere. O **[Guia do Usuário](docs/userguide.md)** é a porta de entrada e explica o protocolo em linguagem simples, com capítulos sobre identidade, arquivos, economia, federação e operação. A **[Visão da v2](docs/VERSAO.md)** resume o que mudou em relação à geração Themelio. O **[Guia de Execução](docs/guia-de-execucao.md)** cobre compilação, testes, cross-build, empacotamento e o checklist de release. O **[Manual Técnico](docs/tecnico.md)** descreve a arquitetura e as decisões de engenharia, enquanto a **[Especificação Formal](docs/especificacao-hdap.md)** define a semântica normativa e o **[RFC-HDAP](docs/rfc-hdap.md)** descreve o formato de fio e as rotas. Para segurança, o **[Modelo de Ameaça](docs/modelo-de-ameaca.md)** lista ameaças, mitigações e o que não está coberto. O **[Léxico Grego](docs/lexico-grego.md)** reúne o vocabulário canônico e a **[Filosofia Econômica](docs/filosofia-economica.md)** explica a base do módulo de preço e reputação. Para o predecessor, o **[HPS](docs/hps.md)** conta a história e as lições que deram origem ao HDAP. O histórico de mudanças está no **[CHANGELOG](CHANGELOG.md)** e a política de reporte de vulnerabilidades no **[SECURITY](SECURITY.md)**.

---

## Contato

O HDAP é mantido por **Thaís (op3n/op3ny)**, fundadora do ecossistema Hsyst. Para dúvidas, colaboração ou imprensa:

- E-mail: [thais@hsyst.org](mailto:thais@hsyst.org)
- GitHub: [@op3ny](https://github.com/op3ny)
- Discord: `@op3n`
- XMPP: `thais@xmpp.hsyst.org`
- Blog: [blog.thais.fyi](https://blog.thais.fyi)
- Site e chave OpenPGP pública: [thais.fyi](https://thais.fyi) · [keys.thais.fyi](https://keys.thais.fyi)

Para reporte de vulnerabilidades, siga a política em **[SECURITY](SECURITY.md)**.

---

## Licença

MIT. Veja [LICENSE](LICENSE).

---

<p align="center">
<strong>HDAP — guarde com prova, não com permissão.</strong><br>
Criado por <a href="https://github.com/op3ny">Thaís (op3n/op3ny)</a> ·
<a href="mailto:thais@hsyst.org">thais@hsyst.org</a> ·
<a href="https://thais.fyi">thais.fyi</a>.
</p>
