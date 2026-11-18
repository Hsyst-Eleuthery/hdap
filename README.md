# HDAP — Hsyst Descentralized Archive Protocol

> **Arquivos com autoria. Memória com prova. Uma casa que não depende de um único servidor.**

*Revisão de 2026-11-17 · v2.0.0 (Téleia vási · Teleios).*

## Tradução rápida

O vocabulário vem do grego antigo para que os nomes sejam estáveis entre idiomas. Estes são os termos que aparecem primeiro:

| Termo | Leitura rápida | O que é no HDAP |
| --- | --- | --- |
| **pyle** | “pilar” | Um nó da rede — o servidor que guarda arquivos. |
| **prosopeion** | “máscara” | A identidade: par de chaves que fica no seu computador. |
| **krypte** | “cofre” | O arquivo local `krypte.hdap`, onde as chaves ficam cifradas. |
| **doma** | “casa” | O seu espaço dentro de um pyle. |
| **adeia** | “permissão” | O documento assinado que diz quem lê ou escreve no seu espaço. |
| **moira** | “parte” | A cota de armazenamento de cada conta. |
| **mochthos** | “trabalho” | O crédito de banda, obtido com prova de trabalho. |
| **syngraphe** | “contrato” | O recibo que debita banda de um mochthos. |
| **prytaneion** | “registro público” | O livro-razão que registra origem, réplicas e transferências. |
| **omphalos** | “umbigo” | A âncora da cadeia de senhas de uso único (OTP). |
| **pylaia** | “portaria” | A prova de trabalho exigida no login para desestimular abuso. |
| **phemé** | “fama” | A reputação que incentiva a deleção e a boa conduta. |
| **metabibasis** | “transferência” | A mudança de posse ou de casa entre nós. |
| **Téleia vási** | “base completa” | A geração atual do protocolo; codinome **Teleios**. |

O léxico completo está em [docs/lexico-grego.md](docs/lexico-grego.md).

oie, eu sou a **Thaís (op3n/op3ny)**. O HDAP nasceu de uma pergunta simples: como guardar arquivos de um jeito em que a posse, a autoria e a história não dependam da boa vontade de uma empresa? A resposta não foi criar mais uma nuvem — foi criar um protocolo pequeno o suficiente para ser entendido e forte o suficiente para ser verificado.

Esta é a versão **v2.0**, a geração **Téleia vási** do protocolo, com codinome **Teleios**. Ela sucede a v1.001 (**Themelio · Epoptia**) sem trocar o formato dos documentos: `# VERSION:` continua `1`. O que muda é a linguagem de interoperabilidade entre nós — tempo Unix UTC em todas as provas, derivação HKDF, sessões gravadas como hash, cofre versionado e autenticação ligada ao desafio emitido pelo servidor. A visão completa da geração está em [docs/VERSAO.md](docs/VERSAO.md).

[![CI](https://github.com/Hsyst-Eleuthery/hdap/actions/workflows/ci.yml/badge.svg)](https://github.com/Hsyst-Eleuthery/hdap/actions/workflows/ci.yml)
[![Licença: MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-blue.svg)](LICENSE)

**[Guia do Usuário](docs/guia-1-introducao.md)** · **[Visão v2](docs/VERSAO.md)** · **[Manual Técnico](docs/tecnico.md)** · **[Especificação](docs/especificacao-hdap.md)** · **[RFC](docs/rfc-hdap.md)** · **[Modelo de Ameaça](docs/modelo-de-ameaca.md)** · **[Downloads](https://github.com/Hsyst-Eleuthery/hdap/releases)**

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

## Começando em 5 minutos

> Se quiser só ver o protocolo funcionando, a sequência mínima é: subir um nó, ler o `tls_pin` no stderr, criar a identidade com `init`, registrar, autenticar e subir um arquivo. Os comandos estão em [Usar o CLI](#usar-o-cli) logo abaixo. Sem CET, sem cadastro de e-mail e sem servidor central.

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

### Faça o backup agora

A identidade é o par de chaves dentro de `krypte.hdap`, cifrado pela sua passphrase. **Não existe recuperação central**: perder o cofre ou a senha é perder a identidade. Logo após `hdap init`, copie `krypte.hdap` para pelo menos dois lugares físicos separados e guarde a senha em outro lugar (um gerenciador de senhas, por exemplo). Se usa o servidor, faça backup de `tls.identity`, da chave mestra passada em `--master-key-file` e do banco **juntos**: sem a identidade TLS o pin muda; sem a chave mestra os blobs ficam ilegíveis. A GUI mostra o lembrete na criação da identidade; o CLI imprime o aviso no `init`.

### Perguntas frequentes

**Preciso de um e-mail ou de um servidor central?** Não. A identidade é um par de chaves local; o `user_id` é `nickname_suffix` derivado da chave pública. O servidor guarda o que é público e não tem sua chave secreta.

**Por que o upload deu erro de expiração/selo?** Todas as provas do protocolo usam segundos Unix UTC. O cliente não escolhe a validade com o relógio local: ele devolve exatamente o `ts` que o nó emitiu no desafio, e o nó usa o mesmo valor. Se você alterou o relógio a ponto de o nonce ter expirado, peça um desafio novo (`/proklesis`). A tolerância de relógio só se aplica entre nós federados; nunca à sessão do usuário.

**A assinatura prova que eu criei o arquivo?** Não. Ela prova que a chave da identidade assinou **aqueles bytes**. Copiar um arquivo público e assiná-lo é possível. O que o protocolo registra é quem assinou e quem enviou primeiro (`origin_user`), separadamente de quem é o dono do namespace (`namespace_owner`). Em envio por conteúdo, o primeiro a publicar o hash vira a origem registrada.

**O que impede o operador de ler meus arquivos?** A cifragem em repouso protege o disco contra roubo do banco ou de backup — mas o nó precisa da chave mestra para servir os arquivos, então um operador com acesso total ao processo consegue lê-los. A chave mestra fora do banco (`--master-key-file`) impede que o roubo do banco sozinho leve o cadeado junto.

**Posso trocar a senha de uso único se perder a cadeia?** Sim, com `hdap rotate` e a chave de identidade. A rota `/omphalos` exige sessão **e** assinatura Ed25519 da chave cadastrada; um token roubado sozinho não altera a âncora.

**Por que o pin do TLS mudou?** Porque `tls.identity` foi recriado (reinstalação, troca de disco) ou porque há um MITM. Pare, compare com [docs/pins-oficiais.md](docs/pins-oficiais.md) e confirme fora da banda antes de aceitar.

### O que fazer se der errado

| Sintoma | Causa provável | Ação |
| --- | --- | --- |
| `factor 3 failed` no login | cliente antigo ou `ts` local substituído | atualize o cliente; ele deve devolver o `ts` do desafio, não o relógio local. Contas criadas antes da v2 ainda aceitam a prova legada. |
| `invalid or expired challenge` | desafio vencido ou já usado | rode `auth` de novo para obter nonce e `ts` novos. |
| `too many outstanding challenges` | muitos logins sem concluir | aguarde a expiração (`proklesis_ttl_secs`) ou ajuste `--max-challenges`. |
| `503 connection limit reached` | muitas conexões simultâneas | reduza workers ou aumente `--max-connections`. |
| `503 node degraded` | trava interna envenenada por uma falha anterior | reinicie o nó; a condição é preservada para não servir estado inconsistente. |
| `pin do TLS não confere` | identidade TLS recriada ou MITM | veja a pergunta acima; nunca aceite um pin novo sem verificação fora da banda. |
| arquivos ilegíveis após restore | chave mestra não restaurada junto do banco | restaure `--master-key-file` exatamente como estava; sem ela não há recuperação. |
| `identity key conflict` no registro | outra chave já usa esse `user_id` | escolha outro nickname/sufixo; re-registrar com a mesma chave é idempotente e seguro. |

Para diagnóstico, rode com `HDAP_LOG=debug` no servidor. Em produção use `HDAP_LOG=warn` (padrão) ou `error`.

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

O processo não precisa de root. Rode com um usuário dedicado, mantenha o diretório de dados fora de `/tmp` e faça backup de `tls.identity` e da chave mestra junto com o banco, porque sem eles o pin do nó muda e os blobs ficam ilegíveis. Detalhes de operação, systemd, firewall e recuperação estão no **[Guia do Usuário](docs/guia-6-operacao.md)** e no **[Manual Técnico](docs/tecnico.md)**.

---

## Pyles oficiais

Estes são os nós públicos operados pelo projeto. Use-os para publicar, replicar ou simplesmente para alcançar a rede:

| Endereço | `server_id` | `tls_pin` (SHA-256 do certificado) |
| --- | --- | --- |
| `pyle1.hdap.hsyst.org:8443` | `pyle-cHlsZTEuaGRhcC5oc3lzdC5vcmc6ODQ0Mw` | `e31eea2c5576724d58741ebfe6629065ab15bbfec2725f416280f820f3ccb2e0` |
| `pyle2.hdap.hsyst.org:8444` | `pyle-cHlsZTIuaGRhcC5oc3lzdC5vcmc6ODQ0NA` | `f94f5606d9f0f87a433ebdaa7fc3a9750df72698bc240a4d459286bdeb717f13` |
| `pyle3.hdap.hsyst.org:8445` | `pyle-cHlsZTMuaGRhcC5oc3lzdC5vcmc6ODQ0NQ` | `01dd1c576af6559bcaf0ecc6590ce8c22518b4ed6f0e4ac5bd90dcc247d41d5f` |
| `pyle.thais.fyi:8443` | `pyle-cHlsZS50aGFpcy5meWk6ODQ0Mw` | `c270bafd948dc5bb185009973099702789b3c7f4eea414670a1180b9f9162573` |

O **id do pyle** é derivado do endereço anunciado; o **pin** é o SHA-256 do DER do certificado TLS e é o que realmente autentica o nó. Um nó que se anuncia nesses endereços deve subir com `--listen 0.0.0.0:<porta> --advertise <endereço>`, para que o id derivado seja o endereço público, e não o bind curinga.

> Confira estes pins **fora da banda** antes de confiar neles: a tabela completa, as chaves de cada nó e a impressão digital OpenPGP da mantenedora estão em [docs/pins-oficiais.md](docs/pins-oficiais.md). O pin fixado na primeira conexão (TOFU) é a proteção contra MITM; conhecer o endereço de um pyle não prova quem responde ali. Um anúncio assinado com a chave `3D97 B7C2 7095 4A1C 590C 4233 B8E0 166A AB5F 47D8` é a forma preferida de receber uma atualização de pin.

---

## Qualidade e verificação

O HDAP é construído com testes antes de promessas. A suíte tem **269 testes automatizados** cobrindo núcleo, servidor, CLI, TLS e GUI, além de um teste manual de integração com nó real. A geração v2 acrescenta testes para F3 vinculado ao desafio, limites do OTP, cofre v1/v2, sessões hashadas, chave mestra externa, rotação OMPHALOS assinada e exibição da Ángelma/UTC na GUI. Há **testes adversariais** para replay, OTP, pin errado, CR isolado, request smuggling, permissão negada, réplica divergente e delete não autorizado. Há **fuzzing** de cinco parsers: documento `.hdap`, requisição HTTP, linhas de permissão `adeia`, URI de acesso `HDAP!` e cofre `krypte.hdap`. O **modelo de ameaça** tem 48 entradas `AME-*`, cada uma ligada a uma mitigação e, quando aplicável, a um teste. E o CI exige formatação e lint (`cargo fmt --check`, `cargo clippy -D warnings`) antes de qualquer merge.

O objetivo não é dizer que o sistema é invulnerável — isso seria mentira. É garantir que cada garantia declarada tenha um mecanismo correspondente e um teste que tente quebrá-la.

---

## Limites honestos

Nenhum sistema é soberano sem custo. Não existe recuperação central de senha: se você perder o `krypte.hdap` ou a senha, a identidade está perdida, e a única defesa é o backup. A criptografia em repouso protege o disco, não o operador: o nó precisa da chave mestra para servir os arquivos, e um operador com acesso total ao processo consegue lê-los. Os metadados são públicos por design, porque nomes, hashes e tamanhos fazem parte da verificação. A deleção é incentivo e reputação, não garantia física: um nó que já copiou o conteúdo pode tentar retê-lo, e o protocolo registra e penaliza, mas não teleporta para dentro do disco alheio. A federação é aberta por design: o primeiro contato fixa a chave do par, e o conteúdo continua protegido por assinatura e hash. E não há consenso global: o HDAP é federado, não uma blockchain, e a convergência é por documentos assinados e sincronização, não por votação global. O token de sessão também é determinístico para `(chave compartilhada, servidor, expiração)` — dois logins no mesmo segundo podem produzir o mesmo valor; ele não é um nonce aleatório.

Esses limites estão documentados em detalhe no **[Modelo de Ameaça](docs/modelo-de-ameaca.md)**.

---

## Versionamento e codinomes

Cada release tem um **codinome de protocolo** (a geração da linguagem entre nós) e um **codinome de lançamento** (o pacote). A v1.0 foi **Themelio · Veritas Aeterna**, a v1.001 foi **Themelio · Epoptia**, e a v2.0 abre **Téleia vási · Teleios**. Correções dentro da v2 saem como `v2.001`, `v2.002` e assim por diante, mantendo **Teleios**; o formato `# VERSION: 1` é independente da geração. A política completa — com as regras de bump, a tabela de codinomes e o histórico — está em **[docs/VERSAO.md](docs/VERSAO.md)**; o histórico ponto a ponto está no **[CHANGELOG](CHANGELOG.md)**.

---

## Documentação

A [versão em inglês deste README](README.en.md) está disponível para quem prefere. O **[Guia do Usuário](docs/guia-1-introducao.md)** é a porta de entrada e explica o protocolo em linguagem simples, com capítulos sobre identidade, arquivos, economia, federação e operação. A **[Visão da v2](docs/VERSAO.md)** resume o que mudou em relação à geração Themelio. O **[Guia de Execução](docs/guia-de-execucao.md)** cobre compilação, testes, cross-build, empacotamento e o checklist de release. O **[Manual Técnico](docs/tecnico.md)** descreve a arquitetura e as decisões de engenharia, enquanto a **[Especificação Formal](docs/especificacao-hdap.md)** define a semântica normativa e o **[RFC-HDAP](docs/rfc-hdap.md)** descreve o formato de fio e as rotas. Para segurança, o **[Modelo de Ameaça](docs/modelo-de-ameaca.md)** lista ameaças, mitigações e o que não está coberto. O **[Léxico Grego](docs/lexico-grego.md)** reúne o vocabulário canônico e a **[Filosofia Econômica](docs/filosofia-economica.md)** explica a base do módulo de preço e reputação. Para o predecessor, o **[HPS](docs/hps.md)** conta a história e as lições que deram origem ao HDAP. O histórico de mudanças está no **[CHANGELOG](CHANGELOG.md)** e a política de reporte de vulnerabilidades no **[SECURITY](SECURITY.md)**.

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
