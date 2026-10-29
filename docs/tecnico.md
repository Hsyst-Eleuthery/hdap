# Manual Técnico — HDAP

**HDAP v1.001 — Themelio · Epoptia**

**Escrito por Thaís (op3n/op3ny)**

---

## 1. Uma introdução honesta

oie. Se você chegou até aqui, provavelmente quer saber o que o HDAP realmente faz, e não apenas o que ele promete.

O HDAP é um protocolo de arquivamento federado. Ele guarda arquivos assinados, prova quem os publicou, mantém uma história verificável de origem e permite que cópias sobrevivam à queda de um nó. O objetivo não é substituir a internet inteira. É resolver uma parte pequena e importante dela: **arquivos que pertencem a alguém e que continuam existindo quando o servidor muda de ideia**.

Este manual explica a arquitetura em linguagem de engenharia, mas sem transformar cada detalhe de implementação em pré-requisito. A especificação formal, o RFC e o modelo de ameaça continuam disponíveis para quem quiser descer ao nível de bytes, rotas e provas criptográficas.

A tese central do projeto é simples: **confiança não deve ser exigida onde pode ser substituída por prova**. Toda vez que o HDAP toma uma decisão, ele tenta responder a três perguntas. A primeira é quem assinou isto, e a resposta é uma assinatura Ed25519 verificável com a chave pública. A segunda é se os bytes são os mesmos que foram assinados, e a resposta é o hash do conteúdo, calculado sobre os bytes crus. A terceira é se esta pessoa tem o direito de fazer isso agora, e a resposta é uma permissão assinada pelo dono, avaliada pelo nó. Se qualquer uma dessas respostas depender apenas da palavra de um operador, o desenho ainda não está pronto.

---

## 2. Visão geral da arquitetura

O HDAP é dividido em cinco crates Rust:

| Componente | Papel |
|---|---|
| `hdap-core` | Núcleo sem I/O: documentos, criptografia, identidade, autenticação, PoW, permissões e protocolo. |
| `hdap-server` | Nó (`pyle`): API HTTP/TLS, persistência SQLite, federação, replicação, reputação. |
| `hdap-tls` | Certificado auto-assinado por nó, persistência do pin e cliente TLS com pinning. |
| `hdap-cli` | Cliente de linha de comando e biblioteca de fluxo usada pela GUI. |
| `hdap-gui` | Aplicativo desktop em `egui` para explorar arquivos, editar documentos e operar a casa. |

A regra de ouro é: **o núcleo não sabe que existe rede**. O servidor não reimplementa a validação de um documento; ele chama o núcleo. O CLI e a GUI também. Isso evita a pior forma de divergência em sistemas distribuídos: dois clientes concordarem sobre o formato e o servidor discordar dos dois.

```
Cliente (GUI/CLI) ── TLS/pin ──> Pyle (servidor) ── SQLite
        │                            │
        └──── mesmos documentos ─────┘
                     │
                hdap-core
```

O estado durável do nó fica em SQLite com WAL e `synchronous=FULL`. A gravação acontece antes da resposta de sucesso: se o disco falhar, o cliente não recebe um `200` que o nó não cumpriu.

---

## 3. Identidade: a casa é sua

Uma identidade no HDAP é um par de chaves:

- **Ed25519** para assinar documentos e provar autoria;
- **X25519** para a etapa de transporte da autenticação;
- uma **seed OTP** local, usada em cadeia de hash;
- um `prosopeion.hdap` público, auto-assinado, que declara nickname, sufixo, chaves e âncora OTP.

As chaves privadas nunca são enviadas ao servidor. Elas ficam no `krypte.hdap`, cifrado com Argon2id + ChaCha20-Poly1305. A senha do usuário não sai do computador.

O identificador global tem a forma `nickname_sufixo`, em que o sufixo é derivado da chave. Ele não é um cadastro central: é uma identidade que pode ser registrada em qualquer pyle sem deixar de ser a mesma.

### O que o login prova

O login é dividido em três fatores por nó:

1. **Assinatura de desafio** — prova que o cliente tem a chave Ed25519.
2. **Passo OTP** — revela o próximo elo de uma cadeia de hash; o nó recusa passos já usados.
3. **Prova de conhecimento da chave de transporte** — um HMAC sobre o segredo derivado de X25519.

O resultado é um `symbolon`, token de sessão válido apenas naquele nó. A sessão não é global. O que é global é a identidade.

O servidor é a autoridade sobre o passo OTP. Se o cliente perde o contador local, ele pergunta ao nó qual é o próximo passo — e o teste automatizado cobre esse caso. O contrário (cliente mandar um passo que o nó já viu) é rejeitado.

### Limite importante

Os três fatores vivem no mesmo cofre local. Isso protege contra roubo de um fator isolado e contra replay, mas **não** protege contra um cofre comprometido. O modelo de ameaça diz isso explicitamente; um manual que escondesse esse fato seria propaganda, não engenharia.

---

## 4. Documentos `.hdap`: a unidade de verdade

Todo objeto relevante do protocolo é um documento textual canônico:

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
# PERM0000: PERM thais_a3f9c2d1e0b7aa11 all / read
### :END BODY
### SIGS:
# SIGNER: thais_a3f9c2d1e0b7aa11
# SIGNATURE: <base64>
### :END SIGS
## :END DOC
```

As regras de canonicalização são rígidas de propósito:

- ordem fixa de seções e chaves;
- uma chave por linha, sem duplicatas;
- assinatura sobre os bytes do documento, não sobre uma serialização JSON intermediária;
- `EDITION > 1` exige `PREV_HASH`, formando uma cadeia de edições.

A assinatura cobre os bytes crus. Isso elimina a classe de bugs em que dois sistemas assinam "o mesmo" objeto com representações diferentes.

### Tipos principais

| Tipo | Função |
|---|---|
| `prosopeion` | Identidade pública e chaves. |
| `adeia` | Permissões e filtro de diádosi. |
| `mochthos` | Prova de trabalho que gera banda. |
| `syngraphe` | Tratado que consome a banda no upload. |
| `metabibasis` | Pedido/aceite de transferência de posse. |
| `prytaneion` | Matriz de origem e réplicas. |
| `pheme` / `pheme_candidate` | Sinais de reputação. |
| `kerux` | Alias DDNS. |
| `timi` | Tabela de preços do módulo econômico. |
| `diadosi` | Procuração de sucessão da casa. |
| `exousia` | Capacidade delegada em cadeia. |
| `link` | Ponteiro simbólico reservado. |

Os nomes gregos não são decoração: eles evitam colisões com termos genéricos e tornam explícito que cada objeto tem uma semântica própria. O glossário completo está em [lexico-grego.md](lexico-grego.md).

---

## 5. O namespace: `HDAP!`

Uma URI de acesso tem a forma:

```
HDAP!<pyle>@<user>/<caminho>?hash
```

Exemplo:

```
HDAP!pyle-MTI3LjAuMC4xOjg0NDM@thais_a3f9c2d1/docs/nota.txt?hash=...
```

- `pyle` identifica o nó;
- `user` é a identidade global;
- `caminho` é relativo à raiz da casa;
- `hash` é opcional e serve para verificar conteúdo específico.

O hash no caminho não é decoração. Ele permite que o cliente confirme que o arquivo recebido é exatamente o que foi assinado, mesmo que o nó tenha sido comprometido ou esteja servindo uma versão antiga.

---

## 6. Armazenamento, integridade e leitura

Quando um arquivo é enviado:

1. o cliente calcula o hash;
2. assina os bytes crus;
3. o nó verifica hash, assinatura, permissão, banda e cota;
4. o conteúdo é cifrado em repouso com ChaCha20-Poly1305 sob a chave mestra do nó;
5. o nó grava o blob e registra a origem no `prytaneion`.

O hash público é do conteúdo em claro. O blob em disco é o ciphertext. Por isso a verificação de integridade na leitura é feita depois de decifrar; a linha do banco guarda tamanho e hash esperado, mas não finge que o ciphertext tem o mesmo hash do arquivo.

A leitura passa por `authorize`, que responde a uma pergunta objetiva: **a identidade autenticada nesta sessão tem `Read` para este caminho?** Se não tiver, o nó responde `403`. A GUI não decide isso no lugar do servidor; ela apenas desabilita o que sabe que não pode fazer, e o servidor continua sendo a autoridade.

---

## 7. Permissões sem mágica

A `adeia.hdap` é uma ACL declarativa e pública:

```
PERM <owner> all / read
PERM <owner> user:<user_id> docs/ write
PERM <owner> user:<user_id> docs/privado.txt deny
```

Cada linha tem sujeito (`all` ou `user:<id>`), caminho (`/`, pasta ou arquivo) e direito (`deny|read|write|own`). As regras são avaliadas do caminho mais específico para o mais geral; no mesmo caminho, um sujeito `user:<id>` vence `all` e `deny` vence os direitos positivos. Sem regra que conceda o pedido, a resposta é negativa. O sujeito é sempre a identidade autenticada — nunca um campo que o cliente enviou no corpo da requisição. A forma compacta de v1.0 (`PERM <owner> all read`) continua aceita.

O dono pode editar a ACL, mas não pode usar isso para desfazer uma transferência já concluída. Transferências gravam uma cessão (`ceession`) antes de copiar; a checagem de cessão é independente do texto da `adeia`. É isso que torna o read-only do cedente **irrevogável** sem depender de promessa.

O mesmo documento pode declarar um filtro de propagação:

```
DIADOSI=white:pyle-A;pyle-C;
DIADOSI=black:pyle-B;
```

`white` só permite cópia/leitura pelos pyles listados; `black` nega os listados. Documentos públicos de identidade (`prosopeion.hdap`, `adeia.hdap`, `diadosi.hdap`) são isentos do filtro de leitura, porque sem eles nem a verificação básica funcionaria.

---

## 8. Banda: custo explícito, não taxa escondida

O HDAP não cobra dinheiro por upload por padrão. Ele cobra **trabalho**.

O cliente resolve um desafio de PoW (`mochthos`) e recebe uma credencial de banda. Cada nó define sua política: quantos bytes valem por prova, qual é a dificuldade mínima e máxima, quantas provas por hora. O valor é recontado localmente pelo nó que recebe o upload.

O tratado (`syngraphe`) substitui a prova consumida e registra o que foi usado. Banda gasta não volta ao apagar o arquivo; isso é deliberado, senão o custo seria decorativo.

A dificuldade é do servidor, não do cliente. O cliente mede seu hashrate e declara; o nó aplica a política e limita a influência de alegações absurdas. Um teto por hora por conta fecha a porta que uma dificuldade adaptativa sozinha deixaria aberta.

O módulo econômico opcional (`katallaxia`, `timi`, `tokos`, `paratheke`) permite que nós publiquem preços e compitam por retenção. Ele não é necessário para o funcionamento básico do arquivo.

---

## 9. Federação: cópias com prova

Quando dois pyles se conhecem, eles fazem um handshake assinado com nonce e janela de tempo. A federação é sempre aberta: o primeiro contato de um pyle desconhecido é aceito e a chave que ele apresenta é fixada. Uma entrada opcional em `federation_peers` (`node_id → {pubkey, endpoint, tls_pin}`) apenas reforça esse pin, para que o mesmo id não possa ser reivindicado depois com outra chave.

A replicação funciona assim:

1. o nó A pergunta ao nó B quais hashes ele tem para um usuário;
2. para cada hash autorizado, A pede os bytes;
3. A verifica o hash e a assinatura de origem;
4. A re-sela o conteúdo sob sua própria chave mestra e registra a réplica;
5. A guarda quem replicou o quê, para conseguir avisar em caso de deleção.

O livro global (`ledger`) e o diretório de bolha (`bubble`) permitem descobrir pyles e conteúdo sem um servidor central. Eles são trocados por digest e convergem por merge idempotente.

Uma replicação pode ser negada por dois motivos legítimos: falta de permissão na `adeia` ou filtro `DIADOSI`. O nó que pediu recebe a contagem de arquivos negados, e a GUI mostra isso em vez de fingir que "espelhou zero".

---

## 10. Mudança de casa e sucessão

A casa é o pyle onde a identidade está registrada. Quando esse pyle fica indisponível, o usuário não deve ficar sem acesso.

### Mudança explícita (`house_move`)

O usuário assina uma mensagem com a nova casa e uma `adeia` de edição maior. O nó de destino verifica a assinatura, aplica a identidade e propaga a mudança aos pares. A origem pode estar offline; não é preciso pedir permissão a ela.

### Sucessão automática (`diadosi`)

O usuário publica um `diadosi.hdap` assinado com:

- `HOME_PYLE` — a casa atual;
- `FALLBACKS` — até 16 pyles que podem assumir;
- hashes e edição atuais da `adeia` e do `prosopeion`.

No início de um `/sync`, um fallback listado pode assumir a casa **somente se**:

- a assinatura do documento for válida;
- os hashes/edição baterem com os documentos atuais;
- o home ainda estiver anunciado como casa;
- o próprio fallback estiver na lista;
- o home estiver offline e o peer do home for conhecido com endpoint.

Sem documento assinado, não há promoção. Sem hash atual, não há promoção. Isso impede que um nó qualquer se declare herdeiro por conta própria.

Na GUI, o painel de backup carrega o `diadosi.hdap` existente ou sugere fallbacks dialáveis da bolha; você revisa a lista e assina. Depois de editar a `adeia` ou o `prosopeion`, a procuração antiga deixa de valer até ser reassinada.

---

## 11. Transferência de posse

O `metabibasis` é assíncrono:

1. o cedente monta um manifesto com alvos, hashes e escopos;
2. assina o pedido;
3. o cessionário vê a oferta numa inbox;
4. aceita e assina;
5. a origem bloqueia a escrita do cedente e copia os bytes;
6. o cessionário recebe uma cópia real, não um link.

O cedente mantém `Read` irrevogável sobre o que cedeu; perde `Write` e `Own`. Se o cessionário apagar a cópia, o destino avisa a origem e a cessão é liberada. Sem esse aviso, o conteúdo ficaria preso para sempre numa transferência que já não existe.

Escopos de pasta cobrem arquivos futuros. O manifesto congela hashes e tamanhos; se a origem mudar entre o pedido e o aceite, a operação falha com `409` em vez de copiar algo diferente do combinado.

---

## 12. Descoberta, aliases e bolha

O `kerux` é o DDNS interno: um documento por usuário mapeia aliases para URIs `HDAP!`. A resolução é pública e verificável por assinatura. Na GUI, digitar um alias na barra de endereço consulta `/kerux/{alias}`; se o alias não existir, a barra abre o caminho literal, para que um erro de DDNS não prenda o usuário.

A bolha (`/bubble`) classifica os pyles conhecidos em:

- `core` — handshake verificado e sem falhas;
- `extended` — dialável, ainda não confirmado;
- `untrusted` — sem endpoint ou com falhas repetidas.

O rodapé da GUI mostra o resumo. O painel de diádosi usa essa lista para sugerir fallbacks, excluindo o próprio nó, entradas sem endpoint e pyles `untrusted`.

---

## 13. Reputação: sinal, não tribunal

O `pheme` agrega sinais de comportamento. A pontuação de um nó é uma mediana dos scores observados pelos pares ativos, o que converge de forma determinística e tolera uma minoria bizantina.

O HDAP **não** tem um tribunal global. Uma penalidade (`oneidos`) é um registro público que influencia escolhas futuras; ela não teleporta para o disco de ninguém nem executa uma sentença. Como a federação é aberta, não existe uma lista de admissão que o operador possa podar. A reputação é um sinal — poderoso, mas não onipotente — e o corte de um par é uma decisão local de roteamento, não uma expulsão global.

Essa distinção é importante para não vender o projeto como algo que ele não é.

---

## 14. Segurança em camadas

| Camada | Mecanismo | O que protege |
|---|---|---|
| Identidade | Ed25519 + OTP + X25519 | autoria, replay, prova de posse |
| Cofre local | Argon2id + ChaCha20-Poly1305 | chaves em repouso no cliente |
| Transporte | TLS auto-assinado + pin | escuta e troca de nó no caminho |
| Documento | canonicalização + assinatura sobre bytes | ambiguidade de representação |
| Conteúdo | hash + assinatura + AEAD | alteração de bytes e disco roubado |
| Autorização | `adeia` + sessão autenticada | acesso indevido |
| Federação | handshake assinado + chave fixada no primeiro contato | nó reivindicando um id com outra chave |
| Operação | persistência antes da resposta + limites de parser | perda de estado e smuggling |

O parser HTTP é escrito à mão e tem limites estritos: cabeçalho máximo, corpo máximo, sem `Transfer-Encoding: chunked`, `CR` isolado recusado e `Content-Length` conflitante recusado. Isso não é paranoia decorativa; é a diferença entre um servidor e uma superfície de ataque.

O modelo completo, com 41 entradas e as mitigações correspondentes, está em [modelo-de-ameaca.md](modelo-de-ameaca.md).

---

## 15. Operação de um pyle

Um nó de produção precisa de:

- **TLS** — o servidor recusa `--no-tls` fora de loopback;
- **disco persistente** — `--data` não deve apontar para `/tmp`;
- **backup** — banco + `tls.identity` + arquivos exportados;
- **limites** — `--moira`, `--max-upload`, `--rate-limit`, `--band-per-hour`;
- **endereço anunciado** — `--advertise` define o endereço público e o id padrão do nó; é obrigatório na prática quando o bind é `0.0.0.0`;
- **federação aberta** — o nó aceita o primeiro contato de qualquer pyle e fixa a chave apresentada; `federation_peers` é apenas um reforço opcional de pin;
- **usuário dedicado** — o processo não precisa de root.

O pin TLS é estável enquanto `tls.identity` existir. Se você perder esse arquivo, o nó gera um certificado novo e todos os clientes que fixaram o pin antigo passam a recusar a conexão. Isso é o comportamento correto: um pin que muda sozinho não seria um pin.

O servidor imprime o pin no stderr e o expõe em `/health`. Em produção, distribua o pin por um canal confiável — não pelo mesmo canal que você usaria para baixar o binário.

---

## 16. Qualidade: como sabemos que funciona

O projeto não pede confiança na maturidade. Ele mostra os testes:

- **228 testes automatizados** (mais um teste manual de integração com nó real);
- testes de dois e três nós para federação, réplica, delete e sucessão;
- testes de GUI que renderizam a interface em 960×640 e falham se um painel sair da tela;
- testes de segurança para replay de OTP, pin incorreto, CR isolado, request smuggling e delete de peer não-originário;
- fuzzing dos parsers de documento e de HTTP;
- CI com `fmt`, `clippy -D warnings`, build e testes.

Nenhum teste prova ausência de bugs. Um conjunto de testes bem escolhido, porém, transforma "confie em mim" em "tente quebrar e veja o que acontece".

---

## 17. Limites e trabalho futuro

O HDAP é federado, não uma blockchain. Não há consenso global, mineração de moeda ou anonimato de rede. Os limites conhecidos incluem:

- recuperação de identidade depende de backup do cofre;
- criptografia em repouso não protege contra o operador do nó;
- metadados são públicos;
- deleção é incentivada, não fisicamente garantida;
- a federação é aberta por design; a primeira chave vista para um id é a que fica fixada;
- a economia (`katallaxia`) é opcional e não é necessária para arquivar.

Esses limites não são falhas escondidas. São decisões de escopo documentadas para que ninguém compre uma promessa que o protocolo não faz.

---

## 18. Mapa da documentação

Para usar o sistema, o [Guia do Usuário](userguide.md) e os seus [seis capítulos](userguide2.md) cobrem identidade, arquivos, economia, federação e operação. Para compilar e empacotar, o [Guia de Execução](guia-de-execucao.md). Para a semântica normativa, a [Especificação Formal](especificacao-hdap.md). Para o formato de fio e as rotas, o [RFC-HDAP](rfc-hdap.md). Para segurança, o [Modelo de Ameaça](modelo-de-ameaca.md). Para o vocabulário, o [Léxico Grego](lexico-grego.md). Para a base econômica do módulo opcional, a [Filosofia Econômica](filosofia-economica.md). E para a história do predecessor, o [HPS](hps.md).

---

<p align="center">
<strong>HDAP — a prova vem antes da confiança.</strong><br>
Thaís (op3n/op3ny)
</p>
