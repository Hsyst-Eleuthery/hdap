# RFC-HDAP — Hsyst Descentralized Archive Protocol

**HDAP v1.0 — Themelio · Veritas Aeterna**

- **Status**: estável — release 1.0, implementado em `hdap-core`, `hdap-server`, `hdap-cli`, `hdap-tls` e `hdap-gui`.
- **Última edição**: 2026-10-22.
- **Objetivos de design**: armazenamento assinado e auditável sem registro global; identidade global com sessão por nó; custo antiabuso por prova de trabalho; federação aberta entre pyles; camada de mercado opcional (`katallaxia`).
- **Documentos-fonte**: [especificacao-hdap.md](especificacao-hdap.md), [modelo-de-ameaca.md](modelo-de-ameaca.md), [lexico-grego.md](lexico-grego.md) e [filosofia-economica.md](filosofia-economica.md).
- **Autoridade documental**: este RFC é normativo para o **formato de fio** (bytes, headers, rotas) e defere à [Especificação Formal](especificacao-hdap.md) para a semântica e ao [Modelo de Ameaça](modelo-de-ameaca.md) para a segurança.

## 1. Notação e terminologia

- Um **`pyle`** (nó) guarda *ktema* (arquivos), emite *mochthos* (banda), participa do *homospondoi* (federação).
- Identidade global de usuário: `nickname_<suffix>` — ver §4.
- Todo valor de exemplo em hex é minúsculo; hashes são SHA-256 (64 hex).
- "deve/MUST", "pode/MAY", "não deve/MUST NOT" seguem RFC 2119.
- **Termos de "dono" (P1-4)**: a rota `/ktema?owner=` refere-se ao `namespace_owner` (dono do espaço `HDAP$/<user>/`); o autor do conteúdo é verificado via `X-HDAP-Sphragis` na sessão; a proveniência original é `origin_user` no `prytaneion`. Ver `especificacao-hdap.md §2.1`.

## 2. Construções criptográficas

| Papel | Algoritmo | Notas |
|---|---|---|
| Assinatura (`sphragis`) | Ed25519 | chaves `SIGN_PUBKEY` publicadas no prosopeion |
| Envelope/sigilo | X25519 + ChaCha20-Poly1305 | AEAD nonce 12B, tag 16B |
| Hash / MAC | SHA-256 / HMAC-SHA256 | digest hex 64 |
| KDF do cofre | Argon2id | senha do usuário → chave do cofre |
| Derivação F3 / sessão | X25519 DH + HMAC | ver §7 |
| OTP (F2) | cadeia Lamport `H^(k-r)(seed)` | âncora pública `OMPHALOS` |
| Transporte | TLS 1.2/1.3 (rustls) com cert **auto-assinada Ed25519** por nó + pinning TOFU | §11 |
| PoW | `SHA256(CHALLENGE ‖ be64(NONCE))`, `leading_zero_bits ≥ BITS` (servidor deriva `BITS` do hashrate declarado) | §8 |

Regra de ouro: chaves privadas **nunca saem do cliente**; o pyle só guarda chaves públicas e o `OMPHALOS`.

## 3. Federação e escopo deste documento

HDAP distingue **dois recortes de governança econômica**, não dois modos de admissão de rede:

1. **Federado** (`homospondoi`) — alvo atual, totalmente implementado; a federação é sempre aberta (qualquer pyle faz o primeiro contato e tem a chave fixada), e o consenso de reputação é maioria simples dos nós ativos.
2. **Mercado** (rede pública) — *research*; voto de reputação pesa por `paratheke` (penhor), deleção é incentivo+reputação, nunca enforcement físico, e o OTP é propagado por sync (limitação de nós offline declarada).

Este documento especifica a federação aberta como MUST e descreve o mercado como doutrina.

## 4. Identidade

- `nickname` em `[a-zA-Z0-9_]{1,32}`, normalizado minúsculo; sufixo **CSPRNG 64-bit** → 16 hex.
- `user_id = nickname_suffix`; validado por `parse_global_id` (o resultado é o identificador universal, independente de nó).
- `prosopeion.hdap` (público, assinado) carrega `NICKNAME`, `SUFFIX`, `SIGN_PUBKEY`, `ENC_PUBKEY`, `OMPHALOS`, `CREATED`, `SEED_ITER`.
- Um usuário pode registrar a **mesma** identidade em vários pyles (o registro é local; a identidade é global). Re-registrar a mesma identidade num pyle → `409`.

## 5. Formato de documento `.hdap` (`stele`)

```
# HSYST DESCENTRALIZED ARCHIVE PROTOCOL
## DOC: <tipo_grego>
### HEAD:
# VERSION: 1
# TYPE: <typen>
# EDITION: <n≥1>
# PREV_HASH: <sha256 da edição anterior>   (MUST se EDITION > 1)
# CREATED_AT: <unix ts>
### :END HEAD
### BODY:
# CHAVE: valor
### :END BODY
### SIGS:
# SIGNER: <user_id>
# SIGNER_PUBKEY: <base64>   (pode ser omitido se dono conhecido)
# SIGNATURE: <base64>
### :END SIGS
## :END DOC
```

Regras canônicas (violação é erro de parse):
1. Chaves BODY `[A-Z0-9_.-]`; ordenação lexicográfica bytewise; documento termina com `\n` único.
2. `PREV_HASH` cobre o texto completo da edição anterior **incluindo `### SIGS`** (cadeia imutável).
3. Assinatura cobre o texto até a linha anterior a `# SIGNATURE:` do assinante.
4. Tipos: `prosopeion`, `adeia`, `mochthos`, `syngraphe`, `metabibasis`, `prytaneion`, `pheme_candidate`, `kerux`, `timi`, `link`. (`krypte` local e `symbolon` derivado não trafegam.)

### 5.0 `link` (ponteiro simbólico, reservado)
- Campos: `URI` (alvo canônico `HDAP!<pyle>@<user>/<path>`), `CEDENTE`, `CESSIONARIO`, `ORIGIN_PYLE`.
- É um `ktema` comum: lista, baixa e verifica por hash como qualquer outro. O tipo continua disponível, mas a transferência assíncrona atual copia os `ktema` reais e **não** materializa `<path>.hdap.link`.

### 5.1 `adeia` (ACL)
- `UUID` opcional, estável entre edições (o encadeamento segue por `PREV_HASH`).
- Linhas `PERM<idx>` canônicas: `PERM {owner} {scope} {right}`.
- Direitos: `deny | read | write | own`. Escopos: `all | user:<id> | path:<prefixo>`.
- `DIADOSI=white:<pyle>;...;` / `DIADOSI=black:<pyle>;...;` restringe replicação e leitura pelo `server_id` do pyle que copia/serve; docs públicos de identidade (`prosopeion.hdap`, `adeia.hdap`, `diadosi.hdap`) são isentos do filtro de leitura.

### 5.2 `mochthos` (banda)
- `OWNER`, `ISSUER`, `CHALLENGE`, `TARGET_BITS`, `NONCE`, `SOLUTION_HASH`, `BANDWIDTH_BYTES`, `STATUS`, `ISSUED_AT`, `EXPIRES_AT`; mais `HASHRATE_HPS`. Assinado pela chave Ed25519 persistente do nó (`pow/N.hdap.pow`).

### 5.3 `timi` (katallaxia)
- `PYLE`, `PRICE_PER_GIB_DAY`, `MAX_DURATION_DAYS`, `VALID_KAIROS`.

### 5.3.1 `diadosi` (procuração de casa)
- Campos: `OWNER`, `OWNER_PUBKEY`, `HOME_PYLE`, `FALLBACKS` (1..=16), `ADEIA_EDITION`, `ADEIA_HASH`, `PROPERTIES_HASH`, `EDITION`, `PREV_HASH`, `CREATED_AT`.
- Assinado pelo dono; a assinatura cobre `signature_input(0)`. Instalado via `POST /diadosi`, exige pubkey/chave em disco, home atual, hashes/edição atuais e edição monotônica.
- Um fallback listado só assume (`HOME_PYLE`) se o home estiver offline, o peer do home for conhecido com endpoint e o documento ainda casar com `adeia`/`prosopeion`. Editar a identidade invalida a procuração até reassinar.

### 5.4 `exousia` (capacidade delegada)
- Campos: `OWNER`, `OWNER_PUBKEY`, `DELEGATE`, `DELEGATE_PUBKEY`; `CHAIN0000`/`CHAIN0000_PUBKEY`… (delegadores intermediários); `SCOPE`, `PATH`, `EXPIRES_AT`, `NONCE`, `DEPTH`; `PARENT_HASH` quando `DEPTH > 0`.
- **SIGS**: uma assinatura por elo, `len(SIGS) == DEPTH + 1`. Elo `0` assinado pelo `OWNER`; elo `i > 0` pelo `CHAIN{i-1}`. Cada signatário apresenta a chave registrada no corpo; a assinatura cobre `signature_input(i)`.
- `OWNER_PUBKEY` é conferida contra o `prosopeion` do dono — a cadeia não se autodeclara raiz.
- Semântica de escopo, contenção de caminho e expiração: `docs/especificacao-hdap.md` §18.

## 6. Cofre local (`krypte.hdap`)

- Nunca sai do cliente. Cifrado em repouso com ChaCha20-Poly1305 sob chave `Argon2id(senha, salt)`.
- Persistido pelo cliente (`identity_store`) em `krypte.hdap` (sealed) + `prosopeion.hdap` (público).
- Chama `save(identity, password, krypte_path, prosopeion_path)` / `load(...)`.

## 7. Autenticação 3FA e sessão (por nó)

Fluxo (`/proklesis` → `/auth`):

1. **F1 — posse (Ed25519)**: o nó emite desafio de uso único `{nonce, ts, expires_at}` (proklesis, TTL default 60 s). Cliente assina `hdap:challenge:{nonce}:{ts}`.
2. **F2 — conhecimento (OTP)**: cliente revela `w_r = H^(k-r)(seed)` com `H^r(w_r) == OMPHALOS`. O nó guarda o **piso de passo consumido** `omphalos_step[user]` e aceita apenas `pasó > piso`. O piso é **propagado** pela federação (campo `otp_consumed` no sync) → replay cross-nó rejeitado.
3. **F3 — posse de `K` derivado**: `K = X25519(priv_enc(servidor), pub_enc(usuário))`. O cliente envia `HMAC(K, "hdap:code" ‖ user_id ‖ server_id ‖ ts)`; o nó recomputa `K` no ato (não armazena segredo).

Sucesso: `symbolon = HMAC(K, "hdap:session" ‖ server_id ‖ exp)`, exp default 12 h, guardado na sessão **daquele nó**. Sessão por nó: o token de A é recusado em B.

### 7.1 O que o 3FA protege (e o que não protege)

| Fator | Prova | Protege contra | **Não protege contra** |
|-------|-------|----------------|------------------------|
| **F1** | Assinatura Ed25519 sobre desafio | Roubo isolado da chave de assinatura; replay de desafio (nonce único) | Chave roubada junto com F2/F3; operador do cofre `krypte.hdap` |
| **F2** | Passo OTP `w_r` (cadeia de hash) | Replay de passo já consumido; phishing de seed (o seed não sai do cliente) | Seed extraída do `krypte.hdap`; nó offline sem sync do piso OTP |
| **F3** | `HMAC(K, ...)` com `K = X25519(priv_enc(node), pub_enc(user))` | Nó malicioso que tenta autenticar como usuário (não tem `priv_enc(user)`); vazamento de DB do nó (não guarda segredo do usuário) | **Forward secrecy**: DH estático-estático — quem obtiver `priv_enc(user)` **ou** `priv_enc(node)` computa `K` de **todas** sessões passadas/futuras daquele par; operador do nó que tem `priv_enc(node)` computa `K` de qualquer usuário do nó |

**Resumo de independência real**:
- F1 e F3 são **ambos posse de chave**. Se `sign_key` e `enc_key` vivem no mesmo `krypte.hdap` (padrão), são o **mesmo fator na prática**.
- F2 deriva de `seed = SHA256(sign_key)` — também no mesmo cofre.
- O cofre `krypte.hdap` (protegido por senha + Argon2id) é o **ponto único de falha**.
- **O 3FA protege**: roubo isolado de um fator, replay de desafio/OTP, nó malicioso sem cofre do usuário.
- **O 3FA NÃO protege**: comprometimento do cofre local; forward secrecy (DH estático-estático); operador do nó que compromete a chave ENC do nó.

> **Decisão de design**: a separação explícita de chaves (assinatura vs. cifragem) permite futuras implementações com HSM/TEE ou cofres separados. Hoje, a independência entre F1/F2/F3 é **limitada pelo armazenamento compartilhado**.

## 8. Banda e custo (`mochthos` / `choregia` / `syngraphe`)

- Challenge do pyle **vinculado à identidade do emissor**: `CHALLENGE = "hdap-mochthos:<server_id>"`.
- `/mochthos/proklesis` → `{challenge, issuer, target_secs, min_bits, max_bits}` (POST).
- **A dificuldade é derivada pelo servidor**, nunca enviada pelo cliente: `BITS = clamp(ceil(log2(claim_hps × target_secs)), min_bits, max_bits)` (`PowPolicy::bits_for`). O cliente **mede** seu hashrate e o declara em `hashrate`. Enviar `target_bits` do cliente era o furo que aceitava `target_bits: 0`.
- Cliente resolve: `SUCCESS ⟺ leading_zero_bits(SHA256(challenge ‖ be64(nonce))) ≥ BITS`. O cliente inicia a busca num **nonce aleatório** (`OsRng`) — como o challenge é determinístico por pyle, um start fixo faria todos os usuários gerarem o mesmo proof, e o guard single-use rejeitaria do 2º em diante.
- `bits_for` é **monótona** e clampada em `[min_bits, max_bits]`: inflar o hashrate nunca é desconto, e uma alegação absurda não vira demanda ilimitada. `--pow-strict` recusa alegações fora da faixa. Limite declarado: o tempo esperado cai em `[target_secs, 2×target_secs)`, então a prova **não** mede wall-clock do cliente; o backstop anti-abuso é `band_bytes_per_hour` por conta/hora.
- `/mochthos/issue` valida e credita `choregia_per_mochthos` bytes ao usuário, e emite `pow/N.hdap.pow` assinado pela chave Ed25519 **persistente** do nó (`State::node_sign_seed`), registrando um `BandObject{countersigned:false}`; resposta `doc: {id, path, body}` + `countersign_required: true`. `POST /mochthos/countersign` recebe `{path, signer_pubkey, signature}` e completa o dual-sig (o dono assina `signature_input(1)`, após o emissor ter assinado `signature_input(0)`); `GET /mochthos/band` lista os objetos vivos (`granted`/`remaining`/`countersigned`).
- **Double-spend (regra de missão)**: um mochthos é honrado **apenas pelo nó emissor**; um proof resolvido contra o challenge de outro pyle é recusado (`400`); proof `(CHALLENGE, NONCE)` é **single-use por nó** (`400` em replay).
- **Upload**: o cliente envia `X-HDAP-Syngraphe` (base64 do `SyngrapheDoc`, assinado pelo dono) que **consome** a banda; o `.pow` é apagado e vira `pow/N.hdap.syngraphe` com o ack do nó. Banda não reembolsável. Sem o header, cai no débito legado de `choregia`. Ao replicar, metadados carregam os mochthos usados; o destino confere.

## 9. Armazenamento, matriz, replicação, deleção

- **Upload**: cliente assina os **bytes crus** e envia a assinatura em `X-HDAP-Sphragis` (base64 Ed25519 o corpo cru); o servidor **exige** o header (salvo `require_content_signature=false` em testes) e verifica contra a pubkey da **sessão autenticada**, não contra campos do corpo. Valida hash, sphragis, permissões e choregia; persiste **cifrado em repouso** (AEAD sob `master_key` do nó) e registra no `prytaneion`. O commit no armazenamento é **síncrono antes da resposta**: falha de flush → `500`.
- **`prytaneion` (matriz)**, chave = content hash: `ORIGIN_PYLE`, `ORIGIN_USER`, `REPLICAS`, `DELETIONS` (histórico).
- **Replicação (`apographon`)**: propaga só após validar mochthos públicos + prytaneion; réplica linkada à matriz. `DIADOSI` pode negar a cópia por pyle (`store_namespace`/`fed_fetch_blob` → `403`).
- **Deleção (`lethe`/`ostrakon`)**: usuário/matriz solicita; nós apagam e confirmam; o apagador deixa um marcador curto (ostrakon). Nó que não apaga → `oneidos` (queda de pheme). **Declarado**: deleção é incentivo + reputação, não enforcement físico.
- **Integridade**: hash e sphragis sempre reverificados no servidor.
- **Quota (`moira`, §16)**: `moira_bytes` por usuário (`0` = ilimitado); upload que excede → `413`; delete libera. A banda (`choregia`) só é decrementada no sucesso do upload (falha devolve banda).

## 10. Permissões e transferência

- Autorização **sempre** pela identidade da sessão; nunca por *hint* do cliente; escopos de `adeia` decidem. Cruzamento sem permissão → `403`.
- `DIADOSI` é um segundo filtro, por pyle (não por usuário): vale para leitura e replicação, inclusive snapshots antigos (`replica_acls`); só os documentos públicos de identidade escapam da leitura.
- `metabibasis` (transferência de posse) é um **handshake assíncrono**: `POST /transfer/request` monta um manifesto assinado pelo cedente (slot 0) e contra-assinado pelo pyle de origem (slot 1); o pedido vai para `POST /transfer/inbox`; o cessionário assina o `ACCEPT` (slot 0), que o pyle de destino contra-assina (slot 1) e que embute o `REQUEST` exato + `REQUEST_HASH`. O alvo canônico é a URI `HDAP!<pyle>@<user>/<path>` e o rascunho carrega `TARGET_KIND` (`file`/`dir`/`identity`), `SCOPE*` (seleção original, cobre arquivos futuros) e o manifesto `TARGET*`/`DEST*`/`HASH*`/`SIZE*`.
- A origem executa `lock_cessions` **antes** de copiar; mesmo pyle usa `complete_local`, pyles distintos usam `POST /transfer/complete` na origem e `POST /transfer/deliver` no destino. Cada byte é reconferido contra o hash/tamanho assinados.
- O read-only do cedente é **irrevogável contra o cedente** e não depende do texto do `adeia` (`POST /adeia` substitui o documento inteiro): a autoridade é `State::ceessions[cedente] = [{to, path, at}]`. `authorize` nega `Write`/`Own` do próprio cedente quando qualquer cessão cobre o caminho; `Read` continua. O cessionário recebe uma cópia real, não um link.
- Quando o cessionário apaga a cópia recebida, o pyle de destino chama `POST /transfer/release` (assinado com a chave do pyle registrada no aceite); a origem apaga a cópia antiga, remove a cessão quando não resta objeto no escopo e emite os tombstones, então os espelhos também somem. A cessão protege contra o cedente, não impede o novo dono de descartar o conteúdo.
- Registros pendente/final ficam em `metabibasis/<b64(old_uri)>-<b64(new_uri)>-<request_id>.request.hdap` e `... .hdap`, imutáveis para upload/delete. Reentrega é idempotente; mudança no manifesto devolve `409`.

## 11. Transporte TLS (AME-09) — MUST fora de loopback

- Todo `pyle` serve TLS com **certificado auto-assinado Ed25519** gerado no primeiro boot e persistido no bundle atômico `<data>/tls.identity` (rcgen), com export de `<data>/tls.crt` + `<data>/tls.key` para ferramentas; o pin sobrevive a reinícios e um crash entre exports não produz par cert/chave inconsistente. `--ephemeral` gera em memória para testes.
- Cliente fixa o pin `P = SHA256(cert_DER)` (TOFU). Conecta TLS **somente** quando conhece `P`; pin divergente → recusa no handshake.
- O pyle publica `tls_pin` em `/health` para auditoria manual.
- A identidade canônica do pyle (`server_id`) é independente do pin (não se confunde chaves de assinatura com chaves TLS).
- Plaintext é permitido apenas em loopback/desenvolvimento.

## 12. Operações HTTP (surface REST/JSON)

### 12.1 Públicas (cliente)
| Método | Rota | Ação |
|---|---|---|
| POST | `/register` | publicar prosopeion (cria `user_id`) |
| POST | `/omphalos` | rotação da âncora OTP (sessão do dono; `SEED_ITER` estritamente crescente) |
| GET | `/proklesis` | desafio F1 (`?user=...`), já com `pylaia` (`required`, `challenge: hdap-pylaia:{server}:{nonce}`, `target_bits`) |
| POST | `/auth` | prova 3FA → `symbolon` por nó |
| POST | `/mochthos/proklesis` | emitir desafio de banda (requer sessão; `{challenge, issuer, target_secs, min_bits, max_bits}`) |
| POST | `/mochthos/issue` | validar proof (auth) |
| POST | `/mochthos/countersign` | dual-sig do `.hdap.pow` (`{path, signer_pubkey, signature}`) |
| GET | `/mochthos/band` | listar `BandObject` vivos do dono |
| GET/POST/DELETE | `/ktema[?owner&path]` | download/upload/delete |
| GET | `/ktema/list[?owner&path]` | listar diretório (JSON, perm Read) |
| POST | `/adeia` | publicar edição ACL |
| POST | `/diadosi` | instalar `diadosi.hdap` assinado (procuração de casa e fallbacks) |
| POST | `/transfer/request` | rascunho/pedido assinado pelo cedente |
| POST/GET | `/transfer/inbox` | entregar pedido auto-verificável / listar ofertas pendentes |
| POST | `/transfer/accept` | rascunho/aceite assinado pelo cessionário |
| POST | `/transfer/complete` | origem recebe o aceite e copia/empurra os bytes |
| POST | `/transfer/deliver` | destino recebe os blobs e grava o registro final |
| POST | `/exousia` | capacidade delegada: `{"issue":{...}}` devolve o rascunho a assinar; `{"capability":"<doc assinado>"}` verifica a cadeia e armazena |
| GET | `/exousia` | listar capacidades do dono autenticado |
| GET/POST | `/prytaneion/*` | matriz/réplicas |
| GET | `/pheme` | reputação |
| GET | `/kerux/{alias}` | DDNS |
| GET | `/health`, `/pyle/integrity` | estado/integridade (health inclui `tls_pin`) |
| POST/GET | `/timi` | katallaxia: publicar/listar preços |

**Fluxo `exousia` em duas fases.** O nó não assina nem outorga: ele (1) devolve um
rascunho não assinado depois de confirmar que quem pede já é delegado de um
capability pai que *contém* o escopo/caminho pedido (re-delegação não pode
ampliar), e (2) no POST final verifica a cadeia de co-assinaturas contra o
`prosopeion` do dono, confere a chave do delegado contra a identidade registrada
e só então armazena. Reenviar a mesma capacidade é idempotente.

### 12.2 Federação (`/homospondoi`)
| Método | Rota | Ação |
|---|---|---|
| POST | `/handshake` | registrar peer (`node_id` + pubkey + `endpoint` + opcional `tls_pin`) — sempre aceito; a chave é fixada no primeiro contato (ou conferida contra um pin prévio); devolve `node_sign_pub` |
| POST | `/sync` | semicronia: content_hash + `otp_consumed` (piso OTP); **dispara replicação automática** de blobs ausentes |
| GET | `/fetch_blob?hash=<content_hash>` | **replicação de conteúdo**: devolve bytes em plaintext (TLS) do blob cujo hash coincide; autenticação por headers `X-HDAP-*` |
| GET | `/namespace?owner=<user_id>` | usuário (prosopeion/adeia/chaves) + entradas (`path`/`hash`/`size`) para pull-through |
| POST | `/pheme` | propagar candidato de reputação |
| POST | `/prytaneion_update` | mudanças de matriz/deleção |
| GET/POST | `/ledger` | livro global de réplicas/proveniência; `GET ?digest=`/`?hash=`, `POST` funde |
| POST | `/house_move` | transferência de casa assinada pelo usuário (edição maior de `adeia`) |

Headers: `X-HDAP-Node-Id`, `X-HDAP-Nonce`, `X-HDAP-Timestamp`, `X-HDAP-Signature` (payload `node_id:nonce:timestamp`, janela ±`fed_window_secs`, nonce single-use).

### 12.3 Reputação e reconciliação (`pheme`)

O modelo de reputação varia por modo de federação (§3):

| Modo | Decisão | Reconciliação quando divergir |
|------|---------|-------------------------------|
| **Federado** (homospondoi) | Maioria simples dos nós ativos | **Regra de reconciliação obrigatória**: ao receber `/pheme` com score divergente, o nó **adota a mediana** dos scores recebidos dos peers ativos (incluindo o próprio). Se há `N` nós ativos, a mediana é o score na posição `⌊N/2⌋` ordenado. Empate: escolhe o menor. Isso garante convergência determinística sem coordinator e tolera até `⌊(N-1)/2⌋` nós bizantinos. |
| **Aberto** (rede pública) | Voto ponderado por `paratheke` (penhor) | Mesma regra: mediana ponderada por stake. Nós sem `paratheke` não votam. |

**Propagação**: `POST /homospondoi/pheme` carrega `pheme_candidate.hdap` (assinado pelo proponente, com `TARGET_ID`, `SCORE_DELTA`, `REASON`, `EVIDENCE`, `PARATHEKE_COMMIT`). O nó receptor:
1. Verifica a assinatura do proponente contra a chave fixada para aquele `node_id` (o pin de `Config.federation_peers`, se existir, ou a chave aceita no handshake).
2. Verifica evidência (hashes de `prytaneion`/`ktema`).
3. Aplica `SCORE_DELTA` localmente.
4. Encaminha para os outros peers (gossip com deduplicação por nonce).
5. Na próxima rodada de `/sync`, todos os nós convergem para a **mesma mediana**.

**Garantia**: a regra da mediana é determinística, não requer coordinator e converge em uma rodada de gossip completa. Um nó que não aplique a regra terá seu `pheme.hdap` com hash divergente → detectado no próximo `/sync` → marca o nó como suspeito (`oneidos`).

> **Federação aberta com pin no primeiro contato** (AME-34): todo `/handshake` é aceito. A chave apresentada é fixada em `State::peers` para aquele `node_id`; um id já fixado não aceita outra chave (`409`). `Config.federation_peers` (`node_id → {pubkey, endpoint, tls_pin}`) é um **reforço opcional**: se houver entrada, a chave precisa casar com ela. O conteúdo continua verificado por assinatura de autor e hash, então um impostor pode ser alcançado, mas não pode forjar conteúdo.

**Descoberta global (`/homospondoi/directory`, `/homospondoi/announce`).** Cada handshake bem-sucedido entra na bolha. A lista é sincronizada por digest canônico: `GET /directory?digest=` responde só o digest quando já há convergência; caso contrário devolve os pyles dialáveis. Um candidato só é inserido em `State::peers` depois de um handshake de callback que confirme `server_id`, chave de assinatura e pin. Anúncios usam fanout 2, `event_id` deduplicado e TTL ≤ 8; anti-entropy roda a cada 60 s contra 2 pares rotativos e o health check de um par a cada 5 min. Assim o custo é O(n) por rodada, não O(n²) de perguntas redundantes, e loops A→B→C→B→A morrem no `event_id`. A descoberta está sempre ativa: um par confiável pode apresentar um desconhecido, mas ele só entra após o handshake de callback.

**Busca por hash, livro global e Cenário B.** `POST /resolve_hash` resolve pelo `pechys` sem URI: local → livro global (local + até 8 pares) → origem → réplicas; valida `sha256` e `sphragis` (pubkey/assinatura no livro e nos headers `X-HDAP-Origin-Pubkey`/`X-HDAP-Sphragis`/`X-HDAP-Origin-Path`), re-sela em `cache/<hash>/<name>` do requisitante e registra a réplica `server_id:owner/path`. O livro troca *digest-first*, funde de forma idempotente (origem first-writer-wins, réplicas/deleções unidas) e o handshake carrega `ledger_digest`. O `adeia` de cada namespace replicado é **congelado no pull** (`State.replica_acls`): réplicas públicas antigas continuam legíveis mesmo com a origem offline ou com edição mais restritiva — `authorize_replica` concede só `Read`; novas edições exigem transferência. `POST /house_move` verifica Ed25519 sobre `hdap:house_move:<user>:><pyle>:<sha256(properties)>:<sha256(adeia)>`, exige edição estritamente maior e propaga via `/homospondoi/house_move` (fanout 2). `GET /bubble` expõe as contagens que o GUI mostra no rodapé.

**Acesso cross-pyle (`POST /resolve` / `GET /mirrors`, §14.2.1 da especificação):** ao abrir `HDAP!<pyle>@<user>/<path>` de outro pyle, o nó local puxa (`GET /namespace` + `GET /fetch_blob`) o namespace daquele usuário, re-verifica o `sha256`, re-sela sob seu `master_key`, grava sob o **mesmo** `owner`, registra a origem no `prytaneion` e o pyle de origem em `State::peers`/`State::mirrors`, e passa a servir a URI localmente (idempotente). O `server_id` default é `pyle-<base64url(host:port)>`, então a URI carrega o endereço a dialar.

**Replicação automática (§9):** ao receber `/sync` com `content_hash` que o nó ainda não possui, o nó dispara `GET /fetch_blob?hash=...` no peer remetente (usando a `endpoint` registrada no handshake), verifica o hash, cifra com sua `master_key` local e registra no `prytaneion` como réplica. A replicação usa a chave de assinatura do nó (`node_sign_seed`) para autenticar a requisição de saída. Resposta inclui headers `X-HDAP-Origin-Server` e `X-HDAP-Origin-User` para proveniência.

### 12.3 Regras de framing do request (AME-39/40/41)

O parser HTTP/1.1 é escrito à mão e fica diretamente sobre o socket, então
smuggling aqui é um bug de parser. Regras estritas:

- **`Content-Length` ambíguo é recusado.** Dois headers `Content-Length` com
  valores divergentes → erro; uma lista separada por vírgula só é aceita se
  todos os elementos coincidem (`5, 5` passa, `5, 6` não). Um valor não numérico
  é erro, nunca zero implícito. O mapa de headers é confrontado com o corpo
  realmente consumido.
- **`CR` isolado no head é recusado.** Todo `CR` precisa fazer parte de um
  `CRLF`. Um `CR` solto é terminador de linha para um proxy e dado comum para
  o nó, e os dois discordariam sobre onde os headers terminam.
- **Só *origin-form*.** O alvo precisa começar com `/`. `http://host/x`
  (*absolute-form*) e `host:port` (*authority-form*) não são interpretados.
- `Transfer-Encoding: chunked` não é suportado; o corpo para no
  `Content-Length` declarado.
- Tetos: head ≤ 64 KiB, body ≤ 8 MiB, e bytes após o `Content-Length` são
  recusados em vez de ignorados.

## 13. Katallaxia (módulo opcional)

- `timi.hdap` = anúncio de preço por nó; `GET /timi` lista. 
- Oferta: `obolos`/byte-tempo; `tokos` cresce com duração (preferência temporal).
- Reputação (`pheme`) é capital; o penhor (`paratheke`) dá voz; `euthyne` = arbitragem privada.
- O núcleo funciona sem o módulo.

## 14. Modelo de ameaça (sumário)

- AME-09 (MITM) — mitigado por TLS + pinning TOFU.
- AME-21 (F3 inválido) — `K` derivado por DH no ato; nada armazenado.
- AME-22 (sessão "global") — sessão por nó; token rejeitado no segundo nó (teste 2S+1U).
- AME-23 (OTP cross-node replay) — piso propagado por sync; passo ≤ piso é rejeitado (teste 2S+1U).
- AME-24 (permissão por hint) — autorização só por sessão (teste 2S+1U, hint forjado → 403).
- AME-28 (double-spend PoW cross-node) — mochthos honrado só pelo emissor + single-use.

## 15. Violações, limites e trabalho futuro (honesto)

- Rede aberta global: **ainda não é o alvo** — deleção não-física, OTP offline, membragem aberta, e/gás/saneira são doutrina/research.
- Persistência dos pyles é **SQLite** (`db.rs`, WAL + `synchronous=FULL`), com `persist()` síncrono antes de responder (AME-35): falha de flush vira **HTTP 500**. Estado efêmero é erro, não modo de operação.
- `serve_tls` do daemon carrega a identidade do bundle `<data>/tls.identity` (fallback para o par legado `tls.crt`/`tls.key`, com migração automática); o pin é estável entre reinícios. Com `--ephemeral` a cert volta a ser gerada em memória (pin muda por boot), útil só em testes.
- Rotação de `omphalos`: `POST /omphalos` (sessão do dono) com `SEED_ITER` monotônico; piso de replay zerado.
- Sync de `pheme` com peers offline: fila `pendings` + retry com backoff ao reestabelecer; declara-se a janela de replay OTP = latência de sync (irredutível sem consenso global — §17.2).
- Vetores de canonicalização: implementados como testes de roundtrip (parse/render) em `hdap-core`; suíte atual: **228 testes passando e 1 ignorado** (61 core, 69 server + 4 bin, 68 GUI, 19 CLI + 2 bin, 5 tls).
- Replicação para peer remoto usa **sempre TLS** (pin quando `tls_pin` está no `PeerRecord`, TOFU quando o id é endereçado e não traz pin); cleartext só é aceito em loopback (AME-37). Resposta de peer é lida com teto de tamanho, e o corpo para no `Content-Length` declarado em vez de esperar o peer fechar.
- Parser HTTP: cabeçalho tem teto próprio (`MAX_HEAD_BYTES`, independente do `max_body`) e toda conexão aceita recebe deadline de leitura/escrita, para que um peer silencioso não segure uma thread (slowloris).

## 16. Verificação

```
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all --check
cargo +nightly fuzz run parse_hdap_doc
cargo +nightly fuzz run parse_http_request
./scripts/cross-release.sh <target>
```