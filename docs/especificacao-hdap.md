# HDAP — Especificação Formal

**HDAP v1.001 — Themelio · Epoptia**

> Revisão de 2026-10-29 · Protocolo: **1.0** (matriz v1) · Status: **normativa e estável**. O documento adota o vocabulário grego canônico definido em [lexico-grego.md](lexico-grego.md).
>
> **Autoridade documental.** Este documento é a **fonte normativa única** da *semântica* do protocolo: o que DEVE ser verdade sobre identidade, sessão, permissões, banda, matriz e deleção. O [RFC-HDAP](rfc-hdap.md) é normativo apenas para o **formato de fio e rotas** e não pode contradizer esta especificação. O [Modelo de Ameaça](modelo-de-ameaca.md) é normativo para os requisitos de segurança (`AME-*`). O [Léxico Grego](lexico-grego.md) é normativo para terminologia. Exemplos usam `VERSION: 1`, a versão do formato de documento, distinta da versão do protocolo.

---

## 1. Escopo e objetivo

O **HDAP** (Hsyst Descentralized Archive Protocol) é um protocolo para **guardar arquivos assinados** (hash de integridade + assinatura do autor + registro auditável de origem) em uma rede de nós (`pyle`) em **federação aberta** (`homospondoi`), com uma camada opcional de incentivos austríacos (`katallaxia`). Regra de ouro: todo `ktema` (arquivo) existe com (a) `pechys` (hash de integridade), (b) `sphragis` (assinatura do autor), (c) registro auditável de origem no `prytaneion` (matriz). Tudo o mais (permissões, transferência de posse, replicação, deleção, confiança) se apoia nesses três fatos.

**Fora de escopo (núcleo)**: DNS global, gait de execução de contrato, PHPS, "mineração de renda". Entram como módulos opcionais: `katallaxia` (economia austríaca), `kerux` (DDNS), `euthyne` (arbitragem privada).

---

## 2. Terminologia (grego canônico)

| Termo (translit.) | Grego | Definição |
|---|---|---|
| `pyle` | Πύλη | Nó/servidor que guarda `ktema`, emite `mochthos`, participa do `homospondoi` |
| `homospondoi` | Ὁμόσπονδοι | Federação de nós sob pacto comum |
| `stele` | Στήλη | Documento `.hdap` (estela inscrita, auto-verificável) |
| `sphragis` | Σφραγίς | Assinatura Ed25519 |
| `heirmos` | Εἱρμός | Cadeia de edições (EDITION + PREV_HASH) |
| `prosopeion` | Προσωπεῖον | Identidade global `nickname_<sufixo>` publicada em `prosopeion.hdap` |
| `hestia` | Ἑστία | Diretório lógico do usuário (`HDAP$/<user>/`) |
| `krypte` | Κρύπτη | Cofre local (`krypte.hdap`, nunca trafega) |
| `omphalos` | Ὀμφαλός | Âncora OTP (cabeça da cadeia de hash), pública em `prosopeion.hdap` |
| `mochthos` | Μόχθος | Prova de trabalho por banda (custo anti-abuso) |
| `choregia` | Χορηγία | Banda/capacidade autorizada |
| `moira` | Μοῖρα | Cota individual de capacidade |
| `syngraphe` | Συγγραφή | Tratado de cessão/contrato de guarda (substitui o `mochthos` consumido) |
| `adeia` | Ἄδεια | Permissões/ACL (`adeia.hdap`) |
| `metabibasis` | Μεταβίβασις | Transferência de posse |
| `prytaneion` | Πρυτανεῖον | Matriz de origem/replicas (`prytaneion.hdap`) |
| `apographon` | Ἀπόγραφον | Réplica de conteúdo |
| `pheme` | Φήμη | Tabela de reputação distribuída (TCD) |
| `oneidos` | Ὄνειδος | Penalidade de reputação |
| `lethe` | Λήθη | Deleção: apagar é esquecer |
| `ostrakon` | Ὄστρακον | Tombstone (marcador de exílio do conteúdo) |
| `symbolon` | Σύμβολον | Token de sessão |
| `proklesis` | Πρόκλησις | Desafio de autenticação |
| `pylaia` | Πυλαία | PoW de entrada (login) |
| `kerux` | Κῆρυξ | DDNS/alias (`kerux.hdap`) |
| `katallaxia` | Καταλλαξία | Camada de mercado/incentivos (opcional) |
| `obolos` | Ὀβολός | Unidade de valor (byte-tempo) |
| `timi` | Τιμή | Preço (e honra: reputação = capital) |
| `tokos` | Τόκος | Juros/preferência temporal |
| `paratheke` | Παραθήκη | Penhor/stake do nó |
| `euthyne` | Εὐθύνη | Arbitragem/prestação de contas |
| `pechys` | Πῆχυς | Cânone de verificação (medida canônica exata) |
| `origin_user` | — | Usuário que **originalmente carregou** o conteúdo (imutável, em `prytaneion`) |
| `namespace_owner` | — | Dono do espaço lógico (`HDAP$/<user>/`); parâmetro `owner` nas rotas `/ktema` |
| `cedente` / `cessionario` | — | Transferidor / recebedor em `metabibasis` (campos `OLD_OWNER` / `NEW_OWNER`) |
| `issuer` | — | Nó que emitiu o `mochthos`/`syngraphe` (campo `ISSUER`) |

---

### 2.1 Funções de "dono" (P1-4)
O termo **owner** aparece em vários contextos com sentidos **não intercambiáveis**:
| Função | Termo técnico | Onde aparece | Imutável? |
|---|---|---|---|
| Autor do upload / signatário do conteúdo | `content_author` (implícito = `namespace_owner` hoje) | header `X-HDAP-Sphragis`, verificado contra sessão | sim (assinatura cobre bytes) |
| Dono do espaço lógico (namespace) | `namespace_owner` | query `owner` em `/ktema*`, `Blob.owner`, `BandObject.owner`, `adeia.hdap` | não (pode mudar via `metabibasis`) |
| Uploader original (proveniência) | `origin_user` | `PrytaneionEntry.origin_user`, `PrytaneionDoc.origin_user` | **sim** |
| Emissor da banda | `issuer` | `MochthosDoc.issuer`, `SyngrapheDoc.issuer` (node_id) | sim |
| Transferidor / Recebedor | `cedente` / `cessionario` | `MetabibasisDoc.old_owner` / `new_owner` | sim (registro histórico) |

**Regra:** documentação e código devem usar o termo técnico acima; o parâmetro de rota `owner` continua como `owner` por compatibilidade, mas **significa `namespace_owner`** (o espaço alvo). Quando a intenção for o autor do conteúdo, usar `origin_user` (do `prytaneion`) ou o `SIGNER` da `sphragis`.
| `kairos` | Καιρός | Janela de tempo (TTL) |
| `ktema` | Κτῆμα | Conteúdo/arquivo armazenado |

> Mapeamento antipó → grego e convenções de escrita: ver `docs/lexico-grego.md`.

---

## 3. Identificação e endereçamento

### 3.1 Identidade global (`prosopeion`)
- `nickname` escolhido pelo usuário (`[a-zA-Z0-9_]{1,32}`), normalizado minúsculo; sufixo **aleatório** CSPRNG **64 bits** → 16 hex. Identidade = `nickname_<sufixo>`, **independente de nó**. Verificável por qualquer nó (o `prosopeion` é público e assinado).
- **Prova de posse obrigatória** (AME-32): `POST /register` e a entrada de uma nova identidade em `/sync` exigem que o `prosopeion` carregue uma **auto-assinatura** válida pela `SIGN_PUBKEY` declarada — o servidor não aceita `SIGNER`/`SIGN_PUBKEY` autodeclarados sem assinatura correspondente. **Rotação de chave de assinatura** exige, além da nova assinatura, a assinatura pela **chave anterior** do registro existente; sem isso, um estranho não pode assumir a identidade de outra pessoa.

### 3.2 Diretório lógico (`hestia`)
```
HDAP$/<user>/
  prosopeion.hdap     # identidade pública (chaves, omphalos)
  adeia.hdap          # ACL pública
  HDAP/
    symbolon.hdap     # (removido — ver §7: fator 3 não depende mais de envelope guardado pelo servidor)
    mochthos/*.hdap.mochthos   # provas de trabalho por banda
    ktema/<caminho...>          # conteúdo do usuário
```

### 3.3 URI de acesso
```
HDAP!<servidor>@<user>/<caminho>?hash=<64hex>
```
- `hash` opcional; se presente, o nó verifica antes de servir. **Decidido: `?hash=<64hex>`** (FF provene hybrid querys).
- `<servidor>` é o `server_id` do pyle; o default é `pyle-<base64url(host:port)>`, de modo que a URI carrega o endereço. Ao resolver uma URI cujo pyle é **outro**, o nó puxa/espelha o namespace do usuário sob demanda em vez de recusar (§14.2.1).

---

## 4. Formato de documento `.hdap` (`stele`)

### 4.1 Sintaxe canônica
```
# HSYST DESCENTRALIZED ARCHIVE PROTOCOL
## DOC: <tipo_grego>
### HEAD:
# VERSION: 1
# TYPE: <prosopeion|adeia|mochthos|syngraphe|metabibasis|prytaneion|pheme|pheme_candidate|kerux|timi>
# EDITION: <n>
# PREV_HASH: <sha256 da edição anterior>     (obrigatório para EDITION > 1)
# CREATED_AT: <unix ts>
# ... campos de HEAD por tipo
### :END HEAD
### BODY:
# CHAVE: valor
### :END BODY
### SIGS:
# SIGNER: <user_id>
# SIGNER_PUBKEY: <armor base64>
# SIGNATURE: <base64>
### :END SIGS
## :END DOC
```

### 4.2 Regras canônicas (inalteradas da v1)
1. BODY: chaves maiúsculas `[A-Z0-9_.-]`; extras de HEAD minúsculas. Ordenação **lexicográfica bytewise**.
2. Linhas vazias extras removidas; documento termina com `\n` único.
3. `EDITION ≥ 1`; `PREV_HASH` **cobre o texto completo da edição anterior, incluindo `### SIGS`** (cadeia imutável).
4. Parser **rejeita** (erro): `VERSION` desconhecido, tipo desconhecido, HEAD obrigatório ausente, valor fora do schema, assinatura malformada.
5. Assinatura cobre o texto até a linha anterior a `# SIGNATURE:` do assinante (mesmo princípio HPS, `GetSignedContractText`).
6. `SIGNER_PUBKEY` pode ser omitido se `SIGNER` já é dono conhecido.

### 4.3 Tipos e esquemas
- **prosopeion** — `NICKNAME`, `SUFFIX`, `SIGN_PUBKEY`, `ENC_PUBKEY`, `OMPHALOS` (hex da âncora da cadeia), `CREATED`, `SEED_ITER`, campos de rotação.
- **adeia** — ACLs textuais (§8), direitos `deny|read|write|own`, escopos `all|user:|arquivo`; `UUID` **opcional** e estável entre edições (identificador do licenciamento; a cadeia de edições segue por `PREV_HASH`, não o obriga).
- **mochthos** (`pow/N.hdap.pow`) — `OWNER`, `ISSUER`, `CHALLENGE`, `TARGET_BITS`, `NONCE`, `SOLUTION_HASH`, `BANDWIDTH_BYTES`, `STATUS: unused`, `ISSUED_AT`, `EXPIRES_AT`; mais `HASHRATE_HPS` no corpo. Assinado com a chave Ed25519 persistente do nó. `TARGET_BITS` é derivado pelo servidor, nunca enviado pelo cliente.
- **syngraphe** — `OWNER`, `ISSUER`, `MOCHTHOS_HASH` (ref do moc cobrado), `MOCHTHOS_LOCATION` (caminho do apagado), `USED_FOR` (caminho do upload), `BANDWIDTH_USED`, `BANDWIDTH_REMAINING`, `STATUS`, `CREATED_AT`.
- **metabibasis** — `KIND` (`request`/`accept`), `REQUEST_ID`, partes e pyles, chaves/pins, `TARGET_KIND`, `SCOPE_COUNT`/`SCOPE{i:04}` e `TARGET_COUNT`/`TARGET{i:04}`/`DEST{i:04}`/`HASH{i:04}`/`SIZE{i:04}`. O `accept` acrescenta `REQUEST_HASH` e `REQUEST_DOC_B64` com o pedido exato. O antigo `metabibasis.hdap` (`OLD_OWNER`, `NEW_OWNER`, `READONLY_KEEP`, `TARGET*`) é legado.
- **link** — `TARGET`, `URI` (canônica §3.3), `CEDENTE`, `CESSIONARIO`, `ORIGIN_PYLE`. Tipo reservado; a transferência assíncrona atual copia `ktema` reais e não cria `<path>.hdap.link`.
- **prytaneion** — `ALIAS` (hash do ktema), `ORIGIN_PYLE`, `ORIGIN_PROSPEION`, `REPLICAS` (`[{pyle, path}]`), `LETHES` (histórico), `PHEME_UPDATES`, `STATUS`.
- **pheme_candidate** — `TARGET_ID`, `SCORE_DELTA`, `REASON`, `EVIDENCE` (hashes de prytaneion/ktema) + `PARATHEKE_COMMIT` quando modo público.
- **kerux** — `ALIAS`, `TARGET_URI`.
- **timi** — (módulo `katallaxia`) `PYLE`, `PRICE_PER_GIB_DAY`, `MAX_DURATION_DAYS`, `VALID_KAIROS` (janela), assinado pelo nó.
- `krypte` (local, nunca trafega) e `symbolon` (derivado, §7) **não são DOC de rede**.

### 4.4 Versionamento e migração
- **Duas versões distintas, não confundir:** a **versão do protocolo** é a geração descrita por este documento, hoje **1.0**; o **`FORMAT_VERSION` do documento `.hdap`** é a versão do formato textual, hoje **`1`**, cravada em todo `# VERSION:` e na constante `FORMAT_VERSION` do código (`hdap-core::doc`). Exemplos normativos usam `VERSION: 1`.
- **Regra de compatibilidade:** o parser **rejeita** `VERSION` desconhecido (fail-closed), então um bump de formato exige migrador explícito; nunca se reinterpreta silenciosamente um documento de versão futura.
- **Migração de estado do nó:** campos novos de `State` no SQLite usam `#[serde(default)]`; se `node_sign_seed` estiver ausente num banco antigo, `Db::load` deriva uma seed não-nula do `master_key` (nunca `[0;32]`), preservando a verificação dos documentos já emitidos. Schema futuro desconhecido é **recusado**.

---

## 5. Criptografia

| Papel | Algoritmo | Material |
|---|---|---|
| Assinatura `sphragis` | Ed25519 | par de assinatura |
| Sigilo/envelope | X25519 + ChaCha20-Poly1305 | par de cifração |
| Hash/MAC | SHA-256 / HMAC-SHA256 | — |
| KDF do cofre | Argon2id | senha do usuário |

- Chaves privadas **nunca saem do cliente**; `prosopeion.hdap` só publica chaves públicas + `omphalos`.
- AEAD nonce aleatório 12B por envelope; tag 16B; envelope com `VERSION`, `KDF`, `ITERATIONS`, `SALT`, `NONCE`, `TAG`, `CIPHERTEXT`.

### 5.1 Transporte (TLS)
- **TLS de base no aplicativo**: todo nó gera **certificado auto-assinado Ed25519** no primeiro boot e o persiste no bundle atômico `<data>/tls.identity` (com export de `<data>/tls.crt` + `<data>/tls.key`); o pin é estável entre reinícios (um pin rotativo quebraria silenciosamente todo peer pinado, release de transferência e handshake de descoberta). `--ephemeral` mantém o comportamento antigo em memória para testes. Serve TLS via rustls; fora de loopback/dev, o cliente **não** aceita plaintext.
- **Pinning TOFU**: o cliente fixa a impressão digital do certificado (`sha256(cert_der)`) do primeiro contato com o nó; conexões com pin divergente são **recusadas no handshake**.
- **Áncora de confiança**: o `server_id` (identidade Ed25519 do pyle) é independente do pin TLS; a raiz de confiança do nó é a sua impressão do pin (bootstrap offline do primeiro nó aceito — MITM de primeira conexão é risco declarado, AME-09).
- `/health` publica `tls_pin` para auditoria manual do pin.
- Implementação: crate `hdap-tls` (geração de cert, acceptor rustls, `PinVerifier`), integração em `hdap-server/http.rs` (`serve_tls`) e `hdap-cli/http_client.rs` (`HttpClient::new_tls(host, port, pin)`).

---

## 6. Cofre local (`krypte.hdap`)
- DOC local cifrado (ChaCha20-Poly1305, chave = Argon2id(senha, salt)). Contém: seed/HDAP Identifier, chave privada de assinatura, chave privada de cifração, nickname/sufixo. **Nunca enviado à rede.**

---

## 7. Autenticação global e sessão (3FA)

O desenho do 3FA parte de três exigências que precisam valer ao mesmo tempo. A primeira é que o servidor consiga verificar a prova sem possuir um segredo que o cliente tem. A segunda é que a sessão seja verificável pelo nó que a emitiu, sem exigir que todos os nós compartilhem o mesmo segredo. A terceira é que o OTP não dependa de um estado global sincronizado a cada login. As decisões abaixo satisfazem essas três exigências.

### 7.1 Materiais
- `session_secret`: **derivado, nunca transmitido.** Ambos os lados derivam `K = X25519(priv_enc(usuário), pub_enc(servidor)) == X25519(priv_enc(servidor), pub_enc(usuário))`. Nenhum servidor **armazena** `K`; cada nó recomputa `K` no momento da verificação a partir da **chave pública** do user (publicada em `prosopeion.hdap`) e da **chave privada** de seu próprio par de cifração.
- `omphalos`: âncora da cadeia de hash (pública). Cada nó guarda apenas o **consumo de passos** que observou (ver 7.3).

### 7.2 Fatores — fluxo por nó
1. **F1 — posse (adesão):** `proklesis` (nonce+ts, TTL `kairos`=60 s), consumido; cliente assina com Ed25519; servidor valida com a chave pública do `prosopeion`.
2. **F2 — conhecimento (OTP):** servidor pede passo `r`; cliente revela `w_r = H^(k-r)(seed)`; servidor verifica `H^r(w_r) == omphalos`. **A revelação é vinculada ao desafio**: cliente envia `w_r` **e** `H(w_r || proklesis.nonce)`; o servidor registra o passo consumido e **propaga o consumo aos pares** (federação, §7.4) — toda preimagem só vale no passo estritamente maior do que o maior passo observado.
3. **F3 — posse de `K` (derivado por DH):** cliente envia `proof = HMAC(K, "hdap:code" || user_id || server_id || ts)`. Servidor computa `K` de `priv_enc(servidor) + pub_enc(user)` e verifica. **Sem envelope `auth_code` guardado pelo servidor, sem segredo armazenado, sem chance de o servidor não validar.**

> **Por que a prova é válida:** o verificador tem tudo de que precisa. `K` deriva de material que ele já possui (a sua chave privada de cifração) somado à chave pública do usuário. Não existe a situação em que o servidor não tem o segredo.
>
> **Por que a sessão é por nó:** `symbolon = HMAC(K, "hdap:session" || server_id || exp)`. Outro nó não consegue verificar esse token, porque não tem `K`. A decisão é explícita: **a identidade é global; a sessão é por nó**. Um login cria sessões separadas por nó, reusando a mesma prova 3FA com desafio renovado. O token carrega `server_id` e nunca é aceito fora do emissor.
>
> **Por que o OTP resiste a replay entre nós:** além do desafio de uso único, o consumo do passo (`w_r`) é propagado no `homospondoi` pela sincronização, no campo `OTP_CONSUMED` do `pheme` e do `prosopeion`. Um `w_r` já usado em outro nó tem `r` menor ou igual ao último passo observado e é rejeitado.

### 7.3 Sessão (`symbolon`)
- Token por nó, TTL configurável (default 12 h). Para acessar outro nó: re-autenticar com novo `proklesis` e OTP+1 (passo estritamente maior). O tipo `symbolon.hdap` na árvore **não existe mais** — o token é derivado localmente, não publicado.
- **Rotação de `omphalos`** (`POST /omphalos`, sessão do dono): troca âncora e `SEED_ITER` (estritamente crescente) e zera o piso de replay do nó; a cadeia antiga morre. Para ser global, o usuário replica a nova edição do `prosopeion` pelos nós (cada nó roda a rotação por si).

### 7.4 PoW de entrada (`pylaia`)
- 1 mochthos "entry" por login (TTL configurável). Mesma solução vale para todos os nós (challenge single-use pertence ao nó).

---

## 8. Permissões (`adeia.hdap`)

- A `adeia` é uma ACL declarativa e pública. A linha canônica é `PERM <owner> <sujeito> <caminho> <direito>`, onde `sujeito` é `all` ou `user:<guest_id>`, `caminho` é `/`, uma pasta (`docs/`) ou um arquivo (`docs/segredo.txt`), e `direito` é `deny|read|write|own`. A forma compacta de v1.0 (`PERM <owner> all read`, `PERM <owner> user:<id> read`, `PERM <owner> path:<p> read`) continua aceita e é emitida para regras de casa inteira, para que documentos antigos sigam válidos.
- A avaliação é determinística e conservadora: **(1)** a regra do caminho mais específico vence (arquivo > pasta > raiz); **(2)** no mesmo caminho, `user:<id>` vence `all`; **(3)** no mesmo nível de especificidade, `deny` vence qualquer direito positivo; **(4)** sem regra que conceda o direito pedido, a resposta é negativa. Assim, liberar a casa com `PERM all / read` e negar um arquivo a uma pessoa com `PERM user:<id> docs/segredo.txt deny` funciona sem fechar o resto da casa.
- A mesma `adeia` pode declarar **`DIADOSI=white:<pyle>;<pyle>;`** ou **`DIADOSI=black:<pyle>;<pyle>;`**. A lista é avaliada contra o `server_id` do pyle que **replica** ou **serve** o namespace: `white` só permite os listados; `black` nega os listados. O filtro vale para cópia (`store_namespace`/`fed_fetch_blob`) e leitura (`authorize`/`authorize_replica`), inclusive réplicas antigas do Cenário B. Documentos públicos de identidade (`prosopeion.hdap`, `adeia.hdap`, `diadosi.hdap`) são isentos do filtro de leitura.
- **O sujeito da decisão é a identidade autenticada na sessão** (7.2). O servidor decide `requester ∈ allowed(scopes)` usando o `prosopeion` da sessão — nunca um campo forjado pelo cliente.
- Para convites federativos (E2E), mantém-se a derivação `shared = X25519(priv_anfitrião, pub_convidado)` **exclusivamente para cifragem de conteúdo compartilhado**, não para autorizar: prova de autenticidade continua sendo a `sphragis` da sessão (Desafio-resposta). O servidor **não verifica hint**; só a identidade da sessão.
- Consequência: não há "hint que se possa repetir" — o que se repete é a sessão autenticada, que exige prova 3FA.

---

## 9. Mochthos por banda e capacidade

### 9.1 Desafio
```
SOLUTION = SHA256(CHALLENGE || be64(NONCE)); SUCCESS: leading_zero_bits >= TARGET_BITS
BITS(claim) = clamp(ceil(log2(claim_hps × target_secs)), min_bits, max_bits)
```

- **A dificuldade é do servidor, nunca do cliente.** `/mochthos/proklesis` devolve a política `{target_secs, min_bits, max_bits}`. O cliente **mede** seu hashrate e o declara em `hashrate`; o nó aplica `PowPolicy::bits_for`. O cliente **não** envia `TARGET_BITS` — permitir isso era o furo que aceitava `target_bits: 0` (banda grátis).
- **Piso e teto.** `min_bits` é trabalho mínimo absoluto (nenhuma alegação compra menos); `max_bits` limita o efeito de uma alegação absurda. `bits_for` é monótona: inflar o hashrate nunca é desconto. `--pow-strict` recusa alegações fora da faixa em vez de as clamp.
- **Limite declarado.** A dificuldade é inteira, então o tempo esperado cai em `[target_secs, 2×target_secs)`. Isso **não** prova que o cliente gastou `target_secs` — não há como distinguir hardware rápido de lento só pela prova. O backstop anti-abuso é `band_bytes_per_hour` (teto por conta/hora) sobre `choregia`. "Adaptativo" e "impossível de burlar" são objetivos em tensão; a política é adaptativa e o teto por hora impede abuso.

### 9.2 Objeto
`pow/N.hdap.pow` — DOC assinado. O nó assina com sua chave Ed25519 **persistente** (`State::node_sign_seed`) e grava o blob, registrando um `BandObject{countersigned:false}`. O cliente anexa seu slot e assina `signature_input(1)`; `POST /mochthos/countersign` verifica as duas assinaturas (emissor sobre `signature_input(0)`, dono sobre `signature_input(1)`) e torna o objeto gastável. Campos sistema `mochthos` §4.3, mais `CHALLENGE` e `HASHRATE_HPS`. Estado: `unused → consumido`.

### 9.3 Recontagem
- Banda (`choregia`) é **por nó**: cada `pyle` aplica a SUA política (`1 mochthos = X bytes`) ao receber. `BANDWIDTH_BYTES` do emissor ≠ banda no destinatário (re-validação local).
- **Double-spend entre nós — regra de missão**: um mochthos é **honrado apenas pelo nó que o emitiu**. O desafio é vinculado ao emissor (`CHALLENGE = "hdap-mochthos:<server_id>"`; `/mochthos/proklesis` devolve `issuer` + a política `{target_secs, min_bits, max_bits}`). Um proof resolvido contra o desafio do nó B é **descartado no nó A** (o emissor é parte do desafio; não há "bilhete universal" a gastar em vários nós). Além disso, cada nó registra `(CHALLENGE, NONCE)` como **single-use local**: re-submeter a mesma prova no próprio nó é rejeitado. `syngraphe` **consome** o mochthos (substitui, o `.pow` é apagado). Não há "registro global": há **responsabilidade do signatário + recontagem local + emissor amarrado à identidade do pyle** (austríaco: valor de um bilhete = promessa de quem assina; e só quem assina o honra).

### 9.4 Tratado (`syngraphe`)
- Antes de finalizar upload: o cliente envia `X-HDAP-Syngraphe` (base64 do `SyngrapheDoc` renderizado, assinado pelo dono), que substitui o mochthos consumido (apagado). Documenta desafio, onde estava, que foi apagado, uso, banda restante. O nó confere os campos contra o `BandObject` e grava `pow/N.hdap.syngraphe` com seu ack. **Não reembolsável** (apagar não devolve banda).
- Ao propagar `apographon`, metadados carregam o caminho dos `.hdap.mochthos` usados; nó destino confere (§10.3).

### 9.5 Estados
`unused → dotado reservado → consumido (syngraphe)`; "liberada" só existe como liberação de disco local, não de capacidade (décision mantida).

---

## 10. Armazenamento, replicação, deleção, matriz

### 10.1 Upload
1. Cliente assina **bytes crus** com Ed25519 → envia `(ktema, hash, sphragis, referências adeia/prosopeion)`. A assinatura vai no header `X-HDAP-Sphragis` (base64).
2. Servidor valida: hash==conteúdo, assinatura confere **contra a pubkey da sessão autenticada** (nunca contra campos do corpo), permissões de escrita, mochthos/choregia (syngraphe). Sem `X-HDAP-Sphragis` válido → `401` (salvo `require_content_signature=false`).
3. Persiste **cifrado em repouso** (`aead_seal(master_key)`) e registra no `prytaneion` de **origem**. O commit é **síncrono antes da resposta**; falha → `500`.

### 10.2 Matriz (`prytaneion.hdap`)
- Por conteúdo (chave = hash): `ORIGIN_PYLE`, `ORIGIN_PROSPEION`, `REPLICAS [{pyle,path}]`, `LETHES` (histórico), `PHEME_UPDATES`.

### 10.3 Replicação (`apographon`)
- Só propaga após o destino validar os mochthos públicos do user + prytaneion; réplica linkada à matriz original.

### 10.4 Deleção (`lethe` / `ostrakon`)
- Solicitada pelo usuário (ou matriz). Todos os nós listados apagam e **confirmam** ao `prytaneion`.
- O nó apagador deixa um **`ostrakon`** (registro curto `LETHED_HASH`, `LETHED_AT`, `INITIATOR`) — **exílio do conteúdo**. O conteúdo binário é apagado; o ostrakon é só o marcador.
- **Nó que não apaga**: falha evidenciada no `prytaneion` → `oneidos` (queda de `pheme`) e, em modo público, acionamento de `euthyne` com quebra de `paratheke`.
- **Limite declarado**: deleção **não é enforcement físico**; é **incentivo econômico + reputação** (a filosofia econômica da §`katallaxia` faz reter o tombstoned sair caro). Como a federação é aberta, a retenção depende de reputação e de incentivos, não de confiança prévia entre operadores.

### 10.5 Integridade
- Hash e `sphragis` sempre verificados no servidor (ler, replicar, propagar).

---

## 11. Transferência de posse (`metabibasis`, assíncrona)

O `metabibasis` é um **handshake assíncrono**: o cedente oferece, o cessionário aceita, e só então a origem bloqueia a escrita e copia os bytes. As duas identidades não precisam estar no mesmo cliente nem compartilhar chave privada.

1. `POST /transfer/request` com `{"draft":{...}}`: o pyle do cedente monta o manifesto (`TARGET*`, `DEST*`, `HASH*`, `SIZE*`), a lista de `SCOPE*` e os dados de ambos os pyles (chaves Ed25519 e pin TLS). O cliente assina o `REQUEST` no slot 0; o pyle de origem contra-assina no slot 1.
2. O pedido final é guardado como `pending` na origem e entregue ao pyle de destino em `POST /transfer/inbox`. No mesmo pyle, a inbox é local e não há tráfego de rede.
3. O cessionário consulta `GET /transfer/inbox`, pede o rascunho de aceite em `POST /transfer/accept` com `{"draft":"<request_id>"}` e assina o `ACCEPT` no slot 0. O pyle de destino contra-assina no slot 1.
4. O `ACCEPT` embute o texto exato do `REQUEST` e seu `REQUEST_HASH`. A origem só aceita o aceite se o hash, o manifesto e as assinaturas dos slots 0/1 conferirem.
5. A origem executa `lock_cessions` **antes** de copiar, re-verifica cada hash/tamanho e grava a cópia no destino. Mesmo pyle: `complete_local`. Pyles distintos: a origem empurra os blobs para `POST /transfer/deliver` no destino.
6. Origem e destino guardam o registro final imutável. O cedente perde `Write`/`Own` sobre os escopos cedidos; o cessionário recebe `ktema` reais (não links).

**Tipos de alvo (`TARGET_KIND`).**
- `file`: exatamente um alvo; a cópia mantém o caminho.
- `dir`: um ou mais escopos de pasta; a cópia inclui o conteúdo atual e os `SCOPE*` bloqueiam também arquivos criados depois.
- `identity`: todos os objetos do cedente, exceto `metabibasis/` e `pow/`; cada cópia vai para `{old_owner}@{old_pyle}/{path}`, para não colidir com o espaço do cessionário.

**Remoto.** O pyle precisa ser endpoint-addressed (`pyle-<base64url(host:port)>`). TLS fora de loopback exige pin; o CLI descobre `/health` (chave do nó + pin) e `/registry?user_id=` (chave do usuário) antes de montar o rascunho. O destino de um aceite remoto encaminha o `ACCEPT` para `POST /transfer/complete` na origem; se a origem estiver inacessível, o aceite fica `accepted` e a resposta é `502`, sem cópia parcial.

### 11.1 Alvos, escopos e colisões
- O cliente normaliza a URI de destino (`HDAP!<pyle>@<user>/<path>`) e envia `new_pyle`, `new_owner`, `new_uri` e `target_kind` no rascunho. O servidor remove `/` inicial dos alvos e rejeita alvo vazio.
- `SCOPE*` é a seleção original, separada do manifesto: `docs` cobre `docs/inner.txt` e arquivos futuros, mas não `docs-old/x.txt` (fronteira de diretório). Escopo vazio é a identidade inteira.
- `TARGET*` é o conjunto exato de blobs copiados no momento do pedido. O manifesto congela `HASH*`/`SIZE*`; qualquer mudança na origem entre pedido e aceite retorna `409`.
- Destino ocupado por conteúdo diferente retorna `409`; conteúdo idêntico é idempotente. A quota `moira` do cessionário é checada antes da escrita.
- A transferência **não** materializa `<path>.hdap.link` nem move os blobs originais: o cedente conserva os bytes, mas fica read-only, e o cessionário recebe uma cópia independente.

### 11.2 Registros e idempotência
- Pendente: `metabibasis/<b64(old_uri)>-<b64(new_uri)>-<request_id>.request.hdap`.
- Final: `metabibasis/<b64(old_uri)>-<b64(new_uri)>-<request_id>.hdap`.
- Esses caminhos são imutáveis para upload/delete (403), como qualquer recibo de transferência.
- O `REQUEST` carrega `REQUEST_ID`, partes, URIs, pyles, chaves, pins, `TARGET_KIND`, `SCOPE_COUNT`/`SCOPE*` e `TARGET_COUNT`/`TARGET*`/`DEST*`/`HASH*`/`SIZE*`. O `ACCEPT` carrega `REQUEST_ID`, `REQUEST_HASH`, `REQUEST_DOC_B64` e a cópia do manifesto.
- Reenviar a mesma entrega é idempotente; um `REQUEST_ID` diferente com o mesmo id é colisão (`409`). Reaceitar um pedido `completed` devolve o mesmo `record_path`.

### 11.3 Read-only garantido e irrevogável
O mecanismo é estrutural, não textual: `State::ceessions[cedente] = [{to, path, at}]`.

- `authorize(cedente, cedente, path, Write|Own)` nega se qualquer cessão cobre `path`; `Read` continua permitido.
- A cessão é gravada antes da cópia; uma falha de cópia não devolve ao cedente o direito de reescrever o que já foi aceito.
- `POST /adeia` não consegue desfazer a cessão: ele substitui o documento ACL, mas a checagem de cession vem antes e é independente do texto.
- A irrevogabilidade vale **contra o cedente**: ele não readquire escrita/posse pelo `adeia`. O novo dono, porém, pode descartar o conteúdo: ao apagar sua cópia, o pyle de destino envia `POST /transfer/release` assinado com a chave do pyle; a origem apaga a cópia antiga, remove a cessão quando não resta objeto sob o escopo e propaga o tombstone aos espelhos. Sem isso, a "cópia read-only" e seus espelhos sobreviveriam para sempre ao conteúdo transferido.
- Para terceiros, a autorização continua vindo do `adeia` do dono; a cessão não concede leitura automática no espaço antigo, porque o cessionário já tem a cópia.

### 11.4 Compatibilidade
`POST /metabibasis` (o antigo fluxo dual-sig local) permanece apenas para arquivos existentes e não cria inbox, `REQUEST`/`ACCEPT` nem registro assíncrono. Ele recusa pastas/identidades, alvos `metabibasis*`/`pow/*` e caminhos já cedidos; clientes novos devem usar as rotas `transfer/*`.

---

## 12. Reputação distribuída (`pheme`) — por modo

- `/HDAP_PHEME/pheme.hdap`: mesmo conteúdo e mesmo hash em todos os nós da federação, validado a cada propagação.
- Entradas: `TARGET_ID` (prosopeion ou pyle), `SCORE_DELTA`, `REASON`, `EVIDENCE` (hashes), `OTP_CONSUMED` (para o §7.2 anti-replay OTP).
- Atualização: `pheme_candidate.hdap` assinado pelo proponente; nós verificam evidência e aplicam.

**Modos:**
| Modo | Consenso | Voto | Uso |
|---|---|---|---|
| **Federado** (homospondoi) | Maioria simples dos nós ativos | Nós com direito a voto | Malha de pyles que se conhecem |
| **Aberto** (rede pública) | Peso por `paratheke` (stake) | Só quem **penhorou** tem voz | Rede pública global — voto anônimo não pesa → anti-Sybil econômico |

- Ex.: nó que não apagou `lethe` — matriz recebe edição removendo score com motivo; nós verificam e atualizam `pheme` local + avisam vizinhos.

---

## 13. Descoberta / DDNS (`kerux`, opcional)
- `kerux.hdap` por usuário mapeia aliases → URI HDAP. `GET /kerux/{alias}` em qualquer nó resolve; resultado verificado por assinatura. Federação troca registros DDNS (reduzido do HPS).

---

## 14. Operações do servidor (REST, JSON) — rotas gregas

### 14.1 Públicas
| Método | Rota | Ação |
|---|---|---|
| POST | `/register` | 1º registro (prosopeion) |
| POST | `/omphalos` | rotação da âncora OTP (sessão do dono; `SEED_ITER` estritamente crescente; piso de replay zerado) |
| GET | `/proklesis` | desafio de auth (nonce) |
| POST | `/auth` | prova 3FA → `symbolon` por nó (TTL) |
| POST | `/mochthos/proklesis` | emitir desafio de mochthos (devolve `{challenge, issuer, target_secs, min_bits, max_bits}`) |
| POST | `/mochthos/issue` | validar/emitir mochthos (honrado **só pelo emissor**; proof single-use local) |
| POST | `/mochthos/countersign` | dual-sig: dono counterassina o `.hdap.pow` e o torna gastável |
| GET | `/mochthos/band` | listar os `BandObject` vivos do dono (`granted`/`remaining`/`countersigned`) |
| GET/POST/DELETE | `/ktema/*` | list, upload, download, rm (adeia + choregia) |

`GET /ktema/list[?owner&path]` (perm **Read**): lista um diretório do dono. Resposta JSON: `{owner, path, entries:[{name, dir, size, hash, path}]}`, onde `dir: true` para pastas implícitas (derivadas do separador `/`, não persistidas — uma pasta desaparece quando não resta arquivo dentro) e `size` é o tamanho real dos bytes (`ciphertext - 12 nonce - 16 tag`). Implementado em `hdap-server` (`handle_ktema_list`) e exposto no CLI como subcomando `hdap-cli list [DIR]` e no explorador do GUI.
| POST | `/adeia` | publicar edição de adeia.hdap |
| POST | `/transfer/request` | rascunho e pedido assinado (cedente) |
| POST | `/transfer/inbox` | entregar pedido assinado (auto-verificável) |
| GET | `/transfer/inbox` | listar ofertas pendentes do usuário autenticado |
| POST | `/transfer/accept` | rascunho e aceite assinado (cessionário) |
| POST | `/transfer/complete` | origem recebe o aceite e copia/empurra os bytes |
| POST | `/transfer/deliver` | destino recebe os blobs e grava o registro final |
| POST | `/transfer/release` | destino pede à origem para apagar a cópia cedida quando o novo dono apaga a dele |
| GET/POST | `/prytaneion/*` | matriz, réplicas, leis |
| GET | `/pheme` | reputação |
| GET | `/kerux/{alias}` | DDNS |
| GET | `/health`, `/pyle/integrity` | estado/integridade do nó |
| POST | `/timi` | (módulo `katallaxia`) publicar preço |
| GET | `/timi` | (módulo `katallaxia`) listar preços anunciados |
| POST | `/resolve` | resolver uma URI de acesso `HDAP!<pyle>@<user>/<path>` (puxa de outro pyle quando preciso — §14.2.1) |
| GET | `/mirrors` | listar os namespaces remotos já espelhados localmente |

### 14.2 Federação (`homospondoi`)
| Método | Rota | Ação |
|---|---|---|
| POST | `/homospondoi/handshake` | apresentação entre nós (nonce/TTL); requer `endpoint` (host:port) e opcional `tls_pin`; **devolve `node_sign_pub`** para o par pinar |
| POST | `/homospondoi/sync` | semicronia periódica (ktema/prytaneion + OTP_CONSUMED); **dispara replicação automática** de blobs desconhecidos |
| GET | `/homospondoi/fetch_blob?hash=<content_hash>` | **replicação de conteúdo**: devolve bytes em plaintext (TLS) do blob cujo hash coincide; autenticação por headers `X-HDAP-*` |
| GET | `/homospondoi/namespace?owner=<user_id>` | lista o usuário (`prosopeion`/`adeia`/chaves) e as entradas (`path`/`hash`/`size`); usado pelo pull-through |
| POST | `/homospondoi/pheme` | propagação de candidato de pheme |
| POST | `/homospondoi/prytaneion_update` | alterações de matriz/deleções |
| GET | `/homospondoi/directory?digest=<hex>` | diretório de pyles conhecidos; devolve só o digest quando o chamador já está convergido |
| POST | `/homospondoi/announce` | anúncio gossip de um pyle recém-verificado (evento + TTL) |
| GET/POST | `/homospondoi/ledger` | livro global de réplicas/proveniência; `GET ?digest=` responde só o digest quando convergido, `GET ?hash=` filtra uma entrada, `POST` faz merge |
| POST | `/homospondoi/house_move` | recebe transferência de casa assinada pelo usuário (nova edição de `adeia`) |

Headers estilo HPS: `X-HDAP-*` + assinatura + nonce + timestamp ±30 s, nonce replay TTL.

> **Federação aberta com pin no primeiro contato** (AME-34): `/homospondoi/handshake` admite qualquer pyle. Se `Config.federation_peers` (`node_id → {pubkey, endpoint, tls_pin}`) tiver uma entrada para o id, a chave apresentada precisa casar com ela; caso contrário, a chave apresentada é fixada em `State::peers` e o par passa a ser conhecido. Um id já fixado não aceita outra chave (`409`). `federation_peers` é, portanto, um reforço opcional de pin, não uma lista de admissão. O conteúdo continua verificado por assinatura de autor e hash, então um impostor pode ser alcançado, mas não pode forjar conteúdo.

**Descoberta global de pyles (bolha).** Todo handshake bem-sucedido entra em `State::peers` e é um candidato a gossip. A troca é *digest-first*: cada nó calcula `SHA-256` canônico sobre `(node_id, endpoint, sign_pub_hex, tls_pin)` ordenados; `GET /homospondoi/directory?digest=` devolve apenas `{digest}` quando o chamador já tem a mesma lista, e a lista completa só quando diverge. O handshake também devolve o diretório quando o digest do chamador difere, então o primeiro contato já semeia ambos os lados sem uma segunda rodada.

Um pyle novo só é aceito depois de um **handshake de callback** ao endpoint anunciado, no qual `server_id`, `node_sign_pub` e `tls_pin` precisam coincidir com o anúncio — o voto é a tentativa real, não a palavra de quem anunciou. Só então ele é copiado para `peers` e replicado. Para não transformar a malha em tempestade:

- anúncio imediato para fanout determinístico de **2** pares, com `event_id` e `ttl` (máx. 8); cada nó processa cada `event_id` uma vez e não reencaminha loops;
- anti-entropy periódica (60 s) contra **2** pares rotativos, sempre por digest;
- health check de um par a cada 5 min e verificação completa apenas de candidatos novos;
- fila e lista limitadas (`MAX_JOBS`/`MAX_KNOWN_PEERS`), TTL de dedup de 10 min.

A descoberta automática está sempre ativa; um par confiável pode apresentar um desconhecido, mas ele só entra depois do handshake de callback. Nós convergem para a mesma lista de pyles **dialáveis** (endpoint não vazio); falhas viram `PeerHealth` local, não removem o registro histórico. `--advertise ADDR:PORT` define o endereço público e o id padrão do nó (`pyle-<base64(advertise)>`); sem ele, o id vem de `--listen`, e um bind curinga produziria um id inalcançável.

**Replicação automática (§10.3):** ao receber `/homospondoi/sync` com `content_hash` que o nó ainda não possui, o nó dispara `GET /homospondoi/fetch_blob?hash=...` no peer remetente, verifica o hash, cifra com sua `master_key` local e registra no `prytaneion` como réplica. A replicação usa a chave de assinatura do nó (`node_sign_seed`) para autenticar a requisição de saída.

#### 14.2.1 Acesso cross-pyle (pull-through / `apographon` sob demanda)
Uma URI de acesso `HDAP!<pyle>@<user>/<path>` pode nomear outro pyle. Em vez de recusar, o nó local **puxa o namespace daquele usuário** e passa a servi-lo. Rotas do nó local:

| Método | Rota | Ação |
|---|---|---|
| POST | `/resolve` | corpo `{ "uri": "HDAP!<pyle>@<user>/<path>" }`; se o pyle for o próprio, responde `{status:"local"}`; senão dialoga com o par, espelha e responde `{status:"mirrored", pyle, owner, path, copied}` |
| GET | `/mirrors` | lista os namespaces remotos já espelhados (`owner`, `origin_pyle`, `origin_server`, `pulled_at`) |
| POST | `/resolve_hash` | corpo `{hash, owner?, path?}`; resolve um arquivo pelo hash (local → livro global → origem → réplicas), valida `sha256` + `sphragis`, cacheia sob o requisitante e registra a réplica no livro |
| GET | `/bubble` | sessão obrigatória; devolve `{counts:{total,core,extended,untrusted}, peers:[...]}` para o painel do GUI |
| POST | `/house_move` | sessão obrigatória; aplica uma transferência de casa já assinada pelo usuário (`adeia` de edição maior) e propaga aos pares |
| POST | `/diadosi` | sessão obrigatória; instala `diadosi.hdap` assinado pelo dono (procuração de sucessão + hashes/edição atuais) |

Fluxo do espelhamento: `GET /homospondoi/namespace?owner=` no par → para cada entrada, `GET /homospondoi/fetch_blob?hash=` (ignora `pow/*`), re-verifica `sha256`, re-sela sob o `master_key` local e grava sob o **mesmo** `owner`. Cada réplica entra no `prytaneion` com a origem real; o pyle de origem é registrado no livro de conhecidos (`State::peers`) e em `State::mirrors`. A operação é **idempotente** (segunda chamada copia 0). Qualquer pyle é dialável: um id endereçado (`pyle-<base64url(host:port)>`) é resolvido pelo próprio endereço e faz handshake antes do pull. `POST /resolve` é o único ponto de replicação iniciado pelo **leitor**, fechando a lacuna de quem nunca sincroniza ativamente.

**Busca por hash e livro global (`resolve_hash` + `ledger`).** O leitor que só conhece o `pechys` usa `POST /resolve_hash`: o nó procura o blob local autorizado, depois consulta o **livro global** local e até 8 pares (`GET /homospondoi/ledger?hash=`), e por fim tenta a origem e as réplicas anotadas. Cada download é verificado contra o hash; a proveniência vem dos headers `X-HDAP-Origin-Pubkey`/`X-HDAP-Sphragis`/`X-HDAP-Origin-Path` do `fetch_blob`, do próprio livro, ou de `GET /prytaneion?hash=` na origem. A `sphragis` é verificada contra a pubkey de origem; assinatura inválida descarta a fonte, ausência (conteúdo legado) é aceita com `verified:false`. O blob é re-selado sob o `master_key` local em `cache/<hash>/<basename>` do **requisitante**, sujeito à quota `moira_bytes`, e a réplica `server_id:owner/path` entra no livro. O livro (`ledger.rs`) é trocado *digest-first* como o diretório, tem merge idempotente/comutativo, origem "first writer wins", réplicas/deleções unidas e teto de 4096 entradas; o handshake carrega `ledger_digest` e um mismatch agenda o pull.

**Bolha no GUI.** `GET /bubble` classifica os pyles conhecidos em `core` (handshake verificado, sem falhas), `extended` (dialável, ainda não confirmado) e `untrusted` (sem endpoint ou ≥3 falhas). O rodapé do GUI mostra `Bolha: N pyles (X core, Y extended, Z untrusted)` e o botão "ver lista" abre os detalhes; o resumo é atualizado no login e a cada `/sync`.

**Barra de URI com DDNS.** No GUI, um token isolado (sem `/`, espaços, `HDAP!` ou id global) é tratado como possível apelido: a barra consulta `GET /kerux/{alias}` numa thread de trabalho. Se o alias existir, navega para a URI de destino; se não existir ou a consulta falhar, abre o caminho literal digitado — um erro de DDNS nunca prende o usuário. Nomes já presentes na pasta atual têm prioridade e abrem o caminho local sem consulta.

**Cenário B: réplica antiga continua servível.** O `adeia` é congelado no momento do pull em `State.replica_acls` (`owner/path → texto`). Conteúdo já replicado continua legível por esse snapshot mesmo que a origem/poster fique offline ou publique uma edição mais restritiva; `authorize_replica` só concede **Read**, e `authorize` atual governa conteúdo novo. Assim o espelho não bloqueia a bolha inteira esperando transferência: só **novas edições** exigem a transferência de casa.

**Diádosi (procuração de casa).** `diadosi.hdap` é um documento público assinado pelo dono com `OWNER`, `OWNER_PUBKEY`, `HOME_PYLE`, `FALLBACKS` (1..=16), `ADEIA_EDITION`, `ADEIA_HASH`, `PROPERTIES_HASH`, `EDITION` e `PREV_HASH`. Ele é a **procuração** para um backup assumir sem nova assinatura de `house_move`: no início de `GET /sync`, o pyle local lê o documento, verifica a assinatura Ed25519, exige que os hashes/edição de `prosopeion.hdap`/`adeia.hdap` sejam os atuais, que `HOME_PYLE` seja o pyle ainda anunciado como casa e que ele próprio esteja em `FALLBACKS`. Se o home estiver offline (health check falha) e o peer do home for conhecido com endpoint, o fallback grava `HOME_PYLE=<si>` e passa a anunciar a casa; sem peer/endpoint conhecido **não promove**. Editar `adeia`/`properties` invalida a procuração até reassinar `diadosi.hdap`. Na GUI, `diadosi` é um tipo do menu e o cartão ausente em Configuração abre o painel de backup; ao abrir, o painel carrega o `diadosi.hdap` existente ou pré-preenche `FALLBACKS` com pyles dialáveis da bolha (exceto o próprio nó, entradas sem endpoint e `untrusted`), sempre editáveis antes de assinar.

**Transferência de casa (`house_move`).** Quando a origem cai, o usuário conectado a um pyle conhecido usa a ação explícita **“mudar casa”** na GUI (ou a rota direta) e assina `hdap:house_move:<user>:><pyle>:<sha256(properties)>:<sha256(adeia)>` com sua chave e envia `POST /house_move`. O nó verifica a assinatura Ed25519, exige `adeia.edition` **estritamente maior** que a instalada, escreve `users`/`prosopeion.hdap`/`adeia.hdap`/`permissions` e propaga a mesma transferência (fanout 2, TTL ≤ 3) via `POST /homospondoi/house_move`. Sem manifestação assinada do usuário, o conteúdo novo continua indisponível; o público antigo segue pelo snapshot acima.

**Nomes de pyle por endereço:** o `server_id` default é `pyle-<base64url(host:port)>` (`crates/hdap-server/src/pyle.rs`), então a própria URI carrega o endereço e o par pode ser dialado sem registro externo; `--id` sobrescreve. O id atesta **localização**, não identidade: a confiança no conteúdo vem da `sphragis` + hash, e a do peer da chave fixada no primeiro handshake.

### 14.4 Sincronia com peers offline (`pheme`/`otp_consumed`)
- **`pendings`**: fila de `pheme_candidate`/`OTP_CONSUMED` não confirmada pelo destino; ao reestabelecer o peer, drena em ordem (FIFO) e confirma.
- **Retry com backoff**: exponencial (ex.: 1 s, 2 s, 4 s...) com teto; descartar após janela de validade do `kairos`.
- **Limitação declarada**: em rede aberta, a janela de replay OTP = latência de sync; irredutível sem consenso global (ver §17 crítica/item 2).

### 14.3 Tokens/concorrência
- Sessões com TTL; desafios consumidos; nonces de federação janela ±30 s + replay guard. Deleção: assinatura do solicitante + confirmação dos réplicas.

---

## 15. Concorrência e falhas

- Mutantes exigem prova da sessão; idempotentes onde possível (retry de upload: mesmo conteúdo → mesmo hash; não duplica `syngraphe`).
- Falha de nó em replicação: `pheme` + retry com backoff.
- Falha de `lethe`: `prytaneion` evidencia → `oneidos` (+ `euthyne`/`paratheke` em modo aberto).
- Upload interrompido: syngraphe não confirmado até persistência verificada integral.
- HTTP próprio (std `TcpListener`), limites de body (100 MB), rate limiting (10 req/s burst 20 por IP) e depth de corpo.
- **Quota de armazenamento por usuário (`moira`)**: `Config::moira_bytes` (0 = ilimitado); upload que exceda → `413`; delete libera a quota. A banda (`choregia`) só é consumida no sucesso do upload — falha em qualquer validação devolve a banda intacta (reembolso implícito).
- **Clock**: relógio do nó com `now()` capturado antes de locks (anti-deadlock); testes com relógio fixado para janelas determinísticas.

---

## 16. Katallaxia (módulo opcional de incentivos)

- Ver `docs/filosofia-economica.md` para a tese completa (austríaca). Resumindo o núcleo da economia:
  1. **Preço é sinal:** cada `pyle` publica `timi` (`timi.hdap`); usuário escolhe livremente. Sem planejador central.
  2. **Byte-tempo é a unidade (`obolos`):** guardar tem custo real; `tokos` cresce com duração (preferência temporal).
  3. **Reputação é capital (`pheme`):** cumprir `lethe` e contratos gera renda; violar destrói capital (`oneidos`).
  4. **Voz = stake (`paratheke`):** rede aberta vota em reputação só com penhor.
  5. **Arbitragem privada (`euthyne`):** disputas resolvidas por árbitros escolhidos; executa penhor + fame.
- **O que não é:** blockchain de contrato, tabela oficial de preços, oráculo, substituição do núcleo. Módulo opcional; o núcleo funciona sem ele.

### Interação com o núcleo
| Núcleo | Katallaxia adiciona |
|---|---|
| `syngraphe` | vira contrato de guarda pago (duração, preço, `kairos`) |
| `choregia` | capacidade produzida sob demanda de mercado (não doação) |
| `lethe` | enforçável por incentivo (perder `pheme`+`paratheke`) |
| `homospondoi` | membragem aberta com penhor |

---

## 17. Rede pública global — posicionamento honesto

| Questão | Resposta HDAP |
|---|---|
| Incentivo | `katallaxia`: preço por byte-tempo, moeda sadia local, reputação e penhor. |
| Consenso | Modo aberto = voto com stake (`paratheke`); Sybil não escala porque voz custa penhor. |
| Deleção | `lethe` incentivado (fama e penhor), nunca enforcement físico; declarado. |
| Autenticação | DH-derivada, sessão por nó, OTP com consumo propagado. |
| Permissões | Só a identidade da sessão, nunca um hint. |
| Privacidade | Metadados públicos são condição da verificabilidade; conteúdo cifrável no cliente; TLS. |
| Complexidade | Núcleo mínimo (auth, ktema, mochthos, adeia, prytaneion, lethe); o resto é módulo. |
| Legal | `lethe` e ostrakon para retirada; responsabilidade do nó que serve o quê; e-direitos abertos a ARG. |

---

## 18. Capacidade delegada (`exousia`) — **implementada (AME-36)**

`exousia.hdap` é um documento de autoridade delegada. O dono do espaço
(`OWNER`) pode outorgar a um `DELEGATE` um escopo restrito sobre um caminho,
e o delegado pode re-delegar dentro desse mesmo envelope. **O servidor não é
autoridade**: ele apenas confere assinaturas e contenção; o outorga nasce da
cadeia de signatários.

### 18.1 Corpo canônico

| Campo | Significado |
|---|---|
| `OWNER` / `OWNER_PUBKEY` | raiz da cadeia e sua chave de assinatura (hex, 32 bytes) |
| `DELEGATE` / `DELEGATE_PUBKEY` | delegado final e sua chave |
| `CHAIN0000`, `CHAIN0000_PUBKEY`, … | delegadores intermediários, do mais externo para o mais interno |
| `SCOPE` | `read` \| `write` \| `readwrite` (escopo desconhecido **não concede nada**) |
| `PATH` | caminho relativo ao espaço do `OWNER` |
| `EXPIRES_AT` | expiry unix; `0` = sem expiry |
| `NONCE` | 16 bytes aleatórios hex; unicidade por instância |
| `DEPTH` | nº de re-delegações; `0` = direto do dono |
| `PARENT_HASH` | obrigatório quando `DEPTH > 0` |

### 18.2 Cadeia de co-assinaturas

Uma assinatura por elo, em ordem da raiz para fora:

- elo `0` — assinado por `OWNER`, outorgando a `CHAIN0000` (ou a `DELEGATE` quando `DEPTH = 0`);
- elo `i > 0` — assinado por `CHAIN{i-1}`, outorgando a `CHAIN{i}` (ou a `DELEGATE` no último elo).

Portanto `len(SIGS) == DEPTH + 1`. Cada signatário MUST apresentar a chave
registrada para ele no corpo (troca de chave é rejeitada), e cada assinatura é
verificada sobre `signature_input(i)`.

Regras de verificação (`ExousiaDoc::verify_chain`):

1. `len(CHAIN) == DEPTH` e `len(SIGS) == DEPTH + 1`;
2. `DEPTH > 0` exige `PARENT_HASH`;
3. nenhuma identidade se repete na cadeia, e o `DELEGATE` não pode ser também
   delegador (auto-delegação impede escalada);
4. `OWNER_PUBKEY` precisa ser igual à chave do `prosopeion` do dono — a raiz de
   confiança **não** é afirmada pelo próprio documento;
5. em cada elo, a chave do outorgado precisa ser distinta da do outorgador.

### 18.3 Contenção (ESC) e expiração

- **Escopo:** `read ⊆ readwrite`, `write ⊆ readwrite`; `write` **não** implica
  `read`. Um filho nunca amplia o escopo do pai.
- **Caminho:** o caminho do filho precisa estar dentro do caminho do pai.
  Segmentos `.`/`..` e caminhos absolutos são rejeitados — `docs/../secrets`
  satisfaria uma comparação por prefixo mas endereça um irmão.
- **Expiry:** `is_covered_by` exige `DEPTH filho == DEPTH pai + 1`.
  `ExousiaDoc::may_outlive` impede que o filho sobreviva ao pai: se o pai expira,
  o filho precisa de um `EXPIRES_AT` concreto e **≤** o do pai. Como `0` significa
  "sem expiry", um pai que expira **não** pode delegar em perpetuidade.
- **Onde a contenção é exigida:** na emissão *e* na submissão do documento
  assinado. Uma cadeia válida prova apenas **quem** assinou, nunca **o que**
  podiam conceder; se o nó só conferisse na emissão, um cliente poderia enviar
  um corpo diferente, porém corretamente co-assinado, e ampliar a concessão. Por
  isso `POST /exousia {"capability": ...}` recarrega o pai armazenado
  (`PARENT_HASH`) e reexecuta escopo, caminho, profundidade e expiry. Um pai
  ausente ou ilegível é recusado — `DEPTH` nunca é aceito só por causa das
  assinaturas.
- Comprovação de posse: o servidor verifica a cadeia contra a chave
  do dono em disco, exige que a chave do `DELEGATE` seja a registrada para aquele
  usuário e restringe o uso ao escopo pedido — `readwrite` é o único escopo que
  satisfaz `Read` e `Write`.

---

## 19. Referências
- [lexico-grego.md](lexico-grego.md) (nomes), [filosofia-economica.md](filosofia-economica.md) (incentivos), [modelo-de-ameaca.md](modelo-de-ameaca.md) e [hps.md](hps.md) (legado).