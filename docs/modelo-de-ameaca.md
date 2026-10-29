# HDAP — Modelo de Ameaça

**HDAP v1.001 — Themelio · Epoptia**

> Revisão de 2026-10-29 · Protocolo: **1.0** (matriz v1). Complementa a [Especificação Formal](especificacao-hdap.md). O vocabulário grego segue o [Léxico Grego](lexico-grego.md), em transliteração ASCII.
> Princípio: propriedades de segurança **concretas e verificáveis**; nada de "não pode ser hackeado".

---

## 1. Premissas e atores

**Atores**
- **Usuário honesto** (U): dono da identidade (`prosopeion`).
- **Pyle honesto** (S): nó/servidor que segue a spec.
- **Pyle malicioso** (SM): controla um nó; pode mentir, adulterar, reter, reordenar.
- **Cliente malicioso** (CM): controla o cliente; forja pedidos.
- **Atacante externo** (A): sem credenciais.
- **Atacante com canal** (AC): MITM ativo/TLS, downgrade, replay.

**Assumimos**
- TLS com TOFU/pinning obrigatório em todas as plataformas.
- O servidor é transporte/custódia, **não autoridade de acesso**; provas de acesso são descentralizadas (spec §7–§8).
- Chaves privadas do usuário apenas no cliente.

---

## 2. Tabela de riscos

| ID | Ameaça | Alvo | Impacto | Mitigação |
|---|---|---|---|---|
| AME-01 | Pyle serve `ktema` adulterado | integridade/autenticidade | Alto | hash + `sphragis`; cliente **sempre** verifica; `?hash=` na URI (§3.3, §10.5); `prytaneion` |
| AME-02 | Pyle nega conteúdo (censura) | disponibilidade | Médio | `apographon` conhecidos no `prytaneion`; `pheme`; multi-nó URI (§10) |
| AME-03 | Pyle retém conteúdo após `lethe` | privacidade/conformidade | Alto | deleção confirmada via `prytaneion`; `ostrakon`; `oneidos`/pheme; em modo aberto `euthyne`+`paratheke` (§10.4, §16) |
| AME-04 | Replay de auth (pacote `authenticate` reusado) | sessão | Alto | `proklesis` consumida; HMAC com ts; janela `kairos`; passo OTP propagado (§7.2) |
| AME-05 | Força bruta do seed/`K` | autenticidade | Alto | seed 256-bit CSPRNG; `K` DH por sessão; rate limiting (§7, §15) |
| AME-06 | Double-spend de mochthos | economia (banda) | Alto | `CHALLENGE` single-use por nó; `syngraphe` consome; recontagem local; sem reembolso (§9) |
| AME-07 | SM fabrica mochthos para si | autenticidade da capacidade | Médio | mochthos **assinado pelo emitente** (dual-sig); revalidação pela política do destinatário (§9.2) |
| AME-08 | Capacidade falsa (banda inflada) | disponibilidade/DoS lento | Médio | recontagem local; limite por user/nó; registro no `prytaneion` (§9.3) |
| AME-09 | MITM de rede (sem pinning) | confidencialidade/autenticidade | Alto | TOFU/pinning obrigatório (§5, conventions) |
| AME-10 | Pyle entrega estado/auth antigo | sessão | Médio | `symbolon` por nó com TTL; OTP passo estritamente maior que o observado (§7) |
| AME-11 | Comprometimento de `krypte.hdap` (cofre local) | segredo (chaves) | Alto | ChaCha20-Poly1305 + Argon2id; senha forte; krypte nunca trafega (§6) |
| AME-12 | Engenharia social / phishing de seed | identidade completa | Alto | 3FA; fator OTP é só conhecimento; posse isolada não autentica (§7) |
| AME-13 | Confusão de `nickname` (imitação de `nickname_...`) | identidade/reputação | Médio | sufixo CSPRNG 64 bits; verificação por `sphragis`, não nome (§3.1) |
| AME-14 | Pyle mente sobre `prytaneion`/replicas | rastreabilidade | Médio | matriz assinada e com histórico; pheme reduz confiança do mentiroso (§10.2, §12) |
| AME-15 | DoS por upload flood | disponibilidade | Médio | rate limit 10/s burst 20; quota; upload ≤100 MB (§15) |
| AME-16 | Deploy com binário adulterado | todo o nó | Alto | `/pyle/integrity` responde hash; federação verifica versão (§14.1) |
| AME-17 | Propagação de `pheme` falsa (score indevido) | reputação injusta | Médio | `pheme_candidate` assinado + evidência; modo aberto exige `paratheke` (§12) |
| AME-18 | Nonce de federação reusado (replay inter-nó) | federação | Médio | nonce+timestamp ±30 s + replay TTL + nonce consumido (§14.2) |
| AME-19 | Injeção/parsing de `stele` malformada | todo | Médio | parser estrito §4.2 rejeita; property tests com mutador estruturado: 20 000 variantes, oráculo = *o que é aceito tem que voltar byte-a-byte* (`parse_never_panics_and_anything_accepted_roundtrips`), mais casos-alvo por defeito |
| AME-40 | **Request smuggling por CR isolado no head** — um `CR` fora de `CRLF` é terminador de linha para um proxy e dado comum para nós, logo os dois discordariam sobre onde terminam os headers (a dessincronização do CL, uma camada antes) | transporte | Alto | varredura pré-parse: todo `CR` precisa fazer parte de um `CRLF` (§14.2) |
| AME-41 | **Request target fora de origin-form** — `http://host/x`, `host:port` ou `health` significam coisas diferentes para um proxy, e o roteamento só entende `/` | transporte | Médio | alvo precisa começar com `/`; só origin-form é aceito (§14.2) |
| AME-39 | **Request smuggling por `Content-Length` ambíguo** — dois CL divergentes, ou CL não numérico, eram resolvidos em silêncio (`unwrap_or(0)`, *last-wins*) | transporte | Alto | CL repetido com valores divergentes → erro; lista separada por vírgula só aceita se todos os elementos coincidem; CL não numérico → erro em vez de zero implícito; e o mapa de headers é confrontado com o corpo consumido (§14.2) |
| AME-20 | Vazamento de metadata via URI | privacidade | Baixo/Médio | URI com hash só revela a quem já conhece; caminhos com adeia; TLS |
| AME-32 | **Tomada de posse de identidade** via `/prosopeion` (registrar/rotacionar em nome da vítima) | identidade | Alto | Registro exige **auto-assinatura** pela `SIGN_PUBKEY` declarada; rotação de seed exige também assinatura pela **chave anterior** (§3.1, §7) |
| AME-33 | **Upload forjado** (bytes atribuídos a outro autor) | integridade/autenticidade | Alto | Cliente assina os **bytes crus**; servidor exige `x-hdap-sphragis` e verifica contra a chave da **sessão autenticada** (não confia no corpo) (§10.3) |
| AME-34 | **Peer não autorizado entra na federação** (primeiro contato fixa a chave) | federação | Médio | Federação **aberta por design**: todo handshake é aceito e a chave apresentada é fixada em `State::peers`; um id já fixado não aceita outra chave (`409`). `Config.federation_peers` (`node_id → {pubkey, endpoint, tls_pin}`) é um reforço opcional de pin, não uma lista de admissão. O risco residual é o primeiro contato: um impostor que chegue antes pode ser fixado para aquele id. O conteúdo continua verificado por assinatura de autor + hash, então ele pode ser alcançado mas não pode forjar conteúdo |
| AME-36 | **Capacidade delegada forjada / ampliada** (delegado escalate escopo, escapa do caminho, reaproveitacapacidade expirada) | delegação/autorização | Alto | Cadeia de co-assinaturas (`len(SIGS) == DEPTH+1`) verificada contra o `prosopeion` do dono; troca de chave rejeitada; auto-delegação proibida; contenção `is_covered_by` (escopo ⊆ pai, caminho dentro do pai, `..`/absoluto rejeitado); `may_outlive` impede filho mais duradouro que o pai (pai que expira não delega em perpetuidade); **contenção revalidada na submissão** — o corpo assinado é re-conferido contra o pai armazenado, porque uma cadeia válida prova quem assinou, não o que podiam conceder; pai ausente → recusado; `EXPIRES_AT` + `NONCE`; `write` não implica `read` (§18) |
| AME-37 | **Transporte HTTP serving em claro / Slowloris / resposta sem limite** — `--no-tls` aceito em bind público; headers sem teto; sem deadlines de leitura | transporte/disponibilidade | Alto | `--no-tls` recusado fora de loopback (`0.0.0.0`/`::` não são loopback); TLS obrigatório fora de loopback; `MAX_HEAD_BYTES` independente de `max_body`; `CONN_TIMEOUT` em leitura/escrita antes do handshake e da resposta; cliente de federação nunca envia em claro a peer remoto (TLS pinado com pin, TLS-TOFU no id endereçado sem pin; cleartext só em loopback); `MAX_RESPONSE_BYTES` + parada por `Content-Length` (§14.2) |
| AME-35 | **Escrita perdida em silêncio** (persist best-effort) | persistência/integridade | Alto | `persist()` síncrono antes de responder; falha de flush → **HTTP 500**; carga inicial falha com exit code ≠ 0 (§14.1) |
| AME-42 | **Backup usurpa a casa / pyle fora da diádosi copia ou lê** | disponibilidade/identidade | Alto | Promoção só com `diadosi.hdap` assinado pelo dono, hashes/edição atuais, fallback listado, peer do home com endpoint e health do primário falhando; sem documento, não promove. `DIADOSI=white/black` filtra replicação e leitura pelo `server_id`, inclusive réplicas antigas; só docs públicos de identidade escapam da leitura (§8, §14.2.1) |

---

## 3. Ameaças de autenticação, economia e rede

| ID | Ameaça | Mitigação | Verificação |
|---|---|---|---|
| AME-21 | **Fator 3 inválido** (servidor não tinha o segredo para validar o HMAC) | `K` **derivado por DH**: o servidor computa `K = X25519(priv_enc(S), pub_enc(U))` na verificação; **nada armazenado**; sem envelope `auth_code` em disco (§7.2-F3) | Unitário: o servidor verifica F3 sem possuir `K` em memória; `K` não aparece no arquivo de estado |
| AME-22 | **Sessão global inválida** | Sessão **por nó**: `symbolon = HMAC(K,"hdap:session"‖server_id‖exp)`; outro nó não tem `K`. Decisão: identidade global, sessão por nó (§7.2) | Unitário: token rejeitado num segundo nó; teste inter-nó |
| AME-23 | **Replay de OTP entre nós** | O passo `r` consumido é **propagado** (`OTP_CONSUMED` na sincronização); desafio de uso único; a revelação liga `w_r` ao `proklesis.nonce` (§7.2) | Integração 2S+1U: `w_r` usado no S1 é rejeitado no S2 |
| AME-24 | **Permissões por hint replayável** | Autorização **só pela identidade da sessão**, nunca por hint; `shared=X25519` fica apenas para cifragem de conteúdo (§8) | Unitário: requisição com hint forjado = 403 |
| AME-25 | **Sybil em rede aberta** | Dois modos: fechado = maioria simples; aberto = voto **pesado por `paratheke`** (voz = stake) (§12) | Teste de política de voto: anônimo não pesa no modo aberto |
| AME-26 | **Deleção impossível contra nó teimoso** | Assumido: `lethe` é **incentivo e reputação**, não enforcement físico; ostrakon e oneidos; modo aberto: euthyne e paratheke (§10.4, §16) | Documentado (limitação declarada) |
| AME-27 | **Falta de incentivo econômico** | Módulo `katallaxia`: `timi` por byte-tempo, `obolos`, `tokos` (preferência temporal), `syngraphe` pago (§16) | Testes do módulo quando implementado |
| AME-28 | **Double-spend de PoW entre nós** | `CHALLENGE` de uso único; `syngraphe` consome; **recontagem local**; valor é promessa do emissor (§9.3) | Unitário: o mesmo mochthos em dois syngraphe → o segundo é recusado |
| AME-29 | **Metadados públicos (quem tem o quê)** | Aceito; publicidade é condição da verificabilidade; `ktema` cifrável no cliente; trilha não exposta; `?hash=` sem lookup por nome (§16, §10) | Documentado (limitação) |
| AME-30 | **Complexidade** | Núcleo mínimo explícito; `katallaxia`, `kerux`, `euthyne` e homospondoi são módulos opcionais, com fronteira via tipos de documento (§16-17) | Revisão de dependências de módulo |
| AME-31 | **Legal (GDPR, conteúdo ilegal)** | `lethe` e ostrakon para retirada; responsabilidade do nó que serve o quê, em jurisdição local; sem garantia global (§17) | Documentado (limitação) |

---

## 4. Mitigações transversais (não-negociáveis)

1. **Parser estrito e rejeição por padrão** (spec §4.2) — AME-19/04.
2. **Um único algoritmo por papel** (Ed25519/X25519/ChaCha20-Poly1305/Argon2id) — AME-09/11/05.
3. **Identidade global, sessão por nó** — AME-21/22/23.
4. **Recontagem local de banda** (§9.3) — AME-06/07/08.
5. **TOFU/pinning em qualquer cliente** — condição de review p/ plataforma nova (pinning de cert *TLS*; a federação também fixa a chave do par no primeiro contato — AME-34).
6. **Testes adversarial + vetores de canonicalização** — AME-19 e divergências cross-implementação.
7. **Autorização só por sessão autenticada** (§8) — AME-24.
8. **Nunca confiar em campo autodeclarado**: identidade por assinatura (AME-32), autor de upload por assinatura dos bytes (AME-33), membro de federação pela chave fixada no primeiro contato (AME-34), persistência confirmada antes da resposta (AME-35), raiz de cadeia de delegação pela chave do dono em disco (AME-36).
9. **Transporte não é detalhe**: TLS é obrigatório fora de loopback, e todo input de rede é limitado por tempo **e** por tamanho antes de ser interpretado (AME-37).

---

## 5. Limitações declaradas (não atacadas pelo HDAP)

- **Deleção não é enforcement físico**: `lethe` depende de incentivo/reputação (mode aberto) ou confiança nos pares (fechado) — AME-26/01.
- **Metadata público** (replicas, quem deu permissão pra quem) é inerente à verificabilidade — AME-29.
- **Responsabilidade legal / jurisdição**: HDAP não arbitra lei; `euthyne` é arbitragem privada voluntária — AME-31.
- **Sybil em rede aberta** depende de `paratheke` ter valor real; se o penhor for barato de obter, o voto volta a ser capturável — AME-25/27.
- Física de autoridade para pinning: MITM de primeira conexão possível (aceito; bootstrap offline do primeiro nó).

---

## 6. Enquadramento por ameaça e testes

| Teste | Cobre |
|---|---|
| Unit: desafio consumido 2× → 2ª falha | AME-04 |
| Unit: F3 verificado sem `K` em disco | AME-21 |
| Unit: token rejeitado em outro nó | AME-22 |
| Integração 2S+1U: `w_r` rejeitado após consumo propagado | AME-23 |
| Unit: hint forjado → 403 | AME-24 |
| Unit: mesmo mochthos em 2 syngraphe → 2ª recusado | AME-06, AME-28 |
| Unit: parser rejeita malformada (fuzz N) | AME-19 |
| Prop: 20 000 mutações — nunca entra em pânico; aceito ⇒ `render` é ponto fixo | AME-19 |
| Unit: CL `0`+`10`, `10`+`0`, `5`+`5,6` → erro de conflito | AME-39 |
| Unit: CL `5`+`5,5` → aceito, e header concorda com o corpo | AME-39 |
| Unit: CL `x`/`-1`/`1.5` com corpo vazio **e** não vazio → erro | AME-39 |
| E2E: réplica entre dois nós por TLS pinado (socket real) | AME-34/37 |
| E2E: pin divergente → falha de handshake, nenhum blob gravado | AME-37 |
| E2E: assinatura de federação com a chave errada → 401 | AME-34 |
| Prop: 20 000 mutações de requisição — CL concorda com o corpo, sem CR/LF em método, path ou header | AME-39/40 |
| Unit: CR isolado no valor, no nome do header e na request line → erro `bare CR` | AME-40 |
| Unit: `health`, `*`, `http://host/x`, `host:443` recusados; `/`, `/a%20b?x=%2F` aceitos | AME-41 |
| Integração 2S+1U: deleção retida → oneidos c/ evidência e réplica apaga | AME-03/17 |
| Integração: conteúdo adulterado rejeitado (hash!) | AME-01 |
| Prop: leading-zero & recontagem banda c/ adversarial pow | AME-06/07/08 |
| Unit modo aberto: voto sem paratheke não pesa | AME-25 |
| Unit: estranho registrando/rotacionando identidade de terceiro → recusado | AME-32 |
| Unit: upload sem `x-hdap-sphragis` (ou forjado) → 401 | AME-33 |
| Unit: handshake de peer não provisionado → 403, `peers` inalterado | AME-34 |
| Unit: `/sync` aceita só edição de configuração estritamente mais nova | AME-32/35 (autorização de escrita) |
| Unit: cadeia `exousia` válida (depth 0 e 1) verifica | AME-36 |
| Unit: corpo adulterado após assinatura → cadeia rejeitada | AME-36 |
| Unit: chave-raiz errada / delegado assinando o próprio elo → rejeitado | AME-36 |
| Unit: `DEPTH > 0` sem `PARENT_HASH` → rejeitado | AME-36 |
| Unit: filho re-assinado com `readwrite` sobre pai `read` → 403 (cadeia válida) | AME-36 |
| Unit: filho re-assinado com caminho fora do pai (`secrets`, `docsx`, `docs/../secrets`) → 403 | AME-36 |
| Unit: filho com `EXPIRES_AT` > pai → 403; pai ausente (404) | AME-36 |
| Unit: filho contido no pai → 200 (a contenção é fronteira, não recusa blanket) | AME-36 |
| Unit: `--no-tls` em `0.0.0.0`/`::`/IP público → recusado; loopback → aceito | AME-37 |
| Unit: `diadosi` white/black decide réplica e leitura; docs de identidade isentos | AME-42 |
| Unit: `diadosi.hdap` só promove fallback com assinatura/hashes atuais e home morto | AME-42 |
| Unit: headers > `MAX_HEAD_BYTES` rejeitados, mesmo corpo > `MAX_HEAD_BYTES` aceito | AME-37 |
| Unit: peer remoto sem pin nunca faz probe em claro (vai a TLS-TOFU); cleartext só em loopback | AME-37 |
| Unit: escalada de escopo e escape `docs/../secrets` → não contido | AME-36 |
| Unit: capability expirada (`EXPIRES_AT`) rejeitada; `0` nunca expira | AME-36 |

> Este modelo será atualizado à medida que a implementação encontre novos fatos.