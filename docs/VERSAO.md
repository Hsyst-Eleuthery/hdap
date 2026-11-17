# HDAP v2 — Téleia vási · Teleios

**HDAP v2.0 — Téleia vási · Teleios**

> Revisão de 2026-11-17 · Geração de protocolo `2` · Formato de documento `VERSION: 1`
>
> Este documento é o **resumo da geração v2**. Para a semântica normativa, leia a [Especificação Formal](especificacao-hdap.md); para bytes e rotas, o [RFC-HDAP](rfc-hdap.md); para segurança, o [Modelo de Ameaça](modelo-de-ameaca.md).

---

## 1. O que mudou

A v1.0 foi o marco zero (**Themelio · Veritas Aeterna**) e a v1.001 uma correção de permissões (**Themelio · Epoptia**). A v2.0 abre a geração **Téleia vási**, cujo codinome de protocolo é **Teleios**.

A mudança é de **interoperabilidade e endurecimento**, não de escrita de documentos. O `FORMAT_VERSION` continua `1`: um `.hdap` escrito pela v1 é lido pela v2 sem conversão, e `# VERSION: 1` segue sendo a única forma aceita. O que mudou é como as provas são derivadas, como o tempo é interpretado, como o nó guarda segredos em repouso e como a pessoa interage com o sistema.

| Área | Themelio (v1) | Teleios (v2) |
|---|---|---|
| Tempo | relógios locais podiam influenciar decisões de clientes | todo instante é Unix UTC em segundos; o cliente devolve o `ts` do servidor |
| F3 | HMAC sobre `hdap:code:{user}:{server}:{ts}` | HMAC sobre `hdap:f3:v2:{user}:{server}:{challenge_text}`, ligado ao desafio |
| HKDF | DH usado diretamente como material de chave | ECIES, segredo de sessão e raiz OTP derivados com HKDF-SHA256 e rótulos próprios |
| OTP | cadeia a partir da seed bruta, sem teto no verificador | raiz via HKDF (`hdap:otp`), teto `MAX_OTP_CHAIN_LEN = 4096` e limite pelo `otp_k` cadastrado |
| Sessão em repouso | token em claro no estado do nó | `v2:{sha256("hdap:session-store:" + token)}`; tokens v1 são hashados no load |
| Chave mestra | dentro do banco | pode ficar fora, em `--master-key-file`; linha do DB zerada |
| Cofre local | `HDAPVAULT\0\x01`, Argon2 19 MiB | `HDAPVAULT\0\x02`, parâmetros no cabeçalho (padrão 64 MiB); v1 continua legível |
| Ángelma | — | MOTD renderizado com tags `HDAP{[tag]}`, em `/health`, `/motd`, CLI e GUI |
| Rotação OMPHALOS | sessão bastava | exige assinatura Ed25519 da identidade sobre texto canônico v2 |
| Operação | sem teto de conexões nem limpeza | `--max-connections`, `--cleanup-interval`, `--time-tolerance` |
| Autoria | autor e dono do namespace conflitos | `origin_user` (autor) separado de `namespace_owner` (diretório) |

---

## 2. Tempo: UTC do começo ao fim

Todo carimbo de tempo do protocolo é um `u64` com segundos desde `1970-01-01T00:00:00Z`. Não há fuso, horário de verão, offset ou string de data no fio. Isso vale para `CREATED_AT`, `EXPIRES_AT`, desafios, sessões, documentos, replicação e federação.

- `unix_secs_utc()` é a única fonte relógica do nó e do cliente.
- `is_expired(now, exp)` trata `0` como "nunca expira" e considera inválido `now >= exp`.
- **Autenticação**: o cliente deve devolver exatamente o `ts` emitido pelo servidor (`client_ts_matches`, igualdade exata). O relógio do cliente não recebe voto sobre a validade do desafio.
- **Federação**: como ambos os lados geram seus próprios timestamps, `Config.time_tolerance_secs` (padrão `300`) permite `|ts_local − ts_recebido| ≤ tolerância`. A janela de anti-replay de nonces é separada, em `fed_window_secs` (padrão `30`).
- **Observabilidade**: `GET /health` publica `time_utc` e `date_utc`, e todas as respostas HTTP carregam `X-HDAP-Server-Time: <segundos UTC>`.

Na prática, um cliente em qualquer fuso obtém o mesmo resultado para o mesmo `ts`: a formatação legível (`YYYY-MM-DD HH:MM:SS UTC`) é feita a partir do Unix UTC, nunca de `Local::now()`.

---

## 3. Derivação de chaves

`hkdf_sha256(ikm, salt, info)` é aplicada a todo segredo compartilhado antes de ele virar material de chave. Os rótulos são distintos para evitar que o mesmo DH sirva a dois papéis:

| Rótulo | Uso |
|---|---|
| `hdap:ecies` | chave ChaCha20-Poly1305 do envelope `eph_pub(32) ‖ nonce(12) ‖ ct+tag` |
| `hdap:session` | segredo compartilhado `K = X25519(priv_enc, pub_enc)` do login |
| `hdap:otp` | raiz da cadeia de hash do `omphalos` |

F1 (Ed25519), F2 (OTP) e F3 (HMAC de `K`) continuam sendo os três fatores. A diferença é que F3 agora cobre o **texto canônico do desafio**:

```
hdap:f3:v2:{user_id}:{server_id}:hdap:challenge:{nonce}:{ts}
```

Um atacante que capture uma prova F3 de uma sessão não pode reaplicá-la em outro desafio, mesmo com o mesmo `user_id` e `server_id`. A prova antiga (`hdap:code:...`) continua aceita **somente** para identidades criadas antes da Teleios: `UserRecord.v2_f3` nasce `false` nos registros migrados do banco v1 (via `#[serde(default)]`) e `true` em toda registro novo. A verificação passa por `factor3_ok()`, que compara a prova com o `ts` exato emitido pelo nó; a rotação OMPHALOS preserva o marcador, então um cliente v1 em migração não perde o acesso ao trocar a âncora.

A cadeia OTP é limitada em dois lugares: `MAX_OTP_CHAIN_LEN = 4096` como teto absoluto e o `otp_k` registrado para aquele usuário como limite real. O servidor **nunca** usa um `seed_iter` enviado pelo cliente para decidir quantos passos verificar.

---

## 4. Sessões e chave mestra

O token entregue ao cliente é `sha256_hex(HMAC(K, "hdap:session:{server_id}:{exp}"))`. Ele é determinístico para `(K, server_id, exp)` — dois logins no mesmo segundo podem gerar o mesmo valor; não é um nonce aleatório.

O que mudou é o **repouso**:

- A chave de armazenamento é `v2:{sha256_hex("hdap:session-store:" + token)}`. O token bruto continua viajando no header `x-hdap-token`, mas não é gravado.
- Em bancos v1, toda sessão em claro é convertida para essa forma no load; o flush seguinte já persiste apenas o hash.
- `is_session_storage_key` reconhece o prefixo `v2:` para distinguir registros migrados.

A chave mestra dos blobs pode sair do banco:

```bash
hdap-server --data /var/lib/hdap --master-key-file /var/lib/hdap/master.key
```

O arquivo contém 64 caracteres hex (32 bytes). Se não existir, o nó cria o diretório, grava com modo `0600` em Unix e migra a chave v1 do banco quando presente. Com a chave externa, a linha do banco é redacionada para `[0u8; 32]`; `Db::peek_master_key` ignora essa linha. **Faça backup da chave mestra junto com o banco**: perdê-la torna os blobs ilegíveis.

---

## 5. Cofre local e login de identidades antigas

O `krypte.hdap` v2 começa com `HDAPVAULT\0\x02` e carrega `m_cost`, `t_cost` e `p_cost` do Argon2id no cabeçalho. O padrão é 64 MiB / t=2 / p=1; o leitor impõe limites de sanidade (`m_cost` entre 19 MiB e 1 GiB, `t_cost` entre 1 e 16, `p_cost` entre 1 e 8) para recusar parâmetros absurdos em um cofre adulterado.

Cofres v1 (`HDAPVAULT\0\x01`, 19 MiB / t=2 / p=1) continuam sendo abertos e regravados no formato v2 na próxima atualização. Identidades v1 cuja âncora OTP foi derivada da seed bruta também continuam autenticando: `Identity::otp_chain_for` detecta a âncora e escolhe a derivação correspondente, sem exigir que a pessoa refaça sua identidade.

---

## 6. Ángelma

**Ángelma** é o nome da mensagem do nó (MOTD). Ela é configurada com `--motd "texto"` ou `--motd-file arquivo` e renderizada no momento da consulta, com tags entre chaves:

```
HDAP Ángelma · uptime HDAP{[uptime]} · HDAP{[users]} usuários · HDAP{[protocol]}
```

A forma canônica é `HDAP{[tag]}`; `HDAP{tag}` também é aceita. `HDAP{{` produz um `HDAP{` literal, e uma tag desconhecida é mantida no texto para expor o erro de digitação. As tags disponíveis incluem `uptime_secs`/`uptime`, `users`, `files`, `sessions`, `node`, `version`, `protocol`, `codename`, `started_utc`, `now_utc`, `date_utc`, `peers`, `tls` e `rate_limit`.

A mensagem pronta aparece em:

- `GET /health` → campo `motd`;
- `GET /motd` → `{ motd, time_utc, server_id }`;
- `hdap-cli health` → bloco `--- Ángelma ---`;
- GUI → badge "Ángelma" no rodapé, com o texto e o `UTC <time_utc>` no hover.

---

## 7. CLI e GUI

O CLI parou de depender de `--pass` na linha de comando. A ordem preferida é:

1. `--pass-env NOME_DA_VARIAVEL` (a variável deve existir; senão o comando sai com código 2);
2. `--pass-file caminho` (uma linha; apenas `\r`/`\n` finais são removidos);
3. prompt no terminal com `stty -echo`.

`--pass` ainda funciona, mas imprime um aviso: a senha aparece na lista de processos. Os comandos `health`, `resolve`, `prices`, `download`, `delete` e `list` não pedem passphrase.

```bash
hdap-cli --tls-pin "$PIN" health
hdap-cli --pass-env HDAP_PASS --tls-pin "$PIN" rotate "$TOKEN"
hdap-cli --pass-env HDAP_PASS --tls-pin "$PIN" auth
```

`rotate TOKEN` exige a chave de identidade além do token: envia `POST /omphalos` com `otp_anchor`, `seed_iter = otp_k + 1` e `identity_signature` sobre `hdap:omphalos:v2:{user}:{old_anchor}:{new_anchor}:{new_k}`. Depois de rodá-lo, o cofre local é regravado, `omphalos.step` volta a `1` e é preciso fazer `auth` de novo para obter um token da nova cadeia.

Tanto `hdap init` quanto a criação da identidade na GUI emitem um aviso guiado de backup: copie `krypte.hdap` para outro lugar físico e guarde a passphrase separadamente. Não existe recuperação central — perder o cofre ou a senha é perder a identidade.

A GUI mostra a Ángelma e o UTC do nó, usa `HH:MM:SS UTC` no rótulo de sincronização e oferece o botão "🔑" para a mesma rotação assinada. Todos os textos novos estão em PT/EN/ES/FR.

---

## 8. Robustez e operação

- `--max-connections N` (padrão `256`) limita conexões simultâneas; acima dele, o nó responde `503 {"error":"connection limit reached"}` sem abrir thread.
- `--cleanup-interval N` (padrão `60` s) remove `proklesis` e sessões expirados; `0` desativa o worker.
- `--max-challenges N` (padrão `4`) limita desafios de fator 1 em aberto por usuário, antes fixo em código.
- Rate limiting por requisição usa `Request.peer` — o IP do socket — em vez de um header que o cliente poderia escolher.
- Re-registrar com a mesma chave pública é idempotente; outra chave para o mesmo `user_id` recebe `409 identity key conflict`, sem revelar quais nomes já existem.
- O startup do nó é registrado com `hlog!` (nível + tag), e `run.sh` usa arquivos PID em vez de `pkill -f hdap-gui`.
- Locks envenenados são recuperados em vez de transformar uma panica em falha permanente; um nó em estado degradado responde `503`.
- Handlers de rede não usam `unwrap`/`expect` em caminhos alcançáveis por entrada remota.
- `--time-tolerance` altera apenas a checagem de skew das assinaturas de federação, nunca a validade de uma sessão ou desafio.

---

## 9. Autoria e contagem de armazenamento

`origin_user` identifica quem carregou o conteúdo e é imutável no `prytaneion`. `namespace_owner` identifica o dono do diretório lógico `HDAP$/<user>/` e é o valor do parâmetro `owner` nas rotas `/ktema`. Na v2, `origin_user_pubkey` e `sphragis` acompanham o autor real da sessão, e `PrytaneionEntry.namespace_owner` foi propagado por ledger, sync, mirror, federação, matrix e banco com `#[serde(default)]` para preservar registros antigos.

A cota `moira` e o contador `st.stored` passaram a medir o **delta real**: sobrescrever um arquivo com bytes idênticos não consome banda nem aumenta a ocupação. Isso evita cobrar duas vezes pelo mesmo conteúdo e mantém a contagem coerente com o que está em disco.

---

## 10. Como verificar a geração

```bash
hdap-server --version
hdap-cli --version
hdap-cli --tls-pin "$PIN" health
curl -k https://127.0.0.1:8443/health
```

No JSON de `/health`, `protocol_version` deve ser `2` e `protocol_codename` deve ser `Teleios`. `version` traz a versão do pacote (`2.0.0`), e `time_utc`/`date_utc` devem ser coerentes entre si, independentemente do fuso de quem consulta.

Para confirmar a compatibilidade com documentos antigos, registre uma identidade v1 e faça login: a cadeia OTP legada é reconhecida automaticamente. Para confirmar a rotação, use `rotate TOKEN` na CLI ou o botão "🔑" na GUI e tente autenticar com a âncora antiga — deve falhar.

---

## 11. Referências

- [CHANGELOG](../CHANGELOG.md) — histórico completo, incluindo v1.0 e v1.001.
- [Especificação Formal](especificacao-hdap.md) — semântica normativa.
- [RFC-HDAP](rfc-hdap.md) — formato de fio, rotas e headers.
- [Manual Técnico](tecnico.md) — arquitetura e decisões de engenharia.
- [Modelo de Ameaça](modelo-de-ameaca.md) — ameaças e mitigações da v2.
- [Guia de Execução](guia-de-execucao.md) — build, testes e release.

---

<p align="center">
<strong>HDAP — a prova vem antes da confiança.</strong><br>
Thaís (op3n/op3ny)
</p>
