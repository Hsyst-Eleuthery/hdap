# HDAP v2.0.0 — Téleia vási · Teleios

**Publicada em 2026-11-18.** Geração **Téleia vási**. Codinome de protocolo: **Teleios**. Codinome de lançamento: **Teleios**. Licença MIT.

> O formato textual dos documentos **não mudou**: `FORMAT_VERSION = 1`, expresso como `# VERSION: 1`. Um `.hdap` escrito pela v1 é lido pela v2 sem conversão. O que mudou foi a linguagem de interoperabilidade, a derivação de chaves, o estado persistido pelo nó e a experiência de operação.

---

## O que é o HDAP

O HDAP é um protocolo federado de arquivamento. Cada nó — chamado de **pyle** — guarda arquivos assinados, mantém um registro verificável de origem e replica conteúdo para outros nós sem pedir licença a uma autoridade central. Não há servidor mestre, banco central de identidades nem senha universal: há operadores independentes que trocam provas e convergem.

Esta é a primeira release da geração v2. Ela sucede a **v1.001 (Themelio · Epoptia)**.

---

## Destaques

### Tempo e provas

- Todo instante de protocolo é **Unix UTC em segundos** (`u64`): sem fuso, DST ou offset no fio. O cliente devolve exatamente o `ts` emitido pelo nó (`client_ts_matches`), então seu relógio local não decide validade.
- `GET /health` anuncia `protocol_version`, `protocol_codename`, `version`, `time_utc`, `date_utc`, `uptime_secs`, `users`, `files` e `motd`. Toda resposta carrega `X-HDAP-Server-Time`.
- A janela de anti-replay da federação é `fed_window_secs = 600` (o dobro da tolerância de 300 s), para que um nonce nunca seja esquecido antes de deixar de ser aceito pelo carimbo de tempo.

### Criptografia e identidade

- HKDF-SHA256 deriva o material ECIES (`hdap:ecies`), o segredo de sessão (`hdap:session`) e a raiz OTP (`hdap:otp`), com intermediários zeroizados.
- O terceiro fator passou a cobrir o desafio: `hdap:f3:v2:{user}:{server}:hdap:challenge:{nonce}:{ts}`. A prova antiga `hdap:code:...` continua válida **somente** para identidades criadas antes da v2 (`UserRecord.v2_f3 = false`).
- A cadeia OTP tem teto absoluto `MAX_OTP_CHAIN_LEN = 4096` e é limitada pelo `otp_k` cadastrado — nunca por um valor enviado pelo cliente.
- A rotação **OMPHALOS** exige assinatura Ed25519 sobre `hdap:omphalos:v2:{user_id}:{old_anchor}:{new_anchor}:{new_k}`. Um token roubado sozinho não rotaciona a âncora.
- Frase de recuperação BIP-39 de 24 palavras gera a identidade completa com rótulos HKDF-SHA512 independentes; a raiz OTP fica no cofre cifrado (`recovery_root`). `hdap-cli recover <FRASE> <NICK>` reconstrói a conta.

### Estado do nó e operação

- A chave mestra pode ficar fora do banco (`--master-key-file`, 64 hex, arquivo `0600`); a linha do DB é zerada e chaves v1 são migradas automaticamente.
- Tokens de sessão são gravados apenas como `v2:{sha256("hdap:session-store:" + token)}`.
- `--max-connections` (256), `--cleanup-interval` (60 s), `--max-challenges` (4) e `--time-tolerance` dão limites explícitos ao servidor.
- A **Ángelma** (`--motd` / `--motd-file`) renderiza tags `HDAP{[tag]}` como `uptime`, `users`, `files`, `protocol`, `date_utc` e `tls` em `/health`, `/motd`, CLI e GUI.
- Cofre local v2 com cabeçalho `HDAPVAULT\0\x02` e parâmetros Argon2 no cabeçalho (padrão 64 MiB); cofres v1 continuam legíveis.
- `origin_user` (quem assinou e enviou) foi separado de `namespace_owner` (dono do diretório). A cota conta o **delta real** de bytes: reenviar arquivo idêntico não cobra banda nem infla armazenamento.

### CLI e GUI

- O CLI não exige `--pass` na linha de comando: use `--pass-env`, `--pass-file` ou prompt TTY com `stty -echo`.
- Novos comandos `health` (sem identidade) e `rotate TOKEN` (rotação OMPHALOS assinada, com regravação do cofre).
- A GUI mostra a Ángelma e o UTC do nó, carimba a hora local em UTC e oferece o botão **🔑** para rotação assinada. Textos em PT/EN/ES/FR.

### Segurança e auditoria

Três rodadas de auditoria fecharam as pendências da geração:

- **TOFU TLS entre instâncias:** o pin aprendido no primeiro contato vive num registro compartilhado por todas as instâncias de `FedHttpClient`, chaveado por `host:port`. Um cliente novo herda o pin e volta a rejeitar certificados diferentes. O nó incorpora os pins aprendidos ao `PeerRecord` no `persist()` e os semeia de volta no boot.
- **Corrida de primeiro contato:** após o handshake e **antes** de enviar o HTTP, o fingerprint observado é comparado com o pin sob o mutex. Se divergirem, a conexão é rejeitada (`InvalidData`) sem enviar nenhum byte da requisição.
- **Nonces concorrentes:** `PersistSignal` substituiu a flag booleana por contadores de geração, de modo que uma mutação concorrente durante um flush não tenha seu sinal apagado — inclusive em respostas 401/403.
- **Sidecars de blob:** gravação temporária + `fsync` + rename atômico, com validação de tamanho e SHA-256 na leitura e fallback para o BLOB do SQLite.
- **Pins oficiais assinados:** o manifesto `docs/pins-oficiais-manifesto.txt` e sua assinatura `.asc` permitem verificar os `tls_pin` dos nós públicos fora da banda. Chave OpenPGP `3D97 B7C2 7095 4A1C 590C 4233 B8E0 166A AB5F 47D8` (`Thaís <thais@github>`).
- **security.txt:** apenas a localização canônica `.well-known/security.txt` (RFC 9116).
- **Auditoria de dependências:** `rusqlite` atualizado para `0.41.1` e `libsqlite3-sys` para `0.39.1`, removendo o CVE do SQLite embutido. `cargo audit` termina sem vulnerabilidades (restam avisos informativos de crates `unmaintained`/`yanked`).
- **Qualidade:** 270 testes automatizados, 0 falhas, 1 ignorado; `cargo fmt --check`, `cargo clippy -D warnings`, build em Linux/Windows/macOS, cinco alvos de fuzz e checagem de MSRV 1.95 no CI.

---

## Compatibilidade

| Item | Situação |
|---|---|
| `# VERSION: 1` | Inalterado — documentos v1 continuam válidos |
| Contas v1 | Continuam fazendo login, inclusive com a prova F3 antiga |
| Cofres v1 | Legíveis; migrados para o formato v2 na próxima gravação |
| Tokens v1 em claro | Hashados no carregamento do banco |
| `ADEIA` v1 | Linhas compactas continuam aceitas e emitidas para regras de casa inteira |

Não há migrador de documentos: o formato permanece o mesmo.

---

## Downloads

| Pacote | Plataforma |
|---|---|
| `hdap-2.0.0-x86_64-unknown-linux-gnu.tar.gz` | Linux x86_64 com glibc (Debian, Ubuntu, Fedora…) |
| `hdap-2.0.0-x86_64-unknown-linux-musl.tar.gz` | Linux x86_64 estático (Alpine, containers, sem glibc) |
| `hdap-2.0.0-x86_64-pc-windows-gnu.zip` | Windows x86_64 |

Cada pacote traz `hdap-server`, `hdap-gui` e `hdap-cli` (com `.exe` no Windows), além de `README.md`, `LICENSE` e `SHA256SUMS`.

---

## Verificação

Os hashes SHA-256 de cada pacote estão nos arquivos `.sha256` anexos a esta release e dentro de cada pacote, em `SHA256SUMS`. Confira antes de executar qualquer binário:

```bash
sha256sum -c hdap-2.0.0-x86_64-unknown-linux-musl.tar.gz.sha256
tar -xzf hdap-2.0.0-x86_64-unknown-linux-musl.tar.gz
cd hdap-2.0.0-x86_64-unknown-linux-musl && sha256sum -c SHA256SUMS
```

No Windows (PowerShell):

```powershell
Get-FileHash .\hdap-2.0.0-x86_64-pc-windows-gnu.zip -Algorithm SHA256
```

A impressão digital OpenPGP para verificação dos pins oficiais é:

```
3D97 B7C2 7095 4A1C 590C  4233 B8E0 166A AB5F 47D8  — Thaís <thais@github>
```

O procedimento completo está em [docs/pins-oficiais.md](pins-oficiais.md).

---

## Começar rápido

Suba um nó local:

```bash
./hdap-server --listen 127.0.0.1:8443 --data ./node
```

O `tls_pin` é impresso no boot. Em outro terminal, aponte o cliente:

```bash
./hdap-cli --host 127.0.0.1 --port 8443 --tls-pin PIN init thais
./hdap-cli --host 127.0.0.1 --port 8443 --tls-pin PIN register
./hdap-cli --host 127.0.0.1 --port 8443 --tls-pin PIN whoami
```

Para compilar do código-fonte com Rust 1.95+:

```bash
cargo build --release --workspace
cargo test --workspace
```

---

## Limites honestos

- Não existe recuperação central de senha: perder o cofre ou a senha significa perder a identidade. O backup é a defesa.
- A criptografia em repouso protege o disco, não o operador.
- A federação aberta ainda é experimental; em produção, use allowlist e verifique os pins fora da banda.
- O HDAP é federado, **não** é uma blockchain. Os detalhes estão no [Modelo de Ameaça](modelo-de-ameaca.md).

---

## Links

- [Visão da geração v2](VERSAO.md) · [Guia do Usuário](guia-1-introducao.md) · [Guia de Execução](guia-de-execucao.md)
- [Especificação Formal](especificacao-hdap.md) · [RFC-HDAP](rfc-hdap.md) · [Manual Técnico](tecnico.md)
- [Modelo de Ameaça](modelo-de-ameaca.md) · [Pins oficiais](pins-oficiais.md) · [Política de segurança](../SECURITY.md)
- [Changelog completo](../CHANGELOG.md) · [Repositório](https://github.com/Hsyst-Eleuthery/hdap) · [Releases](https://github.com/Hsyst-Eleuthery/hdap/releases)

---

Mantido por Thaís (op3n/op3ny) · thais@hsyst.org · https://github.com/op3ny
