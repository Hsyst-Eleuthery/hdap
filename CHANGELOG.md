# Histórico

O HDAP usa dois codinomes por lançamento. O **codinome de protocolo** nomeia uma geração da linguagem do protocolo e muda apenas quando a forma de comunicação ou de interpretação dos documentos muda. O **codinome de lançamento** nomeia o pacote e muda em qualquer release. A versão 1.0 é o marco zero, com o protocolo **Themelio** e o lançamento **Veritas Aeterna**; a v1.001 manteve **Themelio** com o lançamento **Epoptia**. A v2.0 abre a geração **Téleia vási**, com o protocolo **Teleios**, também usado como codinome de lançamento. Correções dentro de uma geração saem como `v2.001`, `v2.002` e assim por diante, com novo codinome de lançamento e o mesmo codinome de protocolo. Mudanças de protocolo abrem a próxima versão maior e trocam os dois codinomes. Toda release atualiza a documentação.

## v2.0 — 2026-11-17

Geração **Téleia vási**. Codinome de protocolo: **Teleios**. Codinome de lançamento: **Teleios**. O formato textual dos documentos não mudou: `FORMAT_VERSION` permanece `1` e documentos v1 continuam válidos. O que mudou foi a linguagem de interoperabilidade, a derivação de chaves, o armazenamento de estado do nó e a experiência de operação.

### Tempo e provas

- Todo tempo de protocolo passou a ser **Unix UTC em segundos** (`u64`). Não há fuso, DST ou offset no fio, e o relógio local do cliente não decide validade: o cliente devolve exatamente o `ts` emitido pelo servidor (`client_ts_matches`, comparação exata).
- `GET /health` passou a anunciar `protocol_version`, `protocol_codename`, `version`, `time_utc`, `date_utc`, `uptime_secs`, `users`, `files` e `motd`. Toda resposta carrega `X-HDAP-Server-Time`.
- `Config.time_tolerance_secs` (padrão `300`) ajusta a tolerância de skew **apenas** nas assinaturas de federação; a retenção de nonces continua em `fed_window_secs` (padrão `30`).

### Criptografia e autenticação

- HKDF-SHA256 passou a derivar o material do ECIES (`hdap:ecies`), o segredo compartilhado de sessão (`hdap:session`) e a raiz da cadeia OTP (`hdap:otp`). Os intermediários são zeroizados.
- O terceiro fator foi vinculado ao desafio: `prove_session_secret_bound` assina `hdap:f3:v2:{user}:{server}:{challenge_text}`, com `challenge_text = hdap:challenge:{nonce}:{ts}`. A forma antiga (`hdap:code:...`) continua aceita para contas v1.
- A cadeia OTP tem teto absoluto `MAX_OTP_CHAIN_LEN = 4096` e é validada também pelo `otp_k` cadastrado, não por um valor enviado pelo cliente. Identidades v1 com âncora de seed bruta continuam podendo fazer login.
- A rotação **OMPHALOS** (`POST /omphalos`) agora exige sessão, `otp_anchor`, `seed_iter` estritamente crescente e `identity_signature` Ed25519 sobre `hdap:omphalos:v2:{user_id}:{old_anchor}:{new_anchor}:{new_k}`. Um token roubado sozinho não pode rotacionar a âncora. Resposta: `{rotated: true, seed_iter}`.

### Estado do nó e operação

- Chave mestra fora do banco via `--master-key-file` (64 hex = 32 bytes, arquivo `0600` em Unix); o DB passa a gravar a linha zerada e uma chave v1 existente é migrada automaticamente. Sem o flag, o nó avisa que mantém a chave no modo legado.
- Tokens de sessão são persistidos apenas como `v2:{sha256("hdap:session-store:" + token)}`; tokens em claro de bancos v1 são hashados no load.
- `--max-connections` (padrão `256`) limita conexões simultâneas com resposta `503` acima do limite; `--cleanup-interval` (padrão `60` s) remove desafios e sessões expirados, e `0` desativa o worker.
- `--motd` e `--motd-file` definem a **Ángelma**: texto renderizado com tags `HDAP{[tag]}` (ou `HDAP{tag}`) como `uptime`, `users`, `files`, `protocol`, `date_utc` e `tls`. A mensagem aparece em `/health`, `/motd`, no CLI e na GUI.
- Rate limiting passou a usar o IP do socket (`Request.peer`) em vez de um header que o cliente podia forjar. Locks envenenados são recuperados, e um nó degradado responde `503`.

### Autoria, armazenamento e handlers

- `origin_user` (autor da sessão) foi separado de `namespace_owner` (dono do diretório físico). `origin_user_pubkey` e `sphragis` acompanham o autor real; `PrytaneionEntry.namespace_owner` tem `#[serde(default)]` e foi propagado por ledger, sync, mirror, federação, matrix e db.
- A cota (`moira`) e `st.stored` agora contam o **delta real** de bytes: reenviar um arquivo idêntico não cobra banda nem infla o armazenamento.
- Handlers de rede em `identity`, `permissions`, `storage`, `bandwidth`, `federation`, `mirror` e `discovery` foram reescritos sem `unwrap`/`expect` relevantes.

### CLI e GUI

- O CLI não depende mais de `--pass` na linha de comando: `--pass-env`, `--pass-file` ou prompt TTY com `stty -echo`. `--pass` segue funcionando, mas avisa que expõe a senha na lista de processos.
- Novo comando `health` (sem identidade nem passphrase) mostra protocolo, versão, `time_utc`/`date_utc`, uptime, contadores e a Ángelma. Novo comando `rotate TOKEN` atualiza a âncora OTP, re-salva o cofre e zera o passo local.
- A GUI exibe a Ángelma e o UTC do nó, carimba a hora local em UTC e oferece o botão "🔑" para rotação OMPHALOS assinada, persistindo a nova identidade e reiniciando `omphalos.step`. Textos em PT/EN/ES/FR.

### Compatibilidade e qualidade

- Cofre local versionado: cabeçalho `HDAPVAULT\0\x02` com parâmetros Argon2 no cabeçalho (padrão 64 MiB/t=2/p=1); cofres v1 (19 MiB/t=2/p=1) continuam legíveis. Limites de sanidade impedem parâmetros absurdos em cofres v2.
- 250 testes automatizados; novos testes cobrem rotação assinada na CLI e na GUI, F3 vinculado, cofre v1/v2, chave externa, sessões hashadas e exibição da Ángelma.

### Documentação

- Novo [resumo da geração v2](docs/VERSAO.md); README, especificação, RFC, manual técnico, modelo de ameaça, léxico, guias e política de segurança atualizados para `2.0.0` / **Téleia vási · Teleios**.

## v1.001 — 2026-10-29

Release de correção de interface. Codinome de protocolo: **Themelio** (matriz v1). Codinome de lançamento: **Epoptia**. A matriz de documentos e rotas continua em v1; esta release corrige a avaliação e a edição das permissões (`adeia`).

### Permissões (`adeia`)

- `deny` deixou de ser ignorado. A avaliação agora aplica a precedência documentada: caminho mais específico vence (arquivo > pasta > raiz), `user:<id>` vence `all` no mesmo caminho, `deny` vence direitos positivos no mesmo nível e a ausência de regra nega.
- A gramática ganhou a forma completa `PERM <owner> <sujeito> <caminho> <direito>`, que permite negar um arquivo a uma pessoa sem fechar a casa inteira. As linhas compactas de v1.0 continuam aceitas e seguem sendo emitidas para regras de casa inteira.
- O editor de `adeia` na GUI foi refeito em três campos explícitos — **Quem**, **Onde** e **Pode** — com escolha entre Todos/Usuário, caminho de arquivo ou pasta e direitos localizados (Negar, Ler, Escrever, Dono). O formulário lê e reescreve tanto documentos antigos quanto novos.
- Regras de caminho agora respeitam limites de componente: `docs` cobre `docs/a.txt` mas não `docs2/a.txt`.
- Testes de servidor cobrem negação por arquivo, negação por pasta, exceção mais específica e isolamento entre usuários.

### Documentação

- Guia do usuário, manual técnico, especificação e RFC atualizados com a gramática, a precedência e os exemplos corretos de `PERM`.
- Cabeçalhos e notas de versão apontam para `v1.001` / **Epoptia**, mantendo o protocolo **Themelio**.

## 1.0.0 — 2026-10-21

Primeira release de produção do HDAP. Codinome de protocolo: **Themelio**. Codinome de lançamento: **Veritas Aeterna**.

### Protocolo e núcleo

- Identidade global com Ed25519/X25519, cofre `krypte.hdap` (Argon2id + ChaCha20-Poly1305) e login 3FA por nó.
- Documentos `.hdap` canônicos com assinatura sobre bytes crus e cadeia de edições por `PREV_HASH`.
- Permissões declarativas (`adeia`) com escopo, expiração e filtro de propagação `DIADOSI=white/black`.
- Banda por prova de trabalho (`mochthos`), tratado de cessão (`syngraphe`) e cota (`moira`).
- Transferência de posse assíncrona (`metabibasis`) com read-only irrevogável e liberação de cessão.
- Mudança de casa (`house_move`) e sucessão assinada (`diadosi.hdap`).
- DDNS interno (`kerux`) e busca por hash com livro global.

### Servidor

- API HTTP/1.1 sobre TLS auto-assinado persistido (`tls.identity`) e pinning TOFU.
- Persistência SQLite com WAL, `synchronous=FULL` e gravação antes da resposta.
- Federação aberta por design: todo pyle pode fazer o primeiro contato e tem a chave apresentada fixada em `State::peers`; `federation_peers` funciona como pin opcional e `--open-federation` é aceito apenas por compatibilidade.
- Replicação verificada, notificação de deleção e proteção contra delete de peer não-originário.
- Limites de parser, rate limit, quota por usuário e teto de upload.
- Recusa de TLS desligado fora de loopback.
- `--advertise` agora define o id padrão do nó: um bind em `0.0.0.0` deixa de gravar o wildcard no `pyle-<base64>` e passa a usar o endereço público.
- Lista dos pyles oficiais em `pyle1.hdap.hsyst.org:8443`, `pyle2.hdap.hsyst.org:8444`, `pyle3.hdap.hsyst.org:8445` e `pyle.thais.fyi:8443` documentada no README e no guia.

### GUI

- Explorador de arquivos com quatro idiomas (PT, EN, ES, FR).
- Editor de documentos com formulário e texto canônico.
- Painel de configuração para os seis documentos da casa.
- Painel de diádosi com carregamento do documento existente e sugestão de fallbacks da bolha.
- Menu de novo documento com `diadosi` encaminhando para o fluxo assinado.
- Barra de URI com resolução de alias DDNS e queda para caminho local.
- Busca por hash, painel de preços, aliases, transferências e mudança de casa.
- Identidade local persistida em diretório de dados do sistema (não em `/tmp`).
- Binário Windows de release sem console anexo (`windows_subsystem`).

### CLI

- Identidade local, registro, autenticação, banda, upload, download, listagem, deleção, aliases, resolução e preços.
- Fluxos de transferência (`request`, `inbox`, `accept`) e compatibilidade local (`transfer-own`).
- Suporte a TLS com pin.
- `whoami` e opções globais (`--host`, `--port`, `--tls-pin`, `--home`, `--pass`) aceitas antes ou depois do comando.
- `--version` no CLI e no servidor.
- Orçamento da prova de trabalho do comando `band` com folga suficiente para não falhar por azar estatístico.

### Qualidade

- 228 testes automatizados + 1 teste manual de integração.
- Modelo de ameaça com 41 entradas `AME-*`.
- Fuzzing dos parsers de documento e HTTP.
- CI com formatação, lint, build, testes e auditoria de dependências.

### Segurança de dependências

- `rustls` atualizado para 0.23.46 e `rustls-webpki` para 0.103.16.
- `cargo audit` sem vulnerabilidades conhecidas; os avisos restantes são de manutenção e estão documentados.

### Documentação e licença

- Guia do usuário em seis capítulos, guia de execução e página do predecessor HPS.
- Manual técnico, especificação, RFC, modelo de ameaça, léxico e filosofia econômica revisados para a versão 1.0.
- Contato da mantenedora no README, no guia de contribuição e na política de segurança.
- Licença MIT, sozinha no arquivo `LICENSE`; um bloco Apache-2.0 sem origem foi removido.

### Downloads

- Linux x86_64 (musl e gnu): `hdap-server`, `hdap-gui`, `hdap-cli`.
- Windows x86_64: `hdap-server.exe`, `hdap-gui.exe`, `hdap-cli.exe`.
