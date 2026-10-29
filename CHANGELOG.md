# Histórico

O HDAP usa dois codinomes por lançamento. O **codinome de protocolo** nomeia uma geração da linguagem do protocolo e muda apenas quando a forma de comunicação ou de interpretação dos documentos muda. O **codinome de lançamento** nomeia o pacote e muda em qualquer release. A versão 1.0 é o marco zero, com o protocolo **Themelio** e o lançamento **Veritas Aeterna**. Correções que não alteram o protocolo saem como `v1.001`, `v1.002` e assim por diante, com um novo codinome de lançamento e o mesmo codinome de protocolo. Mudanças de protocolo abrem uma versão maior, como `v2.0`, e os dois codinomes mudam. Toda release atualiza a documentação.

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
