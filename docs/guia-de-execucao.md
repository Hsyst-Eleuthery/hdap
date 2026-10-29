# Guia de Execução — Compilar, Testar e Empacotar o HDAP

**HDAP v1.001 — Themelio · Epoptia**

**Escrito por Thaís (op3n/op3ny)**

---

Este guia é para quem vai **construir** o HDAP a partir do código: compilar, rodar os testes, gerar binários e empacotar uma release. Para aprender a **usar** os programas, veja o [guia do usuário](userguide.md).

---

## Sumário

- [Requisitos](#requisitos)
- [Compilar do código](#compilar-do-código)
- [Rodar os testes](#rodar-os-testes)
- [Rodar um laboratório local](#rodar-um-laboratório-local)
- [Estrutura do repositório](#estrutura-do-repositório)
- [Compilação cruzada](#compilação-cruzada)
- [Empacotar uma release](#empacotar-uma-release)
- [Integração contínua](#integração-contínua)
- [Checklist de lançamento](#checklist-de-lançamento)

---

## Requisitos

- **Rust 1.95 ou mais recente** e `cargo` (via [rustup](https://rustup.rs)).
- Um ambiente de build C (o crate `rusqlite` compila SQLite via `cc`).
- Para a GUI, as bibliotecas gráficas do sistema (X11/Wayland no Linux).

Confira a versão:

```bash
rustc --version
cargo --version
```

O `Cargo.toml` da raiz declara `rust-version = "1.95"`. Ferramentas mais antigas recusam o build de propósito.

---

## Compilar do código

```bash
git clone https://github.com/Hsyst-Eleuthery/hdap.git
cd hdap
cargo build --release --workspace
```

Os binários ficam em `target/release/`:

- `target/release/hdap-server`
- `target/release/hdap-gui`
- `target/release/hdap-cli`

Para um build de desenvolvimento (mais rápido, com símbolos):

```bash
cargo build --workspace
```

### Compilar só um componente

```bash
cargo build --release -p hdap-server
cargo build --release -p hdap-cli
cargo build --release -p hdap-gui
```

---

## Rodar os testes

A suíte cobre núcleo, servidor, CLI, TLS e GUI:

```bash
cargo test --workspace
```

Comandos de qualidade que o CI exige:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

Há um teste de integração marcado como `#[ignore]`, porque exige um nó real no ar:

```bash
cargo test -p hdap-gui -- --ignored manual_connect_wizard_defaults_live_server
```

O *fuzzing* dos parsers de documento e de HTTP fica em `fuzz/` e usa `cargo-fuzz`:

```bash
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run parse_hdap_doc -- -runs=10000
cargo +nightly fuzz run parse_http_request -- -runs=10000
```

---

## Rodar um laboratório local

Para ver a federação funcionando, suba três pyles e três GUIs com cofres separados:

```bash
cargo build --release --workspace

./target/release/hdap-server --listen 127.0.0.1:8443 --data ./.dev/nodeA &
./target/release/hdap-server --listen 127.0.0.1:8444 --data ./.dev/nodeB &
./target/release/hdap-server --listen 127.0.0.1:8445 --data ./.dev/nodeC &

HDAP_HOME=./.dev/guiA ./target/release/hdap-gui &
HDAP_HOME=./.dev/guiB ./target/release/hdap-gui &
HDAP_HOME=./.dev/guiC ./target/release/hdap-gui &
```

Cada GUI usa um cofre diferente. Registre uma identidade em cada nó e experimente replicação, permissões e mudança de casa.

> A federação é sempre aberta: cada nó aceita o primeiro contato de outro pyle e fixa a chave apresentada. `--open-federation` continua aceito apenas por compatibilidade e não muda nada.

Para derrubar os processos no fim do teste, referencie-os pelo PID ou pelo nome exato do binário — nunca por um padrão largo que possa atingir outros processos.

---

## Estrutura do repositório

```
hdap/
├── Cargo.toml            # workspace
├── crates/
│   ├── hdap-core/        # documentos, cripto, identidade, PoW, protocolo (sem I/O)
│   ├── hdap-tls/         # certificado auto-assinado por nó e cliente com pin
│   ├── hdap-server/      # o pyle: API HTTP/TLS, SQLite, federação
│   ├── hdap-cli/         # cliente de linha de comando e biblioteca de fluxo
│   └── hdap-gui/         # aplicativo desktop (egui)
├── docs/                 # documentação
├── fuzz/                 # alvos de fuzzing
├── scripts/              # execução local e empacotamento
└── .github/workflows/    # integração contínua
```

O núcleo (`hdap-core`) não faz I/O. Servidor, CLI e GUI importam o mesmo núcleo, de modo que uma regra de documento ou de permissão nunca é reimplementada de forma divergente.

---

## Compilação cruzada

A compilação cruzada é feita com [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) e um Zig local, sem root e sem toolchains do sistema:

```bash
cargo install cargo-zigbuild
# extraia o Zig em ~/.local/zig (veja ziglang.org)
rustup target add x86_64-unknown-linux-musl
rustup target add x86_64-pc-windows-gnu
```

Compile para um alvo:

```bash
cargo zigbuild --release --target x86_64-unknown-linux-musl --workspace --bins
cargo zigbuild --release --target x86_64-pc-windows-gnu --workspace --bins
```

Os artefatos ficam em `target/<triple>/release/`.

---

## Empacotar uma release

O script `scripts/cross-release.sh` compila, organiza os arquivos e gera o pacote com checksum:

```bash
./scripts/cross-release.sh x86_64-unknown-linux-gnu
./scripts/cross-release.sh x86_64-unknown-linux-musl
./scripts/cross-release.sh x86_64-pc-windows-gnu
```

Cada execução produz, em `target/release-assets/`:

- uma pasta `<triple>/` com `hdap-server`, `hdap-gui`, `hdap-cli` (ou `.exe`), `LICENSE`, `README.md` e `SHA256SUMS`;
- um arquivo `hdap-<versao>-<triple>.tar.gz` (Linux) ou `.zip` (Windows);
- um `.sha256` do pacote.

O alvo `x86_64-unknown-linux-gnu` usa o compilador nativo; os demais usam Zig. A versão é lida do `Cargo.toml`, salvo se você definir `HDAP_VERSION`.

### Verificar os pacotes

```bash
cd target/release-assets
sha256sum -c hdap-1.0.1-x86_64-unknown-linux-musl.tar.gz.sha256
```

---

## Integração contínua

O workflow `.github/workflows/ci.yml` roda, a cada push ou pull request:

| Job | O que faz |
|---|---|
| Check + Test | `fmt`, `clippy -D warnings`, build e testes na toolchain estável. |
| Fuzzing | Alvos de fuzzing na nightly (sempre em push; em PR, com a label `fuzz`). |
| Security Audit | `cargo audit` sobre o `Cargo.lock`. |
| MSRV | Build com Rust 1.95 para garantir o piso declarado. |

Antes de abrir um pull request, rode localmente os mesmos comandos da seção [Rodar os testes](#rodar-os-testes).

---

## Checklist de lançamento

Toda release do HDAP segue a política de **dois codinomes** descrita no [guia do usuário](userguide.md#codenomes-e-versionamento) e no [CHANGELOG](../CHANGELOG.md). O procedimento:

1. **Defina a versão.** Correções de interface, bugs e vulnerabilidades sobem um passo de patch (`v1.001`, `v1.002`, …) e mudam **apenas o codinome de lançamento**. Mudanças no protocolo abrem uma versão nova (`v2.0`) e mudam **os dois codinomes**.
2. **Atualize a versão** em `Cargo.toml` (workspace) e deixe o `Cargo.lock` acompanhar.
3. **Atualize a documentação**: `README.md`, `CHANGELOG.md`, os documentos afetados em `docs/` e as datas de revisão.
4. **Rode a verificação completa**: `fmt`, `clippy`, `cargo test --workspace` e `cargo audit`.
5. **Gere os pacotes**: `scripts/cross-release.sh` para cada alvo suportado.
6. **Confira os checksums** e anexe os arquivos à GitHub Release, nomeando-a com a versão e os dois codinomes.

Um lançamento sem changelog, sem codinomes ou sem documentação atualizada não está completo.

---

<p align="center">
<strong>HDAP — construa, verifique, publique.</strong><br>
Thaís (op3n/op3ny)
</p>
