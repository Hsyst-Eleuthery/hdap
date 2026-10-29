# Contribuindo com o HDAP

Obrigada pelo interesse. O HDAP é um protocolo pequeno, e mudanças pequenas e bem testadas são mais valiosas do que grandes reescritas.

## Antes de abrir uma mudança

- Leia o [Manual Técnico](docs/tecnico.md) e a [Especificação](docs/especificacao-hdap.md).
- Para mudanças de protocolo, abra uma issue descrevendo a semântica antes do código.
- Para falhas de segurança, siga [SECURITY.md](SECURITY.md) em vez de abrir uma issue pública.

## Ambiente

Requisitos:

- Rust 1.95+;
- `cargo fmt` e `cargo clippy` disponíveis.

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Estilo

- Código em Rust 2021, sem `unsafe` desnecessário.
- Sem comentários que repitam o código; comente decisões e armadilhas.
- Mensagens de erro devem dizer o que fazer, não apenas o que falhou.
- Nomes de protocolo seguem o [Léxico Grego](docs/lexico-grego.md).

## Testes

Toda mudança de comportamento precisa de um teste que falhe sem ela. Para correções de segurança, o teste deve reproduzir o ataque e provar a recusa.

Testes de federação e GUI podem subir nós reais em processo; siga o padrão existente em `crates/hdap-gui/src/app.rs` e `crates/hdap-server/src/node/`.

## Versionamento e releases

O HDAP usa dois codinomes por lançamento. O **codinome de protocolo** nomeia a geração da linguagem e muda apenas quando a comunicação ou a interpretação dos documentos muda; o **codinome de lançamento** muda em qualquer release. A versão 1.0 é o marco zero, com o protocolo **Themelio** e o lançamento **Veritas Aeterna**. A versão **v1.001** mantém o protocolo **Themelio** (matriz v1) e recebe o codinome de lançamento **Epoptia**.

Uma mudança que não altera o protocolo — correção de bug, melhoria de interface, correção de segurança, documentação ou empacotamento — gera a próxima versão de patch, como `v1.001`, com um novo codinome de lançamento e o mesmo codinome de protocolo. Uma mudança de protocolo abre uma versão maior, como `v2.0`, e exige que os dois codinomes mudem. Toda release atualiza o [CHANGELOG](CHANGELOG.md), a documentação e as datas de revisão, e o procedimento completo está no [Guia de Execução](docs/guia-de-execucao.md). Mudanças de protocolo precisam de uma issue de semântica antes do código.

## Commits

Use mensagens curtas e no imperativo, por exemplo:

```
corrige reaplicação da adeia no espelho
adiciona sugestão de fallbacks no painel de diádosi
```

Não inclua segredos, chaves, bancos `.db` ou diretórios de execução no commit.

## Licença

Ao contribuir, você concorda em licenciar sua contribuição sob a licença MIT.

## Contato

O HDAP é mantido por **Thaís (op3n/op3ny)**:

- E-mail: [thais@hsyst.org](mailto:thais@hsyst.org)
- GitHub: [@op3ny](https://github.com/op3ny)
- Discord: `@op3n`
- XMPP: `thais@xmpp.hsyst.org`
- Blog: [blog.thais.fyi](https://blog.thais.fyi)

Para falhas de segurança, prefira [SECURITY.md](SECURITY.md) a uma issue ou discussão pública.
