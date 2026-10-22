# Segurança do HDAP

**HDAP v1.0 — Themelio · Veritas Aeterna** · Revisão de 2026-10-22.

## Como reportar

Se você encontrou uma vulnerabilidade, **não abra uma issue pública**. Envie um relato privado para a mantenedora, Thaís (op3n/op3ny):

- E-mail: [thais@hsyst.org](mailto:thais@hsyst.org)
- GitHub: [@op3ny](https://github.com/op3ny) (mensagem privada)
- Discord: `@op3n`

Para relatos sensíveis, cifre a mensagem com a chave OpenPGP pública da mantenedora. A chave pode ser obtida no servidor `https://keys.thais.fyi` (`thais@hsyst.org`, chave também em `thais@xmpp`, `thais@discord`) e a assinatura pode ser conferida em `https://thais.fyi`.

Inclua, quando possível:

- versão afetada (`hdap-server`, `hdap-cli` ou `hdap-gui`);
- sistema operacional e arquitetura;
- passos para reproduzir;
- impacto observado;
- prova de conceito, se existir.

Você receberá uma confirmação de recebimento. O objetivo é responder em até 7 dias e corrigir antes de qualquer divulgação pública.

## Escopo

Fazem parte do escopo:

- autenticação 3FA e gerenciamento de sessão;
- cofre local `krypte.hdap`;
- formato e canonicalização de documentos `.hdap`;
- permissões (`adeia`) e transferência de posse;
- federação, handshake e replicação;
- parser HTTP e TLS;
- sucessão de casa (`house_move`, `diadosi`);
- GUI e CLI quando o problema afeta segurança.

## Fora de escopo conhecido

- recuperação de identidade sem backup do cofre;
- confidencialidade contra o operador do pyle;
- anonimato de rede;
- disponibilidade física de um nó comprometido;
- engenharia social contra o usuário;
- ataques que dependem de acesso root ao host.

Esses limites estão descritos no [Modelo de Ameaça](docs/modelo-de-ameaca.md).

## Versões suportadas

A linha 1.0 recebe correções de segurança em releases `v1.001`, `v1.002` e assim por diante. O codinome de protocolo permanece **Themelio** nessas correções; apenas o codinome de lançamento muda. Mudanças de protocolo abrem uma versão maior, como `v2.0`, com os dois codinomes novos. Versões anteriores à 1.0 não são suportadas e devem ser atualizadas. Ao reportar, informe a versão exata impressa por `hdap-server --version`, `hdap-cli --version` ou no rodapé da GUI.

## Divulgação responsável

Pedimos um prazo razoável para correção antes da divulgação. Em troca, daremos crédito público ao relator, se ele desejar.
