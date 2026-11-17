# Segurança do HDAP

**HDAP v2.0 — Téleia vási · Teleios** · Revisão de 2026-11-17.

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

- autenticação 3FA e gerenciamento de sessão, incluindo o vínculo do F3 ao desafio emitido pelo servidor e o teto da cadeia OTP;
- rotação OMPHALOS (`POST /omphalos`) e a assinatura de identidade que a autoriza;
- chave mestra externa (`--master-key-file`), redaction do DB e hash das sessões em repouso;
- tempo Unix UTC, `X-HDAP-Server-Time` e a tolerância de relógio da federação;
- limites de conexão, rate limiting por IP do socket e limpeza de desafios/sessões expirados;
- cofre local `krypte.hdap`, incluindo o formato v2 e a leitura de cofres v1;
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

A linha 2.x recebe correções de segurança em releases `v2.001`, `v2.002` e assim por diante. O codinome de protocolo permanece **Teleios** nessas correções; apenas o codinome de lançamento muda. Mudanças na linguagem do protocolo abrem a próxima versão maior, com os dois codinomes novos. A linha 1.x (Themelio · Epoptia) encerrou sua manutenção com a v2.0: documentos e cofres v1 continuam legíveis, mas correções de segurança saem apenas na linha 2.x. Versões anteriores à 1.0 não são suportadas. Ao reportar, informe a versão exata impressa por `hdap-server --version`, `hdap-cli --version` ou no rodapé da GUI e, quando possível, os campos `protocol_version` e `protocol_codename` de `GET /health`.

## Divulgação responsável

Pedimos um prazo razoável para correção antes da divulgação. Em troca, daremos crédito público ao relator, se ele desejar.
