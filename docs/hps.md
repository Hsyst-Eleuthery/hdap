# HPS — o projeto predecessor

**HDAP v1.001 — Themelio · Epoptia**

**Escrito por Thaís (op3n/op3ny)**

---

O **HPS (Hsyst Peer-to-Peer Service)** é o projeto que veio antes do HDAP. Ele pertence à mesma família — a rede **Hsyst** — e continua sendo um sistema próprio, com escopo maior e objetivos diferentes. Esta página existe para deixar clara a relação entre os dois, sem confundir o que cada um faz.

O HPS está em [github.com/Hsyst-Eleuthery/hps](https://github.com/Hsyst-Eleuthery/hps).

---

## O que o HPS faz

O HPS é um ecossistema completo de publicação e economia descentralizada. Ele inclui:

- **contratos digitais** assinados que registram cada ação relevante;
- **vouchers** com histórico verificável (lineage) e prova de trabalho;
- **DNS descentralizado** com domínios `hps://`;
- **exchange** de valor entre servidores;
- **auditoria** e **reputação** distribuídas;
- vários aplicativos: browser de desktop, CLI, miner, mobile, carteira e proxy.

É um projeto grande, com servidor central de federação, muitos eventos e uma economia própria. Nada disso é um defeito: é o desenho que o HPS escolheu para os objetivos dele.

---

## O que o HDAP faz de diferente

O HDAP nasceu de uma pergunta mais estreita: **como guardar arquivos com autoria, posse e história, sem depender de um único servidor?** Em vez de reproduzir todo o ecossistema, ele concentra o esforço em um único objetivo e recusa tudo o que não serve a ele.

| Aspecto | HPS | HDAP |
|---|---|---|
| Objetivo central | Ecossistema completo de serviço P2P e economia | Arquivamento verificável de arquivos |
| Unidade de verdade | Contrato genérico para toda ação | Documento `.hdap` tipado e canônico |
| Economia | Vouchers, exchange, custódia, títulos | Banda por prova de trabalho; economia opcional |
| DNS | Domínios `hps://` | Aliases (`kerux`) sobre URIs `HDAP!` |
| Clientes | Browser, mobile, CLI, miner, proxy | GUI, CLI e servidor |
| Núcleo de protocolo | Reimplementado em vários clientes | Um único `hdap-core` compartilhado |
| Criptografia por papel | Múltiplos algoritmos e formatos | Um algoritmo por função, sem fallbacks |

O HDAP também evita deliberadamente algumas complexidades que o HPS carrega: não há consenso global, não há emissão de moeda própria no núcleo, e não há dependência de um servidor central de federação. A convergência acontece por documentos assinados e sincronização, não por votação.

---

## O que o HDAP aprendeu com o HPS

Três lições moldaram o HDAP diretamente:

1. **Um núcleo só.** Quando cada cliente reimplementa o protocolo, os clientes divergem e o servidor passa a discordar dos dois. O HDAP mantém uma única biblioteca de protocolo sem I/O, compartilhada por GUI, CLI e servidor.

2. **Formatos declarados, não mágicos.** Marcadores improvisados quebram clientes em silêncio. O HDAP define documentos canônicos com versão e tipo explícitos, e um único parser testado.

3. **Prova antes da confiança.** Assinatura sobre os bytes crus, hash verificável em cada cópia, permissões assinadas e proveniência registrada. Toda garantia tem um mecanismo correspondente e um teste que tenta quebrá-la.

---

## Os dois convivem

O HPS e o HDAP não competem. O HPS explora um ecossistema amplo de serviços e economia; o HDAP explora um problema específico com profundidade — arquivos que pertencem a alguém e continuam verificáveis quando o servidor muda de ideia.

Quem quer navegar, minerar e participar de uma economia de vouchers encontra isso no HPS. Quem quer possuir sua identidade e manter seus arquivos acessíveis e auditáveis encontra isso no HDAP.

---

**Leia também:** [userguide.md](userguide.md) · [tecnico.md](tecnico.md) · [filosofia-economica.md](filosofia-economica.md)
