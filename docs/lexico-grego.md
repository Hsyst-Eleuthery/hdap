# HDAP — Λεξικόν (Léxico Grego Canônico)

**HDAP v1.0 — Themelio · Veritas Aeterna**

> Revisão de 2026-10-22 · Protocolo: **1.0**. O projeto se chama HDAP, mas todos os conceitos de protocolo, as superfícies de rede (tipos de documento, rotas REST, nomes de arquivo, chaves de configuração) e os identificadores de implementação carregam **nomes gregos transliterados**. Os glifos gregos são a forma canônica exibida na tabela; o código usa a transliteração ASCII em minúsculas, com `snake_case` para funções e variáveis e `CamelCase` para tipos.
>
> A regra do léxico é evitar nomes óbvios e clichês, como *agora*, *arete*, *ethos*, *logos*, *xenia*, *polis*, *nemesis* ou *phoenix*. Cada termo foi escolhido pela etimologia e serve à tese econômica do projeto: preço como sinal, reputação como capital e ordem espontânea.

---

## 1. Tabela canônica

| Conceito | Grego | Transliteração | Etimologia / por quê |
|---|---|---|---|
| Protocolo | **HDAP** | `hdap` | nome do projeto, mantido |
| Nó / gateway / servidor | Πύλη | `pyle` | a "porta" (Thermopyle = portões quentes): o ponto de passagem do tráfego |
| Federação de nós | Ὁμόσπονδοι | `homospondoi` | "os que partilham a libação do pacto" — nós ligados por um pacto comum |
| Documento `.hdap` | Στήλη | `stele` | estela inscrita, pública, auto-verificável |
| Assinatura | Σφραγίς | `sphragis` | selo/sinete pessoal |
| Cadeia de edições | Εἱρμός | `heirmos` | a corrente que liga elo a elo (história imutável) |
| Identidade (`properties`) | Προσωπεῖον | `prosopeion` | a máscara do ator (origem de *persona*) |
| Diretório do usuário | Ἑστία | `hestia` | a lareira doméstica — a casa do usuário |
| Cofre local | Κρύπτη | `krypte` | a cripta/vault |
| Âncora OTP | Ὀμφαλός | `omphalos` | o umbigo do mundo (pedra de Delfos): âncora verificada por todos |
| PoW | Μόχθος | `mochthos` | o *toil* heroico — esforço realmente pago |
| Banda/capacidade | Χορηγία | `choregia` | a liturgia de financiar o coro — capacidade *concedida* ao cliente |
| Cota individual | Μοῖρα | `moira` | a porção que lhe coube |
| Tratado de cessão | Συγγραφή | `syngraphe` | contrato escrito ateniense (finanças e lei) |
| Permissões (ACL) | Ἄδεια | `adeia` | licença/concessão |
| Transferência de posse | Μεταβίβασις | `metabibasis` | a entrega formal |
| Matriz de origem | Πρυτανεῖον | `prytaneion` | o salão cívico que guardava os registros públicos |
| Réplica | Ἀπόγραφον | `apographon` | a cópia; a colônia do conteúdo noutro nó |
| Reputação/TCD | Φήμη | `pheme` | fama que corre de boca em boca — *word-of-mouth* como capital |
| Penalidade de reputação | Ὄνειδος | `oneidos` | a reprovação pública |
| Deleção | Λήθη | `lethe` | o rio do esquecimento — apagar é *esquecer* |
| Tombstone | Ὄστρακον | `ostrakon` | o caco do ostracismo — condenar conteúdo ao exílio |
| Sessão / token | Σύμβολον | `symbolon` | o "símbolo" original: o token partido de hospitalidade — reconhecimento mútuo sem se falarem |
| Desafio de auth | Πρόκλησις | `proklesis` | a intimação/desafio legal formal |
| PoW de entrada | Πυλαία | `pylaia` | o pedágio guardado pela Pyle |
| DDNS / alias | Κῆρυξ | `kerux` | o arauto que anuncia endereços |
| Economia | Καταλλαξία | `katallaxia` | do grego κατάλλάττω = "admitir no intercâmbio"; a catallaxy de Hayek |
| Unidade de valor | Ὀβολός | `obolos` | o óbolo (a moeda miúda, o pagamento do barqueiro) |
| Preço (e honra) | Τιμή | `timi` | τιμή significa *preço* e *honra*: reputação é capital |
| Juros/preferência temporal | Τόκος | `tokos` | juros = "descendência" do dinheiro (Aristóteles) |
| Penhor / stake | Παραθήκη | `paratheke` | depósito confiado em mãos alheias (garantia de boa conduta) |
| Arbitragem/prestação de contas | Εὐθύνη | `euthyne` | o exame de contas dos magistrados atenienses |
| Cânone de verificação (medida exata) | Πῆχυς | `pechys` | o côvado-padrão: a medida canônica do formato |
| Janela de tempo | Καιρός | `kairos` | o instante oportuno |
| Conteúdo / arquivo | Κτῆμα | `ktema` | a posse adquirida (o que se guarda) |
| Link simbólico (cessão) | Σύνδεσμος | `link` | o elo que aponta; documento que nomeia outro lugar em vez de carregar bytes |
| Capacidade delegada | Ἐξουσία | `exousia` | a autoridade delegada; poder outorgado por assinatura em cadeia |
| Sucessão / procuração de casa | Διάδοσις | `diadosi` | a transmissão/sucessão: fixa a casa e quem pode sucedê-la; também limita a propagação da cópia |
| Dicionário de confiança | — | `pistis` | (reservado: TCD/PHEME avançado) |

---

## 2. Convenções de escrita

1. **Glifos gregos** → usados em documentação, comentários de seção e nas referências deste léxico.
2. **Wire (rede)** → transliteração ASCII em minúsculas, sempre: rota `/pheme`, tipo de documento `pheme`, sufixo `.hdap.pheme`, campo `TARGET_ID`.
3. **Código Rust** → transliteração ASCII: `pyle.rs`, `struct Symbolon`, `fn proklesis(...)`; exceções técnicas para termos que colidem com std (ex.: preço `timi`, nunca `time`).
4. **Namespace raiz `HDAP$`** permanece com o nome do projeto; `HDAP!` permanece no esquema URI.
5. **Ostentações:** o rótulo humano dos casos (ex.: o que era "TCD") passa a ser **Pheme**; a especificação nunca mais usa o nome antigo sem remissão `→ nome antigo`.

---

## 3. Mapa nome antigo → grego (migração)

| Antigo (inglês) | Grego |
|---|---|
| node | `pyle` |
| federation | `homospondoi` |
| document / `.hdap` | `stele` |
| signature | `sphragis` |
| properties.hdap | `prosopeion.hdap` |
| permissions.hdap | `adeia.hdap` |
| auth_code.hdap | `symbolon.hdap` |
| vault.hdap | `krypte.hdap` |
| pow → `N.hdap.pow` | `mochthos/N.hdap.mochthos` |
| treaty | `syngraphe` |
| transfer_own | `metabibasis` |
| matrix.hdap | `prytaneion.hdap` |
| tcd.hdap / tcd_candidate | `pheme.hdap` / `pheme_candidate` |
| dns.hdap | `kerux.hdap` |
| OTP anchor | `omphalos` |
| session / token | `symbolon` / `symbolon-token` |
| challenge | `proklesis` |
| content / file | `ktema` |
| symbolic link / transfer | `link` / `metabibasis` |
| capability / delegation | `exousia` |
| deletion / tombstone | `lethe` / `ostrakon` |
| reputation / TCD score | `pheme` / `oneidos` (penalidade) |
| band / capacity / quota | `choregia` / `moira` |
| storage market / economics | `katallaxia` |
| money unit | `obolos` |
| price | `timi` |
| interest / time-preference | `tokos` |
| stake / escrow | `paratheke` |
| arbitration / accountability | `euthyne` |
| canonical measure | `pechys` |
| time window | `kairos` |