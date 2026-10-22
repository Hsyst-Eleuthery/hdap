# HDAP — Καταλλαξία (Filosofia Econômica Austríaca)

**HDAP v1.0 — Themelio · Veritas Aeterna**

> Revisão de 2026-10-22 · Protocolo: **1.0**. Este é o documento de design econômico do HDAP. Ele explica por que guardar e servir conteúdo custa um recurso escasso, como esse recurso é gerado e precificado e o que muda quando o objetivo é uma **rede pública global**. A inspiração declarada é a **escola austríaca** (Mises, Hayek, Böhm-Bawerk, Kirzner). Não é um plano de "economia de token"; é a camada de **incentivos como ordem espontânea**, opcional por módulo (`katallaxia`).

---

## 1. Princípios austríacos aplicados

| Princípio austríaco | Tradução no HDAP |
|---|---|
| **Ordem espontânea** (Hayek) | Não existe um "planejador central" de preços, cotas ou índices. Cada nó (`pyle`) define o **seu** preço (`timi`) e os usuários escolhem. O mercado (`katallaxia`) é o resultado, não o ponto de partida. |
| **Preferência temporal** (Böhm-Bawerk) | Guardar hoje vale menos que usar hoje. Quanto maior a duração de retenção contratada, maior o preço por byte-tempo (`tokos`). Quem tem baixa preferência temporal (não liga de guardar) oferece preço menor. |
| **Valor subjetivo** (Mises) | O preço não vem do custo, vem da valoração de cada par negociante. O nó que guarda 1 TB barato na Austrália e o usuário no Brasil se encontram por descoberta, não por tabela fixa. |
| **Reputação como capital** (Hayek, teoria da *fama*) | `pheme` não é "score de gamificação": é **capital acumulado** que gera renda futura. Nó com boa fama cobra mais ou é escolhido mesmo mais caro. Violar contrato destrói capital (`oneidos`). |
| **Competição como processo de descoberta** (Hayek/Kirzner) | O empreendedor (nó) descobre ineficiências (região mal atendida, preço mal alinhado) e lucra **corrigindo-as**. Sem "política pública" de replicação: a réplica nasce onde o preço compensa. |
| **Moeda sã, sem emissão por decreto** | Unidade de conta `obolos` é definida por **byte-tempo** (recurso real escasso), não por política monetária. O PoW (`mochthos`) é **custo de produção** da credencial de escrita, não inflação. |
| **Propriedade privada e contrato livre** | `ktema` (o arquivo) pertence a alguém (`kyrios`); `adeia` (permissões) são concessões voluntárias; `syngraphe` (tratado/contrato de guarda) é acordo bilateral livre. |
| **Anti-Sybil econômico, não administrativo** | Membragem aberta sem "lista branca": quem quer ter voz na reputação **penhora** (`paratheke`). Voz = stake. Sem stake, voto não pesa. |

---

## 2. A fiação do incentivo

### 2.1 O mercado (katallaxia)

- Cada `pyle` publica uma **menuitem de preço** (`timi`): { moedas por GiB × dia } e { duração máxima garantida }. Nada é imposto.
- O usuário (ou seu cliente) **descobre** pelos nós que conhece e pela fama (`pheme`), negocia `syngraphe`.
- A `choregia` (banda/capacidade autorizada) deixa de ser "caridade": é a **capacidade de produção** que o nó oferta mediante pagamento contratado.

### 2.2 A moeda (obolos)

- `obolos` = unidade **abstrata e local**, lastreada em recurso real (byte-tempo). O núcleo do HDAP **não emite cadeia própria**; a camada `katallaxia` é um módulo opcional que aceita `obolos` *como unidade de conta*, liquidável em qualquer meio que o par combine (fiat, LN, recibo de serviço recíproco — Arnac não tem "banco").
- Mochthos (PoW) **não é moeda**: é pedágio de entrada e custo anti-abuso (meio, não fim). O usuário paga com trabalho; o nó paga camping com disco. São dons de escassez, não emissão monetária.

### 2.3 Reputação como capital (pheme, oneidos)

- **Ganha-se** fama por: cumprir duração contratada, apagar em `lethe` quando pedido, servir hashes corretos, estar online na janela `kairos`.
- **Perde-se** capital por: reter conteúdo lho (violar `lethe`), servir hash adulterado, censurar, ter downtime de contrato.
- **Economicamente**: `pheme` não é prova de "bom caráter" moral — é **capital capitalizável** que decide renda futura. Perder fama = perder receita. É isto que torna `lethe` *razoavelmente* cumprido mesmo contra nó teimoso: não é física, é **cálculo de custo do nó**.
- Enforce: `paratheke`. Para participar da federação pública, o nó deposita penhor; provas de violação (evidência hashada) acionam `euthyne` (arbitragem)e o penhor **queima/presta** ao lesado. Auferi as contas.

### 2.4 Janela e prazos (kairos/tokos)

- Tudo que é contrato tem `kairos` (janela): desafio, sessão, `timi` válida.
- `tokos` (juros/preferência temporal): a `timi` por byte-tempo **cresce com a duração** — reflete que o nó que amarra disco por 5 anos sacrifica flexibilidade. Isso *revela* a preferência temporal de cada nó; quem guarda barato e longo é quem realmente ama guardar.

### 2.5 Arbitragem (euthyne)

- Disputas (não apagou, adulterou, não pagou) vão a **árbitros privados** escolhidos livremente pelas partes entre nós de alta `pheme` + `paratheke`.
- Veredito registra em `stele` de evidência; repercute em `oneidos` (fama) e executa penhor. **Sem corte central**, sem "mineração de verdade": só reputação + penhor.

---

## 3. Perguntas frequentes sobre o desenho econômico

| Pergunta | Resposta |
|---|---|
| **Se um nó é malicioso, apagar é impossível?** | É verdade, e o protocolo assume isso. O HDAP não alega enforcement físico; torna `lethe` **economicamente dominante**: reter um arquivo tombstoned é risco de `euthyne`, quebra de `paratheke` e `oneidos`, que reduz a renda futura. A reputação é o único "juiz", e funciona porque é capital. |
| **Por que alguém guardaria de graça?** | Não guarda. `katallaxia` monetiza a guarda por `timi`, `obolos` e byte-tempo, com descoberta de mercado. Sem `katallaxia`, o protocolo continua legítimo para federação privada, em que os nós se guardam reciprocamente por `apographon`. |
| **Como se evita o double-spend de PoW?** | O `mochthos` é custo **por nó** e por `proklesis`; o `syngraphe` consome o nonce e o desafio é de uso único. A capacidade autorizada é **declarada e recontada pelo nó destinatário**, seguindo a política local (recontagem, especificação §9.3). Sem registro global, vale a regra austríaca: o valor de um bilhete é a promessa de quem o assina. |
| **O consenso de reputação não é vulnerável a Sybil?** | Em rede aberta, `pheme` **pesa por `paratheke`**: voz é stake. Em rede fechada, de conhecidos, a maioria simples basta. Os dois modos são explícitos, e o modo aberto não usa voto de usuário anônimo. |
| **Os metadados públicos não vazam?** | Vazam, e isso é declarado. A publicidade da `stele` é **condição** da verificabilidade global. A mitigação de superfície é cifrar o `ktema` no cliente, não expor o trilho de acessos e usar URIs com `?hash=` para não depender de lookup por nome. |
| **O protocolo não é grande demais?** | O núcleo é mínimo: identidade, auth 3FA, mochthos/syngraphe, ktema, adeia, prytaneion e lethe. Tudo o mais (`katallaxia`, `euthyne`, DDNS/kerux, federação) é **módulo opcional** com fronteira via tipos de documento, não acoplado ao núcleo. |

---

## 4. O que é e o que NÃO é a katallaxia

**É**: um módulo que publica `timi`, registra `syngraphe` de guarda, usa `obolos` como unidade de conta e move `pheme`/`paratheke`.

**NÃO é**:
- Não é blockchain de contrato inteligente; `syngraphe` é uma `stele` assinada (determinística e auditável), não código executado.
- Não tem "tabela de preços oficial", "consenso de preço" nem "oráculo".
- Não substitui o núcleo: com ela desligada, HDAP segue 100% funcional (modo federação privada).

---

## 5. Leituras

- Hayek, *A Ordem Oral (antologia)*: ordem espontânea e catallaxy; *The Use of Knowledge in Society*: preços como sinal.
- Mises, *Ação Humana*: valor subjetivo e cálculo econômico.
- Böhm-Bawerk, *Capital and Interest*: preferência temporal e `tokos`.
- Kirzner, *Competition and Entrepreneurship*: descoberta empreendedora.