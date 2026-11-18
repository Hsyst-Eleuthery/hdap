# Aplicativos e Operação

*Revisão de 2026-11-17.*

**HDAP v2.0 — Téleia vási · Teleios**

**Escrito por Thaís (op3n/op3ny)**

---

**Leia primeiro:** [guia-5-federacao.md](guia-5-federacao.md) (Federação, Réplicas e Sucessão)
**Guia prático:** [guia-de-execucao.md](guia-de-execucao.md)

---

## Os dois programas

O HDAP é feito de duas peças que trabalham juntas, cada uma com um papel bem definido. A primeira é o **pyle**, o servidor. Ele guarda as casas, aplica as permissões, participa da federação, serve HTTP/TLS e mantém o estado. A segunda é o **cliente**, que existe em duas formas: o `hdap-cli` no terminal e o `hdap-gui` com tela nativa. As duas formas fazem as mesmas operações essenciais, e escolher uma é uma questão de gosto e de hábito.

O pyle não tem interface gráfica, e isso é intencional. Ele é um serviço, feito para rodar como processo em segundo plano, com log, configuração e scripts. O cliente é a parte que você usa, e a GUI é apenas uma camada de conveniência sobre o mesmo núcleo. Se um dia a interface mudar, a identidade e os arquivos continuam os mesmos, porque o que importa está no protocolo, não na tela.

Para uso diário, a GUI é o caminho mais confortável. Para automação, a CLI é a ferramenta certa. É comum usar as duas: a GUI para navegar e a CLI para scripts de backup, replicação e monitoramento. Como as duas falam o mesmo protocolo, você pode alternar sem converter nada.

---

## Primeiros passos com a GUI

Na primeira vez que o `hdap-gui` abre, ele pede um nickname. Você escolhe o nome que quer ver na tela, e o aplicativo gera a identidade, o cofre e a chave. O nickname não precisa ser único na rede, porque o sufixo derivado da chave garante a unicidade. Escolha um nome que faça sentido para você; ele pode ser alterado depois, mas o sufixo permanece o mesmo.

Em seguida, a GUI pede a URL do pyle. Se você estiver testando localmente, é `https://127.0.0.1:8443`. Se for um servidor na rede, é o endereço que o operador informou. Na primeira conexão, a GUI mostra a impressão digital do certificado e pede confirmação: esse é o momento TOFU. Compare o pin com o que o operador publicou no `timi` ou em outro canal confiável. Confirmar um pin errado é o único erro que a criptografia não consegue consertar sozinha.

Depois do registro, a GUI abre a tela principal, com a sua casa, os seus arquivos e o painel de status. Dali você pode navegar, enviar arquivos, criar pastas, editar permissões e ver o saldo de banda. A interface foi desenhada para que as ações destrutivas peçam confirmação e as ações sensíveis mostrem o que será assinado.

---

## Primeiros passos com a CLI

O executável se chama `hdap-cli`. A sintaxe é `hdap-cli [GLOBAIS] COMANDO [ARGUMENTOS]`, e as opções globais podem vir antes ou depois do comando. O primeiro passo é criar a identidade com `init <nickname>`; em seguida vem `register` no pyle escolhido, `auth` para obter o token da sessão e `whoami` para conferir o ID global.

```bash
export HDAP_PASS='uma-senha-forte'
export PIN='impressão digital do certificado do nó'

hdap-cli --home ~/.hdap --pass-env HDAP_PASS init thais
hdap-cli --home ~/.hdap --pass-env HDAP_PASS --tls-pin "$PIN" register
hdap-cli --home ~/.hdap --pass-env HDAP_PASS --tls-pin "$PIN" auth
hdap-cli --home ~/.hdap --tls-pin "$PIN" whoami
```

A passphrase **não precisa** ir na linha de comando. A ordem preferida é `--pass-env NOME` (lê uma variável de ambiente), `--pass-file ARQUIVO` (lê uma linha de um arquivo) ou o prompt no terminal, com eco desligado. `--pass SENHA` ainda funciona, mas imprime um aviso: qualquer pessoa com acesso à lista de processos vê a senha. Os comandos `health`, `resolve`, `prices`, `download`, `delete` e `list` não pedem passphrase.

Os comandos disponíveis são: `init`, `register`, `auth`, `whoami`, `band`, `health`, `rotate`, `upload`, `download`, `delete`, `list`, `alias`, `resolve`, `prices`, `transfer-request`, `transfer-inbox`, `transfer-accept` e `transfer-own`. As globais são `--host` (padrão `127.0.0.1`), `--port` (padrão `8443`), `--tls-pin`, `--pass-env`, `--pass-file`, `--pass`, `--home`, `--help` e `--version`. Um `--tls-pin` é obrigatório contra qualquer nó TLS; sem ele a CLI fala HTTP simples, o que só faz sentido em loopback com `--no-tls` no servidor.

Um detalhe que confunde no começo: o pyle é o servidor; a casa é o espaço. O servidor é o `hdap-server`, separado do cliente. Para usar a casa, você usa `upload`, `download`, `delete`, `list` e as transferências.

---

## O explorador e os painéis da GUI

A GUI é construída em torno de um explorador de arquivos. A área central mostra a casa, permite navegar, enviar, baixar, renomear, apagar e criar pastas. A barra superior carrega a URI lógica e resolve aliases; a barra lateral reúne os lugares, as pessoas e os atalhos de painel. A ideia é que você reconheça o lugar em que está antes de agir, porque quase toda ação depende do caminho e do dono.

Os painéis laterais abrem as tarefas que não cabem na grade. O painel **Documentos** lista os `.hdap` da casa e abre cada um no editor canônico, com validação antes de salvar. O painel **Permissões** edita a `adeia` como uma lista de regras legíveis: cada regra é uma linha com **Quem** (Todos ou um Usuário pelo ID global), **Onde** (`/` para a casa inteira, uma pasta como `docs/` ou um arquivo como `docs/segredo.txt`) e **Pode** (Negar, Ler, Escrever ou Dono). O texto canônico aparece ao lado e é reescrito à medida que você ajusta a regra, com pré-visualização do que será assinado. A ordem das regras no arquivo não importa: a avaliação sempre dá prioridade ao caminho mais específico, ao usuário sobre Todos e à negação sobre a liberação. O painel **Configuração** reúne os seis documentos da casa, incluindo o `diadosi` e o `kerux`.

O painel **Banda** mostra o saldo, o consumo, a `moira` e a tabela do `timi`, com o custo estimado antes de cada operação. O painel **Preços** consulta o `timi` do pyle, e o painel **Aliases** publica e resolve nomes no DDNS. O painel de **Rede** mostra a bolha, os pares conectados e a saúde do nó. Juntos, eles cobrem o ciclo de uso sem exigir que você decore comandos.

---

## O editor de texto canônico

O coração da GUI é o editor de documentos. Ele não é um editor de texto comum: é um editor que entende a forma canônica do protocolo. Quando você abre um `.hdap`, ele mostra o `HEAD`, o `BODY` e o `SIGS`, valida a ordem das seções, a presença dos campos obrigatórios e a coerência dos tipos, e só permite salvar se o documento estiver válido.

Ao salvar, o editor calcula o hash, incrementa a edição, insere o `PREV_HASH` e assina com a chave da identidade. Você vê o diff antes de confirmar. Esse cuidado existe porque um documento inválido pode ser rejeitado pelo pyle ou, pior, aceito com uma semântica diferente da que você esperava. A validação local reduz esse risco, mas não substitui a verificação do servidor.

Há um limite honesto: o editor valida a forma, não a sua intenção. Se você conceder `write` a um caminho que não queria, o documento estará válido e será aceito. A interface mostra um resumo em linguagem natural antes de assinar, mas a decisão é sua. Nenhum software consegue adivinhar o que você quis dizer.

---

## O que acontece no login

Quando o cliente conecta a um pyle, ele apresenta a identidade e resolve o desafio dos três fatores. A GUI mostra o progresso em etapas: conexão TLS, verificação do pin, envio do `prosopeion`, assinatura do desafio, passo OTP e prova de transporte. Se alguma etapa falhar, a mensagem indica qual foi e o que fazer.

Os erros mais comuns têm causas claras. Um `401` no login geralmente significa que o passo OTP está dessincronizado ou que a identidade não está registrada naquele pyle. Um erro de pin significa que o certificado mudou ou que você está falando com outro servidor. Um erro de rede significa que o pyle não está no ar ou que a porta está bloqueada. A GUI traduz esses erros em linguagem simples, mas mantém o código original visível para quem quiser investigar.

Se o login falhar repetidamente, não insista às cegas. Verifique se o pyle está no ar, se a URL está correta, se o pin confere e se o cofre é o que você pensa que é. A maioria dos problemas é de configuração, não de criptografia.

---

## Ángelma, UTC e saúde do nó

A **Ángelma** é a mensagem que o pyle publica sobre si mesmo: uptime, usuários, arquivos, versão, protocolo e outros dados. Ela aparece no rodapé da GUI (passe o mouse para ver o texto e o carimbo UTC), no comando `health` e na rota `GET /motd` do servidor.

```bash
hdap-cli --tls-pin "$PIN" health
```

A saída traz `protocol=v2 (Teleios)`, `version`, `server_id`, `time_utc`, `date_utc`, `uptime_secs`, `users`, `files` e, quando configurada, a Ángelma. O `time_utc` é um inteiro com segundos desde 1970-01-01 às 00:00 UTC; `date_utc` é a mesma informação em texto. Nenhum dos dois depende do fuso de quem pergunta, e toda resposta HTTP carrega o cabeçalho `X-HDAP-Server-Time` com o instante do nó.

Para rotacionar a âncora OTP do seu login, use `rotate TOKEN` na CLI ou o botão 🔑 da GUI. O comando exige a chave de identidade, não apenas o token, e regrava o cofre local com a nova âncora. Depois rode `auth` de novo:

```bash
hdap-cli --pass-env HDAP_PASS --home ~/.hdap --tls-pin "$PIN" rotate "$TOKEN"
hdap-cli --pass-env HDAP_PASS --home ~/.hdap --tls-pin "$PIN" auth
```

---

## Operação: rodando um pyle

Rodar um pyle é uma tarefa de operador, e ela tem requisitos próprios. Você precisa de um servidor com disco, de um certificado TLS válido, de uma configuração de portas e de uma política de backup. O guia de execução cobre os detalhes, mas vale registrar aqui os princípios que não mudam.

O primeiro princípio é que o pyle precisa de persistência antes da resposta. Ele só confirma uma operação depois de gravar no disco. Isso significa que um `200` é uma promessa cumprida, e que uma queda de energia não deixa o cliente achando que publicou algo que não foi publicado.

O segundo é que o pin do certificado é parte da identidade do serviço. Se o certificado muda sem aviso, os clientes recusam a conexão. A rotação de certificado precisa ser planejada e comunicada, com um período de transição em que os dois pins são aceitos. Trocar o certificado sem aviso é a forma mais rápida de perder usuários.

O terceiro é que o log é parte do contrato. Um operador precisa saber o que aconteceu, quando e por quê. O pyle registra as operações com identificadores, e o guia de execução mostra como correlacionar um erro do cliente com uma linha do log do servidor.

Se você só quer alcançar a rede, sem operar um nó, os pyles oficiais mantidos pelo projeto são `pyle1.hdap.hsyst.org:8443`, `pyle2.hdap.hsyst.org:8444`, `pyle3.hdap.hsyst.org:8445` e `pyle.thais.fyi:8443`. Ao subir um nó com bind curinga, passe `--advertise` com o endereço público: é ele que define o id padrão do pyle e o endereço que os pares vão usar. Sem isso, o id sai do bind e fica inalcançável.

---

## Operação v2: novas opções do servidor

Além das opções clássicas (`--listen`, `--advertise`, `--data`, `--id`, `--moira`, `--max-upload`, `--rate-limit`, `--pow-*`), a geração Teleios acrescentou:

| Opção | Para que serve | Padrão |
|---|---|---|
| `--motd TEXTO` / `--motd-file ARQUIVO` | define a Ángelma, com tags `HDAP{[uptime]}`, `HDAP{[users]}`, `HDAP{[protocol]}`, `HDAP{[date_utc]}` etc. | vazia |
| `--master-key-file ARQUIVO` | guarda a chave mestra dos blobs fora do banco (64 hex = 32 bytes, `0600` em Unix) | desligado |
| `--max-connections N` | teto de conexões simultâneas; acima dele, `503` | `256` |
| `--cleanup-interval N` | segundos entre limpezas de desafios e sessões expirados; `0` desativa | `60` |
| `--time-tolerance N` | tolerância de skew entre pyles federados; não afeta sessões | `300` |

Quando `--motd` e `--motd-file` aparecem juntos, **o último vence** — os dois apenas atribuem a mesma configuração. A chave mestra precisa entrar no backup junto com o banco e o `tls.identity`: sem ela os blobs ficam ilegíveis, e sem o `tls.identity` o pin muda. Com a chave externa, o SQLite grava a linha zerada, e tokens de sessão são guardados somente como `v2:{sha256(...)}`.

---

## Atualizações e compatibilidade

A geração atual é **v2.0 — Téleia vási · Teleios**. Uma versão `v2.00x` corrige e melhora sem mudar a linguagem do protocolo; o formato `# VERSION: 1` continua valendo, e cofres e documentos v1 são lidos sem conversão. A política completa de codinomes, as regras de bump e o histórico estão em [VERSAO.md](VERSAO.md); cada release atualiza a documentação e as datas de revisão.

Para o usuário, a recomendação é simples: mantenha o cliente e o pyle na mesma versão maior, leia as notas de release antes de atualizar e faça backup do cofre antes de qualquer mudança. A compatibilidade é um compromisso, mas o backup é a rede de segurança que nenhum compromisso substitui.

---

## Backup e recuperação na prática

O backup do HDAP tem duas partes: o cofre e a casa. O cofre é local, cifrado e pequeno; copie a pasta inteira para um lugar seguro, de preferência offline, e guarde a senha em um gerenciador de senhas. A casa é remota e maior; use réplicas e, se o conteúdo for crítico, uma cópia local periódica.

A recuperação também tem duas partes. Se o cofre foi perdido, não há recuperação da identidade; o caminho é criar uma nova identidade e migrar o conteúdo que ainda existir. Se a casa foi perdida, o fallback configurado no `diadosi` pode assumir, ou as réplicas podem ser promovidas. Em ambos os casos, o tempo de recuperação depende de você ter planejado antes.

Um erro comum é achar que o servidor é o backup. Ele não é. O servidor é uma cópia de trabalho, sujeita a falhas, erros de operação e decisões do operador. O backup é seu, e a responsabilidade também. O HDAP foi desenhado para que essa responsabilidade seja possível, não para eliminá-la.

---

## Termos importantes

| Termo | Definição simples |
|---|---|
| **pyle** | O servidor HDAP. |
| **`hdap-cli`** | O cliente de linha de comando. |
| **`hdap-gui`** | O cliente com interface gráfica nativa. |
| **Ángelma** | Mensagem do pyle com uptime, contadores, versão e protocolo. |
| **UTC** | Relógio do protocolo: segundos desde 1970-01-01 às 00:00, sem fuso. |
| **TOFU** | Confiar no certificado na primeira conexão e fixá-lo. |
| **pin** | Impressão digital do certificado TLS do pyle. |
| **`symbolon`** | Token de sessão local do pyle. |
| **`daemon`** | Modo do pyle com console interativo. |
| **fallback** | Identidade autorizada a assumir a casa. |

---

## Perguntas frequentes

**Preciso rodar meu próprio pyle?** Não. Você pode usar um pyle operado por outra pessoa. Rodar o seu dá controle e independência, mas exige operação e certificado.

**A GUI e a CLI usam o mesmo cofre?** Sim, se apontarem para a mesma pasta. Você pode alternar entre elas sem converter nada.

**Posso usar a GUI sem internet?** Para navegar em conteúdo já baixado e editar documentos, sim. Para sincronizar e publicar, não.

**O que faço se o pin do certificado mudar?** Confirme com o operador por um canal independente antes de aceitar. Uma mudança não anunciada pode ser um ataque.

**Como sei qual versão estou usando?** A GUI mostra a versão no rodapé e no painel de status; a CLI responde a `--version`. Para conferir a geração do protocolo, rode `health`: `protocol_version` deve ser `2` e `protocol_codename`, `Teleios`. Os codinomes também aparecem na documentação da release.

**Por que a CLI não aceita mais só `--pass`?** Aceita, mas avisa. `--pass` expõe a senha na lista de processos; `--pass-env`, `--pass-file` e o prompt do terminal evitam isso. Comandos que não precisam de identidade, como `health`, não pedem senha nenhuma.

**Posso atualizar sem parar o pyle?** Depende do método de instalação. O guia de execução cobre a atualização com e sem downtime, e recomenda backup antes.

**O log do pyle é público?** Não. O log é do operador. O que é público é o estado verificado: assinaturas, hashes e a matriz de origem.

**O que acontece se eu rodar dois pyles na mesma máquina?** Eles precisam de portas e diretórios distintos. Compartilhar o mesmo diretório de dados corrompe o estado.

---

**Leia agora:** [guia-de-execucao.md](guia-de-execucao.md) — Instalação, compilação, testes e empacotamento
