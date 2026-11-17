# Documentação do HDAP

Este diretório reúne a documentação pública do **Hsyst Descentralized Archive Protocol**, na versão **v2.0**, geração **Téleia vási** com codinome de protocolo **Teleios** e codinome de lançamento **Teleios**. Comece pela [visão da geração v2](VERSAO.md) para entender o que mudou em relação ao Themelio. A documentação foi escrita para ser lida em texto corrido, com links entre os capítulos, e para servir tanto a quem quer usar o sistema quanto a quem quer operá-lo, implementá-lo ou auditá-lo.

## Por onde começar

Se você quer usar o HDAP no dia a dia, comece pelo [Guia do Usuário](userguide.md). Ele é a porta de entrada e explica, em linguagem simples, o que é o protocolo, qual é o problema que ele resolve e o que você pode esperar dele. O guia continua em seis capítulos que podem ser lidos em ordem ou consultados separadamente. O [segundo capítulo](userguide2.md) trata da identidade e da casa, das chaves, do cofre, do login e do backup. O [terceiro](userguide3.md) trata de arquivos, documentos e permissões, incluindo o formato canônico dos documentos `.hdap` e a avaliação da `adeia`. O [quarto](userguide4.md) trata de banda, economia e reputação. O [quinto](userguide5.md) trata da federação, das réplicas e da sucessão. E o [sexto](userguide6.md) trata dos aplicativos, da operação de um pyle, das atualizações e da recuperação.

Se o seu objetivo é compilar, testar, empacotar ou publicar o projeto, o caminho é o [Guia de Execução](guia-de-execucao.md). Ele cobre as dependências, os comandos de build, a suíte de testes, o cross-build para Linux e Windows, a geração de artefatos, a verificação de checksums e o checklist de release. É um guia de engenharia, não um guia de usuário, e foi escrito para quem precisa reproduzir o binário a partir do código.

Se o seu objetivo é entender a arquitetura e as decisões de engenharia, leia o [Manual Técnico](tecnico.md), que agora cobre HKDF, tempo UTC, cofre versionado e sessões hashadas. Ele descreve os componentes, os fluxos, as estruturas de dados e as escolhas que moldaram o protocolo. Para a semântica normativa, o próximo passo é a [Especificação Formal](especificacao-hdap.md). Para o formato de fio, as rotas HTTP e o comportamento do nó, o [RFC-HDAP](rfc-hdap.md). Os três documentos são complementares: o manual explica o porquê, a especificação define o quê e o RFC descreve o como.

Se o seu objetivo é auditar a segurança, o [Modelo de Ameaça](modelo-de-ameaca.md) lista cada ameaça, a mitigação correspondente e, o que é igualmente importante, os limites que o protocolo não promete resolver. Para o vocabulário, o [Léxico Grego](lexico-grego.md) reúne os nomes canônicos com a tradução e o uso de cada um. Para a base econômica, a [Filosofia Econômica](filosofia-economica.md) explica por que a banda existe, como o preço é formado e o que a reputação mede.

Para entender de onde o HDAP veio, o [HPS](hps.md) descreve o predecessor, as suas ideias e os limites que motivaram a criação de um protocolo novo. É um documento histórico, útil para situar as escolhas, mas não é necessário para usar o sistema.

## Como ler os documentos

A documentação usa a transliteração grega em minúsculas para os nomes de protocolo, como `pyle`, `adeia` e `diadosi`. Blocos de código e rotas são literais. As palavras "DEVE", "NÃO DEVE" e "PODE" têm sentido de requisito normativo apenas na Especificação e no RFC; nos guias, elas aparecem como descrição de comportamento. Os exemplos usam `127.0.0.1:8443` e arquivos fictícios, e não devem ser copiados para produção sem ajuste.

## Versionamento da documentação

Toda release do HDAP atualiza a documentação. A versão 1.0 é o marco zero, com **Themelio · Veritas Aeterna**; a v1.001 manteve Themelio com **Epoptia**. A versão **v2.0** abre a geração **Téleia vási**, com protocolo **Teleios**. Correções que não mudam o protocolo geram versões `v2.001`, `v2.002` e assim por diante, alterando apenas o codinome de lançamento; mudanças de protocolo abrem a próxima versão maior e trocam os dois codinomes. O formato dos documentos segue em `# VERSION: 1`. O resumo da geração está em [VERSAO.md](VERSAO.md) e o histórico completo no [CHANGELOG](../CHANGELOG.md).

## Documentos

A [Visão da v2](VERSAO.md) resume a geração Teleios; o [Guia do Usuário](userguide.md) é a porta de entrada e o resumo geral. Os capítulos [2](userguide2.md), [3](userguide3.md), [4](userguide4.md), [5](userguide5.md) e [6](userguide6.md) aprofundam identidade, arquivos, economia, federação e operação. O [Guia de Execução](guia-de-execucao.md) cobre build, testes e release. O [Manual Técnico](tecnico.md), a [Especificação Formal](especificacao-hdap.md) e o [RFC-HDAP](rfc-hdap.md) cobrem arquitetura, semântica e fio. O [Modelo de Ameaça](modelo-de-ameaca.md) cobre segurança. O [Léxico Grego](lexico-grego.md) cobre vocabulário. A [Filosofia Econômica](filosofia-economica.md) cobre a economia. E o [HPS](hps.md) cobre o predecessor.

Voltar ao [README do projeto](../README.md).
