# Pins TLS dos pyles oficiais

**HDAP v2.0 — Téleia vási · Teleios** · Revisão de 2026-11-17.

> **Este arquivo é uma âncora de bootstrap, não prova absoluta.** Os valores abaixo foram lidos de `GET /health` (`tls_pin`) em cada nó oficial em 2026-11-17. Confira-os por um canal independente antes de confiar, e prefira receber uma cópia assinada pela mantenedora. O id do pyle é derivado do endereço anunciado e **não** é um pin; o pin é o SHA-256 do DER do certificado TLS.

| Endereço | `server_id` | `tls_pin` (SHA-256 do certificado) |
|---|---|---|
| `pyle1.hdap.hsyst.org:8443` | `pyle-cHlsZTEuaGRhcC5oc3lzdC5vcmc6ODQ0Mw` | `e31eea2c5576724d58741ebfe6629065ab15bbfec2725f416280f820f3ccb2e0` |
| `pyle2.hdap.hsyst.org:8444` | `pyle-cHlsZTIuaGRhcC5oc3lzdC5vcmc6ODQ0NA` | `f94f5606d9f0f87a433ebdaa7fc3a9750df72698bc240a4d459286bdeb717f13` |
| `pyle3.hdap.hsyst.org:8445` | `pyle-cHlsZTMuaGRhcC5oc3lzdC5vcmc6ODQ0NQ` | `01dd1c576af6559bcaf0ecc6590ce8c22518b4ed6f0e4ac5bd90dcc247d41d5f` |
| `pyle.thais.fyi:8443` | `pyle-cHlsZS50aGFpcy5meWk6ODQ0Mw` | `c270bafd948dc5bb185009973099702789b3c7f4eea414670a1180b9f9162573` |

As chaves públicas anunciadas por cada nó no mesmo instantâneo:

| Endereço | `node_sign_pub` | `node_enc_pub` |
|---|---|---|
| `pyle1.hdap.hsyst.org:8443` | `5a6abe7f69f65dcb15a4b2c9f565a38fc81ab125cba930cac36d33cef7442867` | `f9619bc4f8c7888850c03ee39020e975e428e588d206c6ce95373ce0bf6c8f0b` |
| `pyle2.hdap.hsyst.org:8444` | `9b008c0800b4639f625448b57f076f58a5911f8ca84848b81f1fefcdf21ec6db` | `55f157fe5237fd68249914239ab8d804ff0e923ccb5d5e35be194c9ae763f322` |
| `pyle3.hdap.hsyst.org:8445` | `652623de5c1087a45a18f0ddc2ebc2c5ca48e6bda9ac15c86fc43c1f54e92e02` | `1cacc66936d7cbfc882f847eb231ed149cd5f64083e9f991c392f2dda3212c62` |
| `pyle.thais.fyi:8443` | `7113350e536c39488b4712ca29d704b2974acae0e65dded37cefab01524aeb5d` | `306b3cae6b440c24ce00336e4c0d35cf4331a6cf37a0b9f973fd29e68bcad46c` |

## Como usar

```bash
export PIN='e31eea2c5576724d58741ebfe6629065ab15bbfec2725f416280f820f3ccb2e0'
hdap-cli --host pyle1.hdap.hsyst.org --port 8443 --tls-pin "$PIN" health
```

O pin fixado na primeira conexão (TOFU) passa a ser a âncora daquele nó. Se mudar, **pare e investigue**: pode ser uma reinstalação legítima do nó ou um MITM. A GUI mostra o pin na tela de conexão; a CLI nunca aceita um nó TLS sem `--tls-pin`.

## Verificação fora da banda

A mantenedora publica anúncios assinados com a chave OpenPGP cuja impressão digital é:

```
1489 36AB E859 A3A9 0ED1 E17A 5FF5 3F39 FFC4 D03F
```

A chave está em `https://keys.thais.fyi/pks/lookup?op=get&search=thais%40hsyst.org`. O contato de segurança está em [SECURITY.md](../SECURITY.md) e em [security.txt](../.well-known/security.txt).

O manifesto de pins assinado está em [`docs/pins-oficiais-manifesto.txt`](pins-oficiais-manifesto.txt). Para validar:

```bash
curl -fsSL 'https://keys.thais.fyi/pks/lookup?op=get&search=thais%40hsyst.org' | gpg --import
gpg --verify docs/pins-oficiais-manifesto.txt.asc docs/pins-oficiais-manifesto.txt
```

O arquivo `.asc` (assinatura OpenPGP separada) deve ser fornecido pela mantenedora.

Ao trocar de nó, repita a leitura de `/health` e compare com esta tabela. Nenhuma listagem derivada de endereço substitui o pin: `pyle-<base64(endereço)>` identifica o nó, mas não autentica o certificado.
