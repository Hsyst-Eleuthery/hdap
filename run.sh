#!/usr/bin/env bash
# Sobe um pyle local + a GUI para desenvolvimento.
#
# O estado do nó (SQLite) e o home da GUI ficam em ./.hdap-dev por padrão, e
# não em /tmp: o `krypte.hdap` do cliente é a identidade, e perdê-lo no reboot
# significa uma identidade nova. Sobrescreva com HDAP_DEV_DIR.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

DEV_DIR="${HDAP_DEV_DIR:-$ROOT/.hdap-dev}"
DATA_DIR="$DEV_DIR/node"
GUI_HOME="$DEV_DIR/gui"
LOG_DIR="$DEV_DIR/log"
mkdir -p "$DATA_DIR" "$GUI_HOME" "$LOG_DIR"

SERVER_LOG="$LOG_DIR/server.log"
GUI_LOG="$LOG_DIR/gui.log"

echo "[run] compilando release (incremental) ..."
cargo build --release -p hdap-server -p hdap-gui

pkill -f "hdap-server.*8443" 2>/dev/null || true
pkill -f "hdap-gui" 2>/dev/null || true
sleep 0.3

echo "[run] iniciando nó em 127.0.0.1:8443 (TLS, pin via TOFU) ..."
# Sem --id: o nó adota pyle-<base64(127.0.0.1:8443)>, então a URI de acesso já
# carrega o endereço e outro pyle consegue dialá-lo direto.
setsid ./target/release/hdap-server \
  --listen 127.0.0.1:8443 \
  --open-federation \
  --data "$DATA_DIR" \
  --choregia 1048576 \
  >"$SERVER_LOG" 2>&1 &
SRV_PID=$!

# Espera o pin aparecer no log (o TLS é gerado no boot).
PIN=""
for _ in $(seq 1 50); do
  PIN=$(grep -oE 'tls_pin=[0-9a-f]{64}' "$SERVER_LOG" 2>/dev/null | head -1 | cut -d= -f2 || true)
  [[ -n "$PIN" ]] && break
  sleep 0.1
done
echo "[run] PID do nó: $SRV_PID"
if [[ -n "$PIN" ]]; then
  echo "[run] pin TLS (TOFU): $PIN"
else
  echo "[run] AVISO: pin TLS não apareceu em $SERVER_LOG (o nó pode ter falhado)"
fi

echo "[run] iniciando GUI ..."
# The GUI takes no positional path; HDAP_HOME relocates the default base and
# the nickname is still appended, so `maria` and `jose` stay separate vaults.
HDAP_HOME="$GUI_HOME" setsid ./target/release/hdap-gui >"$GUI_LOG" 2>&1 &
GUI_PID=$!
echo "[run] PID da GUI: $GUI_PID"

cat <<UI

=== CONEXÃO NO GUI (tela de login) ===
Host:     127.0.0.1
Porta:    8443
Pin TLS:  DEIXE VAZIO (TOFU — a GUI fixa o pin no primeiro login)
Home dir: deixe vazio (usa HDAP_HOME=$GUI_HOME/<nickname>)
Nickname: qualquer um (é o nickname que você digitar)
Senha:    a senha é o que protege seu krypte.hdap — guarde-a

O passo de OTP fica em $GUI_HOME/<nickname>/omphalos.step, então fechar e rodar de novo
continua na mesma conta. Apagar esse diretório cria uma identidade nova — e sem a senha, o krypte é irrecuperável.

Logs: nó=$SERVER_LOG  GUI=$GUI_LOG

Ctrl+C para parar os dois.
UI

trap 'kill $SRV_PID $GUI_PID 2>/dev/null || true; echo; echo "[run] parado"' EXIT
wait
