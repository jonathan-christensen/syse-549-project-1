#!/bin/sh
# Start all four Lab 1 services in the background, one log file each.
#
#   sh scripts/run_all.sh            start every service
#   sh scripts/run_all.sh verifier rp   start only the ones named
#   sh scripts/run_all.sh subject csp verifier rp frontend   + the React UI
#
# `frontend` (the React app under frontend/) is opt-in, not in the default
# set: it is not part of the graded contract, and the default output staying
# exactly "4 of 4 up: subject csp verifier rp" is what docs/deployment.md
# tells the team to screenshot as proof the four services are up.
#
# No sudo, no systemd: nohup from the home directory, which is all the lab
# server allows. Ports and the bind address come from .env.
set -u

cd "$(dirname "$0")/.." || exit 1
ROOT=$(pwd)
RUN_DIR="$ROOT/run"
mkdir -p "$RUN_DIR"

[ -f .env ] || { echo "no .env - copy .env.example to .env and fill it in first"; exit 1; }

# Partner A's services are FastAPI modules; Partner B's are packages under services/.
module_for() {
    case "$1" in
        subject)  echo "services.subject.main" ;;
        csp)      echo "services.csp.main" ;;
        verifier) echo "services.verifier" ;;
        rp)       echo "services.rp" ;;
    esac
}

WANTED=${*:-"subject csp verifier rp"}

# Which of our ports are already listening, and on what address. A service
# started by hand - or a partner's copy on the same host - holds the port
# without a pidfile here, and launching a second one just fails obscurely.
HELD=$(python3 - "$WANTED" <<'PORTSCAN'
import subprocess, sys
sys.path.insert(0, ".")
from shared import config
try:
    out = subprocess.run(["ss", "-tln"], capture_output=True, text=True, timeout=5).stdout
except Exception:
    out = ""
listening = {}
for line in out.splitlines()[1:]:
    parts = line.split()
    if len(parts) >= 4 and ":" in parts[3]:
        addr, _, port = parts[3].rpartition(":")
        listening.setdefault(port, addr)
for name in sys.argv[1].split():
    if name not in config.PORT_OFFSETS:
        continue  # e.g. "frontend" - not a config.py-managed service
    port = str(config.port_for(name))
    if port in listening:
        print("%s %s %s" % (name, port, listening[port]))
PORTSCAN
)

FRONTEND_PORT=5173

start_frontend() {
    pidfile="$RUN_DIR/frontend.pid"
    if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        echo "  frontend already running (pid $(cat "$pidfile"))"
        return
    fi
    if [ ! -d "$ROOT/frontend/node_modules" ]; then
        echo "  frontend NOT started - run 'npm install' in frontend/ first"
        return
    fi
    (
        cd "$ROOT/frontend" || exit 1
        nohup npm run dev > "$RUN_DIR/frontend.log" 2>&1 &
        echo $! > "$pidfile"
    )
    echo "  started frontend (pid $(cat "$pidfile")) -> run/frontend.log"
}

for s in $WANTED; do
    if [ "$s" = "frontend" ]; then
        start_frontend
        continue
    fi
    mod=$(module_for "$s")
    [ -n "$mod" ] || { echo "unknown service: $s"; continue; }
    pidfile="$RUN_DIR/$s.pid"
    if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        echo "  $s already running (pid $(cat "$pidfile"))"
        continue
    fi
    holder=$(printf '%s\n' "$HELD" | awk -v s="$s" '$1 == s {print $2" "$3}')
    if [ -n "$holder" ]; then
        hport=${holder% *}; haddr=${holder#* }
        echo "  $s NOT started - port $hport is already held, bound to $haddr"
        if [ "$haddr" != "0.0.0.0" ] && [ "$haddr" != "*" ]; then
            echo "            that is not 0.0.0.0, so nothing on this host reaches it via localhost"
        fi
        echo "            whose: ps -eo pid,user,args | grep $s"
        continue
    fi
    nohup python3 -m "$mod" > "$RUN_DIR/$s.log" 2>&1 &
    echo $! > "$pidfile"
    echo "  started $s (pid $!) -> run/$s.log"
done

# Give them a moment, then say which ones actually answer.
sleep 2
echo
echo "== health =="
python3 - "$WANTED" <<'PY'
import json, sys, urllib.request
sys.path.insert(0, ".")
from shared import config
wanted = [n for n in sys.argv[1].split() if n in config.PORT_OFFSETS]
failed = 0
for name in wanted:
    url = "http://127.0.0.1:%d/health" % config.port_for(name)
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            body = json.load(r)
        ok = body.get("service") == name
        print("  %-9s %s  %s" % (name, "ok  " if ok else "WRONG", json.dumps(body)))
        failed += 0 if ok else 1
    except Exception as exc:
        print("  %-9s DOWN  %s" % (name, exc))
        # Print the reason rather than only pointing at the log: the last
        # meaningful line is nearly always the whole diagnosis.
        try:
            lines = [l.rstrip() for l in open("run/%s.log" % name) if l.strip()]
        except OSError:
            lines = []
        if lines:
            print("            %s" % lines[-1][:160])
            print("            (full log: run/%s.log)" % name)
        else:
            print("            see run/%s.log" % name)
        failed += 1
print()
if failed:
    print("%d of %d not answering" % (failed, len(wanted)))
else:
    print("%d of %d up: %s" % (len(wanted), len(wanted), " ".join(wanted)))
PY

# Not one of the four contract services, so it gets its own line rather than
# folding into the "N of 4 up" count docs/deployment.md screenshots.
case " $WANTED " in
    *" frontend "*)
        if command -v curl >/dev/null 2>&1 && curl -s -o /dev/null -m 3 "http://127.0.0.1:$FRONTEND_PORT/"; then
            echo "  frontend  ok    http://127.0.0.1:$FRONTEND_PORT"
        else
            echo "  frontend  DOWN  see run/frontend.log"
        fi
        ;;
esac
