#!/bin/sh
# Stop the services started by run_all.sh.
#
#   sh scripts/stop_all.sh           stop everything
#   sh scripts/stop_all.sh rp        stop only the ones named
set -u

cd "$(dirname "$0")/.." || exit 1
RUN_DIR="$(pwd)/run"

for s in ${*:-subject csp verifier rp}; do
    pidfile="$RUN_DIR/$s.pid"
    if [ -f "$pidfile" ]; then
        pid=$(cat "$pidfile")
        if kill "$pid" 2>/dev/null; then
            echo "  stopped $s (pid $pid)"
        else
            echo "  $s was not running (stale pid $pid)"
        fi
        rm -f "$pidfile"
    else
        echo "  $s not started by run_all.sh"
    fi
done
