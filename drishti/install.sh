#!/usr/bin/env bash
#
# Drishti installer. Idempotent, safe to re-run.
#
#   ./install.sh          set up, verify, print how to run
#   ./install.sh --start  set up, verify, then launch the web app
#
# Creates a private virtualenv in this folder for Flask. Nothing is installed
# system wide and nothing outside this folder is touched.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

VENV="$HERE/.venv"
BOLD=""; DIM=""; RED=""; GREEN=""; NIDO=""; OFF=""
if [ -t 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'
  GREEN=$'\033[32m'; NIDO=$'\033[38;5;166m'; OFF=$'\033[0m'
fi

say()  { printf '%s\n' "$*"; }
step() { printf '%s==>%s %s\n' "$NIDO" "$OFF" "$*"; }
die()  { printf '%serror:%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }

printf '\n%sDRISHTI%s  installer\n%s%s%s\n\n' "$NIDO$BOLD" "$OFF" "$DIM" "$HERE" "$OFF"

# ---------------------------------------------------------------- python
step "Looking for Python 3.9 or newer"
PY=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
      PY="$candidate"
      break
    fi
  fi
done

if [ -z "$PY" ]; then
  say ""
  say "No usable Python found."
  case "$(uname -s)" in
    Darwin)
      say "On macOS, either of these works:"
      say "    xcode-select --install        # Apple's command line tools"
      say "    brew install python           # or Homebrew"
      ;;
    *)
      say "Install Python 3.9 or newer from your package manager."
      ;;
  esac
  die "Python 3.9+ is required"
fi
say "    $PY  $("$PY" -c 'import sys; print(sys.version.split()[0])')"

# ---------------------------------------------------------------- venv
step "Setting up the virtualenv for Flask"
if [ ! -x "$VENV/bin/python" ]; then
  "$PY" -m venv "$VENV" 2>/dev/null || die "could not create a virtualenv at $VENV"
  say "    created $VENV"
else
  say "    reusing $VENV"
fi
VPY="$VENV/bin/python"

step "Installing Flask"
if "$VPY" -c 'import flask' 2>/dev/null; then
  say "    already present, $("$VPY" -c 'import importlib.metadata as m; print(m.version("flask"))')"
else
  "$VPY" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
  "$VPY" -m pip install --quiet flask || die "pip could not install Flask, are you online?"
  say "    installed $("$VPY" -c 'import importlib.metadata as m; print(m.version("flask"))')"
fi

# ---------------------------------------------------------------- launchers
step "Writing launchers"
chmod +x "$HERE/Drishti.py" "$HERE/Drishti_cli.py" "$HERE/selftest.py" 2>/dev/null || true

cat > "$HERE/drishti" <<EOF
#!/usr/bin/env bash
# Drishti CLI. Standard library only, the virtualenv is not required.
exec "\$(dirname "\${BASH_SOURCE[0]}")/Drishti_cli.py" "\$@"
EOF
chmod +x "$HERE/drishti"

cat > "$HERE/Drishti.command" <<EOF
#!/usr/bin/env bash
# Double click this in Finder to start the Drishti web app.
cd "\$(dirname "\${BASH_SOURCE[0]}")"
exec "./.venv/bin/python" Drishti.py
EOF
chmod +x "$HERE/Drishti.command"
say "    ./drishti            CLI"
say "    ./Drishti.command    web app, double clicks from Finder"

# ---------------------------------------------------------------- verify
step "Verifying this machine can actually run it"
say ""
set +e
"$VPY" "$HERE/selftest.py"
RC=$?
set -e

say ""
if [ "$RC" -ne 0 ]; then
  printf '%sSelf-test reported failures.%s Fix the FAIL lines above, then re-run ./install.sh\n' "$RED" "$OFF"
  exit "$RC"
fi

printf '%sReady.%s\n\n' "$GREEN$BOLD" "$OFF"
say "  Web app     ./Drishti.command      or  .venv/bin/python Drishti.py"
say "  CLI         ./drishti 8.8.8.8"
say "  API keys    ./drishti --keys       or the Settings button in the web app"
say "  AI summary  brew install ollama && ollama serve && ollama pull llama3.2"
say ""

if [ "${1:-}" = "--start" ]; then
  step "Starting the web app, ctrl-c to stop"
  exec "$VPY" "$HERE/Drishti.py"
fi
