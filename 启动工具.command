#!/bin/zsh
set -euo pipefail
cd -- "${0:A:h}"
app_path="$PWD/dist/Claude Network Check.app"
if [[ ! -d "$app_path" ]]; then
  ./build_app.command
fi
exec /usr/bin/open "$app_path"
