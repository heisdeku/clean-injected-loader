#!/usr/bin/env bash
# Symlink clean-injected-loader onto your PATH at ~/bin so edits in this repo
# take effect immediately. Re-run any time; it's idempotent.
set -euo pipefail

src="$(cd "$(dirname "$0")" && pwd)/clean-injected-loader.sh"
bindir="${1:-$HOME/bin}"
dest="$bindir/clean-injected-loader"

mkdir -p "$bindir"
chmod +x "$src"
ln -sfn "$src" "$dest"

echo "linked $dest -> $src"
case ":$PATH:" in
  *":$bindir:"*) ;;
  *) echo "note: $bindir is not on your PATH — add it, e.g.:"
     echo "      echo 'export PATH=\"$bindir:\$PATH\"' >> ~/.zshrc" ;;
esac
