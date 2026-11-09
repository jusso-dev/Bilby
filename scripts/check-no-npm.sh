#!/usr/bin/env bash
# Fails if any npm, yarn, pnpm or bun files are tracked, or if app.js grows
# past 300 lines. See docs/adr/0002-frontend-without-npm.md.
set -euo pipefail

status=0
banned='(^|/)(package\.json|package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb|bun\.lock)$|(^|/)node_modules(/|$)'
if found=$(git ls-files | grep -E "$banned"); then
  echo "These files aren't allowed (Bilby has no npm or Node):"
  echo "$found"
  status=1
fi

max=300
lines=$(wc -l < app/ui/app.js | tr -d ' ')
if [ "$lines" -gt "$max" ]; then
  echo "app/ui/app.js has $lines lines. The limit is $max."
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "No npm files tracked. app.js is $lines lines (limit $max)."
fi
exit "$status"
