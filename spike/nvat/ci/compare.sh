#!/usr/bin/env bash
# Summarize every job's out/ directory (downloaded into $1/out-<name>) as Markdown, comparing
# each verdict and its claims with NVIDIA's x86-64 package.
set -uo pipefail
dir=${1:?usage: compare.sh <results dir>}
base=$dir/out-baseline-x86_64

field() { [ -f "$1" ] && grep -m1 "^$2=" "$1" | cut -d= -f2; }
mib() { [ -n "$1" ] && awk -v b="$1" 'BEGIN {printf "%.1f", b / 1048576}'; }
count() { [ -f "$1" ] && grep -c "$2" "$1"; }

verdict() { # <out dir> <mode>
  local f=$1/$2.json
  if [ ! -s "$f" ]; then echo "not run"; return; fi
  local ok
  ok=$(grep -q '"success": true' "$f" && echo pass || echo FAIL)
  if [ "$1" = "$base" ]; then echo "$ok"
  elif [ ! -s "$base/$2.json" ]; then echo "$ok (no baseline)"
  elif diff -q "$f" "$base/$2.json" >/dev/null; then echo "$ok, same claims"
  else echo "$ok, DIFFERENT claims"
  fi
}

echo "## libnvat per target"
echo
echo "| job | NvRemote (NRAS) | NvLocal | CA bundle | full build | library | stripped | exports as NVIDIA links | exports restricted |"
echo "|---|---|---|---|---|---|---|---|---|"
for d in "$dir"/out-*; do
  name=${d##*/out-}
  secs=$(cat "$d/build-seconds" 2>/dev/null || true)
  def=$( [ -f "$d/exports-default.txt" ] && echo "$(wc -l < "$d/exports-default.txt") ($(count "$d/exports-default.txt" '^nvat_') nvat_)")
  res=$( [ -f "$d/exports-restricted.txt" ] && echo "$(wc -l < "$d/exports-restricted.txt") ($(count "$d/exports-restricted.txt" '^nvat_') nvat_)")
  ca=$( [ -f "$d/ca" ] && (grep -q '^default$' "$d/ca" && echo default || echo "needs explicit ($(grep -q 'file: ' "$d/ca" && echo "$(grep -o 'file: [^ ]*' "$d/ca" | cut -c7-) missing" || echo "none compiled in"))"))
  echo "| $name | $(verdict "$d" remote) | $(verdict "$d" local) | ${ca:--} | ${secs:+$((secs / 60))m$((secs % 60))s} | $(mib "$(field "$d/size" size)") MiB | $(mib "$(field "$d/size" stripped_size)") MiB | ${def:--} | ${res:--} |"
done

for d in "$dir"/out-*; do
  [ "$d" = "$base" ] && continue
  for mode in remote local; do
    if [ -s "$d/$mode.json" ] && [ -s "$base/$mode.json" ] && ! diff -q "$d/$mode.json" "$base/$mode.json" >/dev/null; then
      echo
      echo "### ${d##*/out-} $mode vs NVIDIA package"
      echo '```diff'
      diff -u "$base/$mode.json" "$d/$mode.json"
      echo '```'
    fi
  done
done
