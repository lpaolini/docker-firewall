#!/usr/bin/env bash
# Print the Debian package version for the checked-out commit:
#   exactly on tag vX.Y.Z -> X.Y.Z
#   N commits after it    -> X.Y.Z+devN.g<sha>
#   no release tag yet    -> 0.0.0+devN.g<sha>, N counting from the first commit
# A dev version sorts after its last release and before the next one, and
# grows with every commit on a linear branch, so apt always upgrades to it.
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

if ! desc="$(git -C "${ROOT}" describe --tags --long --match 'v[0-9]*' 2>/dev/null)"; then
  echo "0.0.0+dev$(git -C "${ROOT}" rev-list --count HEAD).g$(git -C "${ROOT}" rev-parse --short HEAD)"
  exit 0
fi

tag="${desc%-*-g*}"          # v0.1.0-5-gabc1234 -> v0.1.0
rest="${desc#"${tag}"-}"     # 5-gabc1234
count="${rest%%-*}"
sha="${rest#*-g}"

if [[ "${count}" = 0 ]]; then
  echo "${tag#v}"
else
  echo "${tag#v}+dev${count}.g${sha}"
fi
