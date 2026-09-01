#!/usr/bin/env bash
set -euo pipefail
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repository_root"
tracked_status_before="$(git status --porcelain=v1 --untracked-files=no)"
unstaged_state_before="$(git diff --binary --no-ext-diff --)"
index_state_before="$(git diff --cached --binary --no-ext-diff --)"
npm --prefix docs/spec/vectors/generator ci
npm --prefix docs/spec/conformance ci
npm --prefix docs/spec/vectors/generator run draft:check -- "$repository_root"
npm --prefix docs/spec/vectors/generator run snapshot-check -- "$repository_root"
npm --prefix docs/spec/vectors/generator run test:snapshot-manifest
npm --prefix docs/spec/conformance run build
npm --prefix docs/spec/conformance test
tracked_status_after="$(git status --porcelain=v1 --untracked-files=no)"
unstaged_state_after="$(git diff --binary --no-ext-diff --)"
index_state_after="$(git diff --cached --binary --no-ext-diff --)"
if [[ "$tracked_status_after" != "$tracked_status_before" || "$unstaged_state_after" != "$unstaged_state_before" || "$index_state_after" != "$index_state_before" ]]; then
  echo "conformance CI mutated tracked or index state" >&2
  exit 1
fi
