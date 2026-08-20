#!/usr/bin/env bash
set -euo pipefail
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repository_root"
npm --prefix docs/spec/vectors/generator ci
npm --prefix docs/spec/conformance ci
npm --prefix docs/spec/vectors/generator run family:check
npm --prefix docs/spec/vectors/generator run check
npm --prefix docs/spec/conformance run check -- "$repository_root"
