#!/usr/bin/env bash
# Build and verify an isolated two-wheel release candidate; never publish it.
set -euo pipefail
umask 022

if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
  echo 'Usage: build_arm_wheels.sh [new-output-directory]'
  echo 'Build and verify macOS ARM64 + manylinux ARM64 wheels for the declared version.'
  echo 'Requires macOS ARM64, OrbStack Docker, Python 3.14, uv and Rust 1.97.1.'
  exit 0
fi

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for command_name in python3.14 uv docker rsync; do
  command -v "$command_name" >/dev/null || { echo "Missing $command_name" >&2; exit 1; }
done
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || {
  echo "Run this combined build on macOS ARM64 with an ARM64 Docker runtime." >&2; exit 1;
}
version="$(python3.14 - "$project_root/Cargo.toml" <<'PY'
import sys, tomllib
with open(sys.argv[1], 'rb') as source:
    print(tomllib.load(source)['package']['version'])
PY
)"
output_directory="${1:-$project_root/dist/releases/$version-arm64}"
output_directory="$(python3.14 - "$output_directory" <<'PY'
import sys
from pathlib import Path
print(Path(sys.argv[1]).resolve())
PY
)"
[[ ! -e "$output_directory" ]] || {
  echo "Output already exists; choose a new directory: $output_directory" >&2; exit 1;
}
mac_rust_bin="${ARM_WHEEL_MAC_RUST_BIN:-$project_root/dist/arm-builder-cache/macos-rust-1.97.1/bin}"
[[ "$("$mac_rust_bin/rustc" --version)" == rustc\ 1.97.1\ * ]] || {
  echo "Set ARM_WHEEL_MAC_RUST_BIN to a Rust 1.97.1 bin directory." >&2; exit 1;
}
linux_image='ghcr.io/pyo3/maturin@sha256:9f84fbea151ae578388e474eee6087867875fa3adfb11b572fa44150c65254ee'
evidence_directory="$project_root/dist/build-evidence/$(date -u +%Y%m%dT%H%M%SZ)-$version"
source_directory="$evidence_directory/source"
wheel_directory="$evidence_directory/wheels"
cache_directory="$project_root/dist/arm-builder-cache"
mkdir -p "$source_directory" "$wheel_directory" "$cache_directory/cargo" "$cache_directory/rustup"
rsync -a --exclude '/.git/' --exclude '/target/' --exclude '/dist/' \
  --exclude '/.venv/' --exclude '/.scratch/' --exclude '/backlog/' \
  --exclude '/.pytest_cache/' --exclude '/.ruff_cache/' --exclude '__pycache__/' \
  --exclude '.env*' "$project_root/" "$source_directory/"
python3.14 - "$source_directory" "$evidence_directory/source-sha256.json" <<'PY'
import hashlib, json, sys
from pathlib import Path
root = Path(sys.argv[1])
checksums = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(root.rglob('*')) if p.is_file()}
Path(sys.argv[2]).write_text(json.dumps(checksums, indent=2) + '\n')
PY

uv venv "$evidence_directory/mac-venv" --python "$(command -v python3.14)"
mac_python="$evidence_directory/mac-venv/bin/python"
uv pip install --python "$mac_python" 'maturin==1.14.1' 'pytest==9.1.1' 'ruff==0.16.3'
export PATH="$mac_rust_bin:$PATH"
export RUSTC="$mac_rust_bin/rustc"
export CARGO_TARGET_DIR="$evidence_directory/mac-target"
export MACOSX_DEPLOYMENT_TARGET=11.0
export PYO3_PYTHON="$mac_python"
export PYTHONDONTWRITEBYTECODE=1
(
  cd "$source_directory"
  "$mac_python" -m tools.release_contract preflight --tag "v$version"
  "$evidence_directory/mac-venv/bin/ruff" check .
  "$evidence_directory/mac-venv/bin/ruff" format --check .
  cargo fmt --check
  cargo clippy --locked --all-targets -- -D warnings
  cargo test --locked
  "$evidence_directory/mac-venv/bin/maturin" build --release --locked \
    --target aarch64-apple-darwin --interpreter "$mac_python" --out "$wheel_directory"
  mac_wheel="$wheel_directory/quickxorhash_native-$version-cp314-abi3-macosx_11_0_arm64.whl"
  "$mac_python" -m tools.release_contract verify-wheel --target macos-arm64 "$mac_wheel"
  uv pip install --python "$mac_python" --no-index --no-deps "$mac_wheel"
  "$mac_python" -m pytest -p no:cacheprovider
) 2>&1 | tee "$evidence_directory/macos.log"

# Rust 1.97.1 and Python CPython 3.14 with the GIL; never select cp314t.
docker run --rm -i --platform linux/arm64 --entrypoint /bin/bash \
  --mount "type=bind,source=$source_directory,target=/source,readonly" \
  --mount "type=bind,source=$wheel_directory,target=/wheels" \
  --mount "type=bind,source=$cache_directory,target=/cache" \
  -e CARGO_HOME=/cache/cargo -e RUSTUP_HOME=/cache/rustup \
  -e RUSTUP_TOOLCHAIN=1.97.1 -e ARM_WHEEL_VERSION="$version" \
  "$linux_image" -s <<'LINUX' 2>&1 | tee "$evidence_directory/linux.log"
set -euo pipefail
[[ "$(uname -m)" == aarch64 ]]
[[ "$(getconf GNU_LIBC_VERSION)" == 'glibc 2.17' ]]
[[ "$(maturin --version)" == 'maturin 1.14.1' ]]
rustup toolchain install 1.97.1 --profile minimal --component rustfmt,clippy --no-self-update
rustc --version
cargo --version
mkdir /work
cp -a /source/. /work/
cd /work
uv venv /work/venv --python /opt/python/cp314-cp314/bin/python
uv pip install --python /work/venv/bin/python 'pytest==9.1.1' 'ruff==0.16.3'
export PYO3_PYTHON=/work/venv/bin/python
export PYTHONDONTWRITEBYTECODE=1
/work/venv/bin/python -c 'import sys; assert sys._is_gil_enabled(); print(sys.version)'
/work/venv/bin/python -m tools.release_contract preflight --tag "v$ARM_WHEEL_VERSION"
/work/venv/bin/ruff check .
/work/venv/bin/ruff format --check .
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --features pyo3/extension-module
maturin build --release --locked --target aarch64-unknown-linux-gnu \
  --interpreter /work/venv/bin/python --compatibility manylinux2014 --out /wheels
linux_wheel="/wheels/quickxorhash_native-$ARM_WHEEL_VERSION-cp314-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl"
/work/venv/bin/python -m tools.release_contract verify-wheel \
  --target manylinux-aarch64 "$linux_wheel"
uv pip install --python /work/venv/bin/python --no-index --no-deps "$linux_wheel"
/work/venv/bin/python -m pytest -p no:cacheprovider
LINUX

(
  cd "$source_directory"
  "$mac_python" -m tools.release_contract assemble --tag "v$version" --dist "$wheel_directory"
)
mkdir -p "$output_directory"
cp "$wheel_directory/"* "$output_directory/"
python3.14 - "$output_directory" "$evidence_directory" "$linux_image" <<'PY'
import json, sys
from pathlib import Path
output, evidence = map(Path, sys.argv[1:3])
(evidence / 'build.json').write_text(json.dumps({
    'artifacts': str(output), 'evidence': str(evidence),
    'linux_image': sys.argv[3], 'rust': '1.97.1', 'maturin': '1.14.1',
    'targets': ['macos-arm64', 'manylinux-aarch64'], 'published': False,
}, indent=2) + '\n')
PY
printf 'Verified wheels: %s\nBuild evidence: %s\n' "$output_directory" "$evidence_directory"
