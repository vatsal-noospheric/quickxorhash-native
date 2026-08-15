"""Validate QuickXorHash Native release artefacts against repository policy."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import venv
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path

WHEEL_FILENAME = re.compile(
    r"^(?P<distribution>.+)-(?P<version>[^-]+)-(?P<python>[^-]+)-"
    r"(?P<abi>[^-]+)-(?P<platform>[^-]+)\.whl$"
)
SMOKE_TEST = """
import base64
import hashlib
import sys
from pathlib import Path

from quickxorhash_native import (
    __version__,
    BLOCK_SIZE,
    DEFAULT_HASH_BUFFER_SIZE,
    HASH_CHECKPOINT_VERSION,
    FileHashAccumulator,
    calculate_file_hashes,
)

assert __version__ == sys.argv[1]
assert BLOCK_SIZE == 160
assert DEFAULT_HASH_BUFFER_SIZE > 0
assert HASH_CHECKPOINT_VERSION > 0

payload = (b"quickxorhash-native" * 19) + b"\\x00\\x01"
uninterrupted = FileHashAccumulator()
uninterrupted.update(payload)

checkpointed = FileHashAccumulator()
checkpointed.update(payload[:37])
restored = FileHashAccumulator.restore(checkpointed.snapshot())
restored.update(payload[37:])
assert restored.finalise() == uninterrupted.finalise()

path = Path("release-contract-smoke.bin")
path.write_bytes(payload)
expected = uninterrupted.finalise()
assert calculate_file_hashes(str(path)) == expected
assert set(expected) == {"size", "sha1_hash", "quick_xor_hash"}
assert expected["size"] == len(payload)
assert expected["sha1_hash"] == hashlib.sha1(payload).hexdigest()
assert len(base64.b64decode(expected["quick_xor_hash"], validate=True)) == 20

for buffer_size in (1, 17, 160, 161):
    assert calculate_file_hashes(str(path), buffer_size=buffer_size) == expected

prefix = payload[:73]
prefix_accumulator = FileHashAccumulator()
prefix_accumulator.update(prefix)
assert calculate_file_hashes(str(path), stop_after=73, buffer_size=11) == (
    prefix_accumulator.finalise()
)

empty = Path("release-contract-empty.bin")
empty.write_bytes(b"")
empty_metadata = calculate_file_hashes(str(empty))
assert empty_metadata["size"] == 0
assert empty_metadata["sha1_hash"] == hashlib.sha1(b"").hexdigest()

try:
    calculate_file_hashes(str(path), buffer_size=0)
except OSError:
    pass
else:
    raise AssertionError("zero buffer size did not raise OSError")

try:
    FileHashAccumulator.restore("not-a-checkpoint")
except ValueError:
    pass
else:
    raise AssertionError("invalid checkpoint did not raise ValueError")
"""


class ReleaseContractError(Exception):
    """A release candidate violates a named contract invariant."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code

    def __str__(self) -> str:
        return f"{self.code}: {super().__str__()}"


@dataclass(frozen=True)
class WheelTarget:
    """One accepted operating-system and architecture wheel target."""

    name: str
    platform_tags: frozenset[str]


@dataclass(frozen=True)
class ReleasePolicy:
    """Repository-owned release invariants resolved from source metadata."""

    distribution: str
    version: str
    requires_python: str
    python_tag: str
    abi_tag: str
    targets: tuple[WheelTarget, ...]


@dataclass(frozen=True)
class WheelEvidence:
    """Validated identity extracted from a wheel filename and archive."""

    path: Path
    target: WheelTarget


def load_release_policy(repository: Path) -> ReleasePolicy:
    """Load and cross-check the source metadata that defines a release."""

    cargo = _read_toml(repository / "Cargo.toml")
    cargo_lock = _read_toml(repository / "Cargo.lock")
    pyproject = _read_toml(repository / "pyproject.toml")
    try:
        package = cargo["package"]
        project = pyproject["project"]
        release = pyproject["tool"]["quickxorhash"]["release"]
        pyo3 = cargo["dependencies"]["pyo3"]
    except (KeyError, TypeError) as error:
        raise ReleaseContractError(
            "invalid_contract", f"required source metadata is missing: {error}"
        ) from error

    distribution = _required_string(project, "name")
    version = _required_string(package, "version")
    locked_packages = cargo_lock.get("package")
    if not isinstance(locked_packages, list):
        raise ReleaseContractError(
            "invalid_contract", "Cargo.lock contains no package list"
        )
    matching_locked_packages = [
        locked_package
        for locked_package in locked_packages
        if isinstance(locked_package, dict)
        and locked_package.get("name") == distribution
    ]
    if len(matching_locked_packages) != 1:
        raise ReleaseContractError(
            "invalid_contract",
            f"Cargo.lock must contain exactly one {distribution} package",
        )
    if matching_locked_packages[0].get("version") != version:
        raise ReleaseContractError(
            "source_mismatch",
            f"Cargo.lock version does not match Cargo.toml version {version}",
        )

    requires_python = _required_string(release, "requires-python")
    if project.get("requires-python") != requires_python:
        raise ReleaseContractError(
            "source_mismatch",
            "project requires-python does not match the release policy",
        )
    if release.get("sdist") is not False:
        raise ReleaseContractError(
            "invalid_contract", "native-only releases must set sdist = false"
        )

    abi3_feature = _required_string(release, "abi3-feature")
    pyo3_features = pyo3.get("features", ()) if isinstance(pyo3, dict) else ()
    if abi3_feature not in pyo3_features:
        raise ReleaseContractError(
            "source_mismatch",
            f"PyO3 features do not include release ABI feature {abi3_feature}",
        )
    feature_match = re.fullmatch(r"abi3-py(?P<digits>\d+)", abi3_feature)
    if feature_match is None:
        raise ReleaseContractError(
            "invalid_contract", f"unsupported ABI3 feature {abi3_feature}"
        )

    targets_data = release.get("targets")
    if not isinstance(targets_data, dict) or not targets_data:
        raise ReleaseContractError("invalid_contract", "release targets are missing")
    targets = tuple(
        WheelTarget(
            name=name,
            platform_tags=frozenset(_required_string_list(value, "platform-tags")),
        )
        for name, value in sorted(targets_data.items())
    )

    return ReleasePolicy(
        distribution=distribution,
        version=version,
        requires_python=requires_python,
        python_tag=f"cp{feature_match.group('digits')}",
        abi_tag="abi3",
        targets=targets,
    )


def inspect_wheel(path: Path, policy: ReleasePolicy) -> WheelEvidence:
    """Validate wheel identity and metadata without executing its extension."""

    match = WHEEL_FILENAME.fullmatch(path.name)
    if match is None:
        raise ReleaseContractError(
            "invalid_wheel_tag", f"wheel filename is not supported: {path.name}"
        )

    distribution = _normalise_distribution(match.group("distribution"))
    if distribution != _normalise_distribution(policy.distribution):
        raise ReleaseContractError(
            "package_mismatch",
            f"wheel distribution {distribution} is not {policy.distribution}",
        )
    if match.group("version") != policy.version:
        raise ReleaseContractError(
            "version_mismatch",
            f"wheel {path.name} does not contain version {policy.version}",
        )

    python_tags = frozenset(match.group("python").split("."))
    abi_tags = frozenset(match.group("abi").split("."))
    platform_tags = frozenset(match.group("platform").split("."))
    if python_tags != {policy.python_tag} or abi_tags != {policy.abi_tag}:
        raise ReleaseContractError(
            "invalid_wheel_tag",
            f"wheel {path.name} must use {policy.python_tag}-{policy.abi_tag}",
        )

    matching_targets = [
        target
        for target in policy.targets
        if platform_tags <= target.platform_tags
        and bool(platform_tags & target.platform_tags)
    ]
    if len(matching_targets) != 1:
        raise ReleaseContractError(
            "unsupported_target",
            f"wheel {path.name} has unsupported platform tags {sorted(platform_tags)}",
        )

    expected_tags = {
        f"{python_tag}-{abi_tag}-{platform_tag}"
        for python_tag in python_tags
        for abi_tag in abi_tags
        for platform_tag in platform_tags
    }
    _inspect_wheel_archive(path, policy, expected_tags)
    return WheelEvidence(path=path, target=matching_targets[0])


def verify_wheel(repository: Path, path: Path, target_name: str) -> WheelEvidence:
    """Verify one native wheel at its declared target and execute its interface."""

    policy = load_release_policy(repository)
    expected_target = next(
        (target for target in policy.targets if target.name == target_name), None
    )
    if expected_target is None:
        raise ReleaseContractError(
            "unsupported_target", f"release policy has no target {target_name}"
        )
    evidence = inspect_wheel(path, policy)
    if evidence.target != expected_target:
        raise ReleaseContractError(
            "target_mismatch",
            f"wheel {path.name} is for {evidence.target.name}, not {target_name}",
        )
    _run_installed_wheel_smoke(path, policy.version)
    return evidence


def verify_release_preflight(repository: Path, tag: str) -> ReleasePolicy:
    """Validate source metadata and the requested release tag before builds."""

    policy = load_release_policy(repository)
    expected_tag = f"v{policy.version}"
    if tag != expected_tag:
        raise ReleaseContractError(
            "version_mismatch", f"release tag {tag} must be {expected_tag}"
        )
    return policy


def assemble_release_bundle(repository: Path, distribution: Path, tag: str) -> Path:
    """Verify the exact release asset set and create its SHA-256 manifest."""

    policy = verify_release_preflight(repository, tag)
    if not distribution.is_dir():
        raise ReleaseContractError(
            "missing_asset", f"distribution directory does not exist: {distribution}"
        )

    entries = sorted(path for path in distribution.iterdir() if path.is_file())
    source_distributions = [
        path for path in entries if path.name.endswith((".tar.gz", ".zip"))
    ]
    if source_distributions:
        raise ReleaseContractError(
            "sdist_forbidden",
            f"source distributions are forbidden: {source_distributions[0].name}",
        )
    unexpected = [
        path for path in entries if path.suffix != ".whl" and path.name != "SHA256SUMS"
    ]
    if unexpected:
        raise ReleaseContractError(
            "unexpected_asset", f"unexpected release asset: {unexpected[0].name}"
        )

    wheels = [path for path in entries if path.suffix == ".whl"]
    if len(wheels) != len(policy.targets):
        raise ReleaseContractError(
            "missing_asset",
            f"expected {len(policy.targets)} wheels, found {len(wheels)}",
        )
    evidence = [inspect_wheel(path, policy) for path in wheels]
    observed_targets = [item.target.name for item in evidence]
    if len(set(observed_targets)) != len(observed_targets):
        raise ReleaseContractError(
            "duplicate_asset", f"duplicate target wheel: {observed_targets}"
        )
    expected_targets = {target.name for target in policy.targets}
    if set(observed_targets) != expected_targets:
        expected = sorted(expected_targets)
        observed = sorted(observed_targets)
        raise ReleaseContractError(
            "missing_asset",
            f"expected targets {expected}, found {observed}",
        )

    manifest = distribution / "SHA256SUMS"
    manifest_content = "".join(
        f"{_sha256(path)}  {path.name}\n" for path in sorted(wheels)
    )
    if manifest.exists():
        if manifest.read_text() != manifest_content:
            raise ReleaseContractError(
                "checksum_mismatch", "existing SHA256SUMS does not match wheel bytes"
            )
    else:
        temporary_manifest = distribution / ".SHA256SUMS.tmp"
        temporary_manifest.write_text(manifest_content)
        os.replace(temporary_manifest, manifest)
    return manifest


def _inspect_wheel_archive(
    path: Path, policy: ReleasePolicy, expected_tags: set[str]
) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            metadata_name = _unique_member(names, ".dist-info/METADATA", path)
            wheel_name = _unique_member(names, ".dist-info/WHEEL", path)
            metadata = BytesParser().parsebytes(archive.read(metadata_name))
            wheel_metadata = BytesParser().parsebytes(archive.read(wheel_name))
    except (OSError, zipfile.BadZipFile) as error:
        raise ReleaseContractError(
            "invalid_wheel", f"cannot inspect wheel {path.name}: {error}"
        ) from error

    if _normalise_distribution(metadata.get("Name", "")) != _normalise_distribution(
        policy.distribution
    ):
        raise ReleaseContractError(
            "package_mismatch", f"wheel metadata name is invalid in {path.name}"
        )
    if metadata.get("Version") != policy.version:
        raise ReleaseContractError(
            "version_mismatch", f"wheel metadata version is invalid in {path.name}"
        )
    wheel_requires_python = metadata.get("Requires-Python", "")
    if _normalise_version_specifiers(
        wheel_requires_python
    ) != _normalise_version_specifiers(policy.requires_python):
        raise ReleaseContractError(
            "package_mismatch",
            f"wheel Requires-Python must be {policy.requires_python} in {path.name}",
        )
    internal_tags = set(wheel_metadata.get_all("Tag", ()))
    if internal_tags != expected_tags:
        raise ReleaseContractError(
            "invalid_wheel_tag",
            f"wheel filename and internal tags disagree in {path.name}",
        )
    if not any(name.endswith(".abi3.so") for name in names):
        raise ReleaseContractError(
            "invalid_wheel", f"wheel contains no ABI3 native extension: {path.name}"
        )
    member_basenames = {Path(name).name for name in names}
    required_type_support = {"quickxorhash_native.pyi", "py.typed"}
    missing_type_support = required_type_support - member_basenames
    if missing_type_support:
        raise ReleaseContractError(
            "invalid_wheel",
            f"wheel {path.name} lacks type-support files "
            f"{sorted(missing_type_support)}",
        )


def _run_installed_wheel_smoke(path: Path, expected_version: str) -> None:
    if sys.version_info[:2] != (3, 14):
        raise ReleaseContractError(
            "wheel_install_failed",
            "installed-wheel verification requires CPython 3.14",
        )
    with tempfile.TemporaryDirectory(prefix="quickxorhash-wheel-") as temporary:
        environment_root = Path(temporary)
        virtual_environment = environment_root / "venv"
        try:
            venv.EnvBuilder(with_pip=True, clear=True).create(virtual_environment)
        except (OSError, subprocess.CalledProcessError) as error:
            raise ReleaseContractError(
                "wheel_install_failed", f"cannot create clean environment: {error}"
            ) from error

        scripts = virtual_environment / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")
        environment = os.environ.copy()
        environment["PATH"] = os.pathsep.join(
            [str(scripts), "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        )
        environment.pop("PYTHONPATH", None)
        if shutil.which("cargo", path=environment["PATH"]) or shutil.which(
            "rustc", path=environment["PATH"]
        ):
            raise ReleaseContractError(
                "wheel_install_failed", "Rust remains available in smoke-test PATH"
            )

        install = subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                "--only-binary=:all:",
                str(path.resolve()),
            ],
            cwd=environment_root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        if install.returncode != 0:
            raise ReleaseContractError(
                "wheel_install_failed",
                _subprocess_failure("wheel installation", install),
            )
        smoke = subprocess.run(
            [str(python), "-I", "-c", SMOKE_TEST, expected_version],
            cwd=environment_root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        if smoke.returncode != 0:
            raise ReleaseContractError(
                "public_interface_failed",
                _subprocess_failure("installed-wheel interface", smoke),
            )


def _subprocess_failure(
    operation: str, result: subprocess.CompletedProcess[str]
) -> str:
    output = "\n".join(
        part.strip() for part in (result.stdout, result.stderr) if part.strip()
    )
    return f"{operation} failed with exit {result.returncode}: {output}"


def _read_toml(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ReleaseContractError(
            "invalid_contract", f"cannot read {path.name}: {error}"
        ) from error


def _required_string(mapping: object, key: str) -> str:
    if not isinstance(mapping, dict) or not isinstance(mapping.get(key), str):
        raise ReleaseContractError("invalid_contract", f"{key} must be a string")
    return mapping[key]


def _required_string_list(mapping: object, key: str) -> tuple[str, ...]:
    if not isinstance(mapping, dict):
        raise ReleaseContractError("invalid_contract", f"{key} must be a list")
    value = mapping.get(key)
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) for item in value)
    ):
        raise ReleaseContractError(
            "invalid_contract", f"{key} must be a non-empty string list"
        )
    return tuple(value)


def _unique_member(names: list[str], suffix: str, path: Path) -> str:
    matches = [name for name in names if name.endswith(suffix)]
    if len(matches) != 1:
        raise ReleaseContractError(
            "invalid_wheel",
            f"wheel {path.name} must contain exactly one {suffix} member",
        )
    return matches[0]


def _normalise_distribution(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _normalise_version_specifiers(value: str) -> str:
    return ",".join(specifier.strip() for specifier in value.split(","))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="release-contract")
    subparsers = parser.add_subparsers(dest="command", required=True)
    assemble = subparsers.add_parser("assemble")
    assemble.add_argument("--tag", required=True)
    assemble.add_argument("--dist", type=Path, required=True)
    preflight = subparsers.add_parser("preflight")
    preflight.add_argument("--tag", required=True)
    verify = subparsers.add_parser("verify-wheel")
    verify.add_argument("--target", required=True)
    verify.add_argument("wheel", type=Path)
    return parser


def main(arguments: list[str] | None = None) -> int:
    """Run the release-contract command interface."""

    options = _build_parser().parse_args(arguments)
    try:
        if options.command == "preflight":
            policy = verify_release_preflight(Path.cwd(), options.tag)
            print(f"release source verified: v{policy.version}")
            return 0
        if options.command == "assemble":
            manifest = assemble_release_bundle(
                Path.cwd(), options.dist.resolve(), options.tag
            )
            print(f"release bundle verified: {manifest}")
            return 0
        if options.command == "verify-wheel":
            evidence = verify_wheel(Path.cwd(), options.wheel.resolve(), options.target)
            print(f"wheel verified for {evidence.target.name}: {evidence.path}")
            return 0
    except ReleaseContractError as error:
        print(error, file=sys.stderr)
        return 2
    raise AssertionError(f"unhandled command: {options.command}")


if __name__ == "__main__":
    raise SystemExit(main())
