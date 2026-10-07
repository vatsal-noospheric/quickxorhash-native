from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import textwrap
import tomllib
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from tools import release_contract

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class ReleaseContractCliTests(unittest.TestCase):
    def test_repository_assembles_exactly_the_three_supported_wheels(self) -> None:
        with (REPOSITORY_ROOT / "Cargo.toml").open("rb") as source:
            version = tomllib.load(source)["package"]["version"]
        with tempfile.TemporaryDirectory() as temporary:
            distribution = Path(temporary)
            for platform_tag in (
                "macosx_11_0_arm64",
                "manylinux_2_17_aarch64.manylinux2014_aarch64",
                "manylinux_2_17_x86_64.manylinux2014_x86_64",
            ):
                _write_wheel(distribution, platform_tag, version=version)
            result = _run_contract(
                REPOSITORY_ROOT,
                "assemble",
                "--tag",
                f"v{version}",
                "--dist",
                str(distribution),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                len((distribution / "SHA256SUMS").read_text().splitlines()), 3
            )
            _write_wheel(distribution, "macosx_10_12_x86_64", version=version)
            rejected = _run_contract(
                REPOSITORY_ROOT,
                "assemble",
                "--tag",
                f"v{version}",
                "--dist",
                str(distribution),
            )
            self.assertEqual(rejected.returncode, 2, rejected.stderr)

    def test_env_builder_failure_preserves_wheel_install_failed_contract(self) -> None:
        error = subprocess.CalledProcessError(
            returncode=1,
            cmd=["python", "-m", "ensurepip"],
            stderr="ensurepip failed",
        )

        with mock.patch.object(release_contract.venv, "EnvBuilder") as env_builder:
            env_builder.return_value.create.side_effect = error

            with self.assertRaises(release_contract.ReleaseContractError) as context:
                release_contract._run_installed_wheel_smoke(Path("unused.whl"), "2.0.0")

        self.assertEqual(context.exception.code, "wheel_install_failed")

    def test_preflight_accepts_matching_source_version_and_tag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            _write_source_contract(repository)

            result = _run_contract(repository, "preflight", "--tag", "v2.0.0")

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("release source verified: v2.0.0", result.stdout)

    def test_preflight_rejects_a_mismatched_release_tag_before_builds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            _write_source_contract(repository)

            result = _run_contract(repository, "preflight", "--tag", "v2.0.1")

            self.assertEqual(result.returncode, 2)
            self.assertIn("version_mismatch", result.stderr)

    def test_assemble_accepts_exact_version_two_wheel_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            distribution = repository / "dist"
            distribution.mkdir()
            _write_source_contract(repository)
            expected_wheels = sorted(
                [
                    _write_wheel(distribution, "macosx_11_0_arm64"),
                    _write_wheel(
                        distribution,
                        "manylinux_2_17_aarch64.manylinux2014_aarch64",
                    ),
                ]
            )

            result = _run_contract(
                repository,
                "assemble",
                "--tag",
                "v2.0.0",
                "--dist",
                str(distribution),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            manifest_lines = (distribution / "SHA256SUMS").read_text().splitlines()
            self.assertEqual(
                [line.split("  ", 1)[1] for line in manifest_lines],
                [wheel.name for wheel in expected_wheels],
            )
            self.assertTrue(
                all(re.fullmatch(r"[0-9a-f]{64}  \S+", line) for line in manifest_lines)
            )

    def test_assemble_accepts_canonical_requires_python_whitespace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            distribution = repository / "dist"
            distribution.mkdir()
            _write_source_contract(repository)
            _write_wheel(
                distribution,
                "macosx_11_0_arm64",
                requires_python=">=3.14, <3.15",
            )
            _write_wheel(
                distribution,
                "manylinux_2_17_aarch64.manylinux2014_aarch64",
                requires_python=">=3.14, <3.15",
            )

            result = _run_contract(
                repository,
                "assemble",
                "--tag",
                "v2.0.0",
                "--dist",
                str(distribution),
            )

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_assemble_rejects_different_requires_python_range(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            distribution = repository / "dist"
            distribution.mkdir()
            _write_source_contract(repository)
            _write_wheel(
                distribution,
                "macosx_11_0_arm64",
                requires_python=">=3.13, <3.15",
            )
            _write_wheel(
                distribution,
                "manylinux_2_17_aarch64.manylinux2014_aarch64",
            )

            result = _run_contract(
                repository,
                "assemble",
                "--tag",
                "v2.0.0",
                "--dist",
                str(distribution),
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("package_mismatch", result.stderr)

    def test_verify_wheel_rejects_a_wheel_for_another_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            distribution = repository / "dist"
            distribution.mkdir()
            _write_source_contract(repository)
            linux_wheel = _write_wheel(
                distribution,
                "manylinux_2_17_aarch64.manylinux2014_aarch64",
            )

            result = _run_contract(
                repository,
                "verify-wheel",
                "--target",
                "macos-arm64",
                str(linux_wheel),
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("target_mismatch", result.stderr)

    def test_assemble_rejects_source_distributions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            distribution = repository / "dist"
            distribution.mkdir()
            _write_source_contract(repository)
            _write_wheel(distribution, "macosx_11_0_arm64")
            _write_wheel(
                distribution,
                "manylinux_2_17_aarch64.manylinux2014_aarch64",
            )
            (distribution / "quickxorhash-native-2.0.0.tar.gz").write_bytes(b"")

            result = _run_contract(
                repository,
                "assemble",
                "--tag",
                "v2.0.0",
                "--dist",
                str(distribution),
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("sdist_forbidden", result.stderr)

    def test_assemble_rejects_internal_tag_disagreement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            distribution = repository / "dist"
            distribution.mkdir()
            _write_source_contract(repository)
            _write_wheel(
                distribution,
                "macosx_11_0_arm64",
                internal_platform_tag="macosx_12_0_arm64",
            )
            _write_wheel(
                distribution,
                "manylinux_2_17_aarch64.manylinux2014_aarch64",
            )

            result = _run_contract(
                repository,
                "assemble",
                "--tag",
                "v2.0.0",
                "--dist",
                str(distribution),
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("invalid_wheel_tag", result.stderr)

    def test_assemble_rejects_a_stale_checksum_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            distribution = repository / "dist"
            distribution.mkdir()
            _write_source_contract(repository)
            _write_wheel(distribution, "macosx_11_0_arm64")
            _write_wheel(
                distribution,
                "manylinux_2_17_aarch64.manylinux2014_aarch64",
            )
            (distribution / "SHA256SUMS").write_text("0" * 64 + "  stale.whl\n")

            result = _run_contract(
                repository,
                "assemble",
                "--tag",
                "v2.0.0",
                "--dist",
                str(distribution),
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("checksum_mismatch", result.stderr)

    def test_assemble_rejects_a_wheel_without_type_support(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            distribution = repository / "dist"
            distribution.mkdir()
            _write_source_contract(repository)
            _write_wheel(
                distribution,
                "macosx_11_0_arm64",
                include_type_support=False,
            )
            _write_wheel(
                distribution,
                "manylinux_2_17_aarch64.manylinux2014_aarch64",
            )

            result = _run_contract(
                repository,
                "assemble",
                "--tag",
                "v2.0.0",
                "--dist",
                str(distribution),
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("invalid_wheel", result.stderr)
            self.assertIn("type-support", result.stderr)

    def test_assemble_rejects_a_stale_cargo_lock_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            distribution = repository / "dist"
            distribution.mkdir()
            _write_source_contract(repository)
            (repository / "Cargo.lock").write_text(
                textwrap.dedent(
                    """
                    version = 4

                    [[package]]
                    name = "quickxorhash-native"
                    version = "0.2.0"
                    """
                ).lstrip()
            )
            _write_wheel(distribution, "macosx_11_0_arm64")
            _write_wheel(
                distribution,
                "manylinux_2_17_aarch64.manylinux2014_aarch64",
            )

            result = _run_contract(
                repository,
                "assemble",
                "--tag",
                "v2.0.0",
                "--dist",
                str(distribution),
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("source_mismatch", result.stderr)
            self.assertIn("Cargo.lock", result.stderr)


def _run_contract(
    repository: Path, *arguments: str
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPOSITORY_ROOT)
    return subprocess.run(
        [sys.executable, "-m", "tools.release_contract", *arguments],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def _write_source_contract(repository: Path) -> None:
    (repository / "Cargo.toml").write_text(
        textwrap.dedent(
            """
            [package]
            name = "quickxorhash-native"
            version = "2.0.0"

            [dependencies]
            pyo3 = { version = "0.29.0", features = ["abi3-py314"] }
            """
        ).lstrip()
    )
    (repository / "pyproject.toml").write_text(
        textwrap.dedent(
            """
            [project]
            name = "quickxorhash-native"
            requires-python = ">=3.14,<3.15"
            dynamic = ["version"]

            [tool.quickxorhash.release]
            requires-python = ">=3.14,<3.15"
            abi3-feature = "abi3-py314"
            sdist = false

            [tool.quickxorhash.release.targets.macos-arm64]
            platform-tags = ["macosx_11_0_arm64"]

            [tool.quickxorhash.release.targets.manylinux-aarch64]
            platform-tags = ["manylinux_2_17_aarch64", "manylinux2014_aarch64"]
            """
        ).lstrip()
    )
    (repository / "Cargo.lock").write_text(
        textwrap.dedent(
            """
            version = 4

            [[package]]
            name = "quickxorhash-native"
            version = "2.0.0"
            """
        ).lstrip()
    )


def _write_wheel(
    distribution: Path,
    platform_tag: str,
    *,
    internal_platform_tag: str | None = None,
    include_type_support: bool = True,
    requires_python: str = ">=3.14,<3.15",
    version: str = "2.0.0",
) -> Path:
    filename = f"quickxorhash_native-{version}-cp314-abi3-{platform_tag}.whl"
    wheel = distribution / filename
    dist_info = f"quickxorhash_native-{version}.dist-info"
    internal_platform_tag = internal_platform_tag or platform_tag
    wheel_tags = "\n".join(
        f"Tag: cp314-abi3-{tag}" for tag in internal_platform_tag.split(".")
    )
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("quickxorhash_native.abi3.so", b"native-extension-placeholder")
        if include_type_support:
            archive.writestr("quickxorhash_native.pyi", b"")
            archive.writestr("py.typed", b"")
        archive.writestr(
            f"{dist_info}/METADATA",
            textwrap.dedent(
                """
                Metadata-Version: 2.4
                Name: quickxorhash-native
                Version: {version}
                Requires-Python: {requires_python}
                """
            )
            .lstrip()
            .format(requires_python=requires_python, version=version),
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\n"
            "Generator: test\n"
            "Root-Is-Purelib: false\n"
            f"{wheel_tags}\n",
        )
    return wheel


if __name__ == "__main__":
    unittest.main()
