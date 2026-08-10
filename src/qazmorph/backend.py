"""Resource discovery and subprocess boundary for the finite-state backend."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
from typing import Any
import unicodedata

from .platform_runtime import PlatformRuntimeError, resolve_platform_runtime


class BackendError(RuntimeError):
    pass


APERTIUM_RESERVED = frozenset("\\^$/<>{}[]@#*+")
ORTHOGRAPHIC_HYPHENS = frozenset("-\u2010\u2011")
DASH_PUNCTUATION = frozenset("\u2012\u2013\u2014\u2212")
HYPHEN_LIKE = ORTHOGRAPHIC_HYPHENS
BOUNDARY_SUPERBLANK = "[]"
CONTROL_SUPERBLANKS = {
    "\x00": "[QAZMORPH-USER-NUL]",
    "\r": "[QAZMORPH-CARRIAGE-RETURN]",
}
PROTECTED_CHARACTERS = frozenset("\\^$/<>{}[]@#*+~|=&`")
RESOURCE_MANIFEST_V2 = "qazmorph-resource-manifest-v2"
RESOURCE_MANIFEST_V3 = "qazmorph-resource-manifest-v3"
RESOURCE_FILES_BY_SCHEMA = {
    RESOURCE_MANIFEST_V2: frozenset(
        {
            "kaz.automorf.hfstol",
            "kaz.autogen.hfstol",
            "kaz.guesser.automorf.hfst",
            "kaz.rlx.bin",
        }
    ),
    RESOURCE_MANIFEST_V3: frozenset(
        {
        "kaz.automorf.hfstol",
        "kaz.autogen.hfstol",
        "kaz.guesser.automorf.hfstol",
        "kaz.rlx.bin",
        }
    ),
}


def _protected_sentinel(character: str) -> str:
    return f"[QAZMORPH-U{ord(character):06X}]"


def _protected_stream_unit(character: str) -> str:
    escaped = escape_apertium_text(character)
    category = unicodedata.category(character)
    tag = "punct" if category.startswith("P") else "sym"
    sentence = "<sent>" if character in ".!?" else ""
    return f"^{escaped}/{escaped}<{tag}>{sentence}$"


def escape_apertium_text(text: str) -> str:
    """Quote raw user characters that are control syntax in Apertium streams."""

    return "".join(("\\" + char) if char in APERTIUM_RESERVED else char for char in text)


def _hyphen_chains(text: str) -> list[tuple[str, tuple[int, ...]]]:
    """Return alphanumeric/combining-mark chains containing internal dashes."""

    def component(character: str) -> bool:
        return character.isalnum() or unicodedata.category(character).startswith("M")

    chains: list[tuple[str, tuple[int, ...]]] = []
    cursor = 0
    while cursor < len(text):
        if not component(text[cursor]):
            cursor += 1
            continue
        start = cursor
        end = cursor + 1
        hyphens: list[int] = []
        while end < len(text):
            if component(text[end]):
                end += 1
                continue
            if (
                text[end] in HYPHEN_LIKE
                and end + 1 < len(text)
                and component(text[end + 1])
            ):
                hyphens.append(end)
                end += 2
                while end < len(text) and component(text[end]):
                    end += 1
                continue
            break
        if hyphens:
            chains.append((text[start:end], tuple(hyphens)))
        cursor = max(end, cursor + 1)
    return chains


def prepare_apertium_text(
    text: str, *, protected_hyphens: set[int] | frozenset[int] | None = None
) -> str:
    """Escape input and protect repeated hyphen chains from tokenizer loss.

    HFST's on-the-fly tokenizer can consume the letter material after an
    unknown prefix when the suffix is itself a known hyphenated lexical item
    (for example ``Има-а-а`` used to become ``Има--``).  Empty Apertium
    superblanks create zero-surface token boundaries.  The backend normally
    supplies the hyphens belonging to chains that a direct analyzer lookup
    proved unknown.  The standalone helper conservatively protects chains with
    at least three components, retaining ordinary two-part dictionary forms.

    Literal user brackets are escaped first and can therefore never be
    confused with the inserted control superblanks.
    """

    if protected_hyphens is None:
        protected_hyphens = {
            index
            for _surface, hyphens in _hyphen_chains(text)
            if len(hyphens) >= 2
            for index in hyphens
        }

    chunks: list[str] = []
    for index, char in enumerate(text):
        if char in CONTROL_SUPERBLANKS:
            chunks.append(CONTROL_SUPERBLANKS[char])
            continue
        if char in PROTECTED_CHARACTERS:
            chunks.append(_protected_sentinel(char))
            continue
        escaped = ("\\" + char) if char in APERTIUM_RESERVED else char
        if index in protected_hyphens:
            chunks.extend((BOUNDARY_SUPERBLANK, escaped, BOUNDARY_SUPERBLANK))
        else:
            chunks.append(escaped)
    return "".join(chunks)


def strip_boundary_superblanks(stream: str) -> str:
    """Restore zero-surface controls inserted by ``prepare_apertium_text``."""

    for character, sentinel in CONTROL_SUPERBLANKS.items():
        stream = stream.replace(sentinel, character)
    for character in PROTECTED_CHARACTERS:
        stream = stream.replace(
            _protected_sentinel(character), _protected_stream_unit(character)
        )
    return stream.replace(BOUNDARY_SUPERBLANK, "")


def _candidate_resource_dirs(explicit: str | os.PathLike[str] | None) -> list[Path]:
    candidates: list[Path] = []
    project_root = Path(__file__).resolve().parents[2]
    candidates.extend(
        (
            project_root / ".qazmorph" / "resources",
            Path.home() / ".cache" / "qazmorph" / "resources",
        )
    )
    return candidates


def _has_verified_v3_guesser_gate(manifest: dict[str, Any]) -> bool:
    try:
        result = manifest["build"]["verification"][
            "productive_guesser_finite_valued"
        ]["result"]
        graph = result["graph"]
        probes = result["no_cap_probes"]
        optimized = result["optimized_runtime"]
    except (KeyError, TypeError):
        return False

    def zero(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value == 0

    return (
        result.get("schema") == "qazmorph-guesser-finiteness-v1"
        and graph.get("reachable_input_epsilon_cycle") is False
        and probes.get("all_lemmas_match_bounded_root_relation") is True
        and zero(probes.get("cycle_markers"))
        and optimized.get("full_relation_equivalent_to_standard") is True
        and optimized.get("candidate_sets_equal_to_standard") is True
        and zero(optimized.get("cycle_markers"))
    )


class FSTBackend:
    _verified_toolchain_inventories: dict[
        tuple[str, str],
        tuple[tuple[str, int, int, int, int, int, int, str | None], ...],
    ] = {}

    def __init__(self, resource_dir: str | os.PathLike[str] | None = None) -> None:
        self.resource_dir = self._find_resource_dir(resource_dir)
        self.runtime_dir = self.resource_dir.parent
        self.analyzer_path = self.resource_dir / "kaz.automorf.hfstol"
        self.grammar_path = self.resource_dir / "kaz.rlx.bin"
        self.manifest = self._read_manifest()
        self._resource_inventory = self._verify_resource_inventory()
        self.guesser_optimized = self.manifest["schema"] == RESOURCE_MANIFEST_V3
        self.guesser_format = "optimized" if self.guesser_optimized else "standard"
        self.guesser_verified_finite = _has_verified_v3_guesser_gate(self.manifest)
        self.guesser_productive_safe = self.guesser_verified_finite
        self.guesser_safety_reason = (
            "resource v3 embeds the required finite optimized-guesser gate"
            if self.guesser_verified_finite
            else (
                "resource v3 finite-guesser proof is missing or invalid"
                if self.manifest["schema"] == RESOURCE_MANIFEST_V3
                else "legacy resource v2 has no verifiable finite-guesser gate"
            )
        )
        self.guesser_path = self.resource_dir / (
            "kaz.guesser.automorf.hfstol"
            if self.guesser_optimized
            else "kaz.guesser.automorf.hfst"
        )
        self._select_runtime_toolchain()
        self.toolchain_manifest = self._read_bound_toolchain_manifest()
        self._toolchain_inventory = self._verify_bound_toolchain_inventory()
        self._executable_origins: dict[str, str] = {}
        self._executable_verified: dict[str, bool] = {}
        self.environment = self._environment()
        self.hfst_proc = self._find_executable("hfst-proc", "QAZMORPH_HFST_PROC")
        self.cg_proc = self._find_executable("cg-proc", "QAZMORPH_CG_PROC", required=False)
        self.hfst_lookup = self._find_executable("hfst-lookup", "QAZMORPH_HFST_LOOKUP", required=False)
        self.hfst_optimized_lookup = self._find_executable(
            "hfst-optimized-lookup", "QAZMORPH_HFST_OPTIMIZED_LOOKUP", required=False
        )

    def _select_runtime_toolchain(self) -> None:
        """Select a locked native runtime or retain the resource build binding."""

        original = self.manifest.get("build", {}).get("toolchain")
        if not isinstance(original, dict):
            raise BackendError("Resource manifest has no valid toolchain binding")
        self.resource_build_toolchain_binding = dict(original)
        try:
            detached = resolve_platform_runtime(
                self.resource_dir, str(self.manifest.get("bundle_id", ""))
            )
        except PlatformRuntimeError as exc:
            raise BackendError(str(exc)) from exc
        if detached is None:
            self.toolchain_dir = self._resolve_toolchain_dir(self.manifest)
            self.toolchain_binding = dict(original)
            self.toolchain_origin = "resource-bound-toolchain"
            self.platform_runtime_lock_entry = None
            return
        self.toolchain_dir = detached.directory
        self.toolchain_binding = dict(detached.binding)
        self.toolchain_origin = detached.origin
        self.platform_runtime_lock_entry = dict(detached.lock_entry)

    @staticmethod
    def _find_resource_dir(explicit: str | os.PathLike[str] | None) -> Path:
        configured = explicit or os.environ.get("QAZMORPH_RESOURCE_DIR")
        if configured:
            candidate = Path(configured).expanduser().resolve()
            if (candidate / "kaz.automorf.hfstol").is_file():
                return candidate
            raise BackendError(f"Configured resource directory is invalid: {candidate}")
        checked: list[str] = []
        for candidate in _candidate_resource_dirs(explicit):
            candidate = candidate.resolve()
            checked.append(str(candidate))
            if (candidate / "kaz.automorf.hfstol").is_file():
                return candidate
        locations = "\n  - ".join(checked) or "(none)"
        raise BackendError(
            "Kazakh FST resources are not installed. Run scripts/bootstrap_h100.sh "
            "on its supported Ubuntu x86-64 platform, download a matching "
            "release bundle, or set QAZMORPH_RESOURCE_DIR. Checked:\n  - " + locations
        )

    def _read_manifest(self) -> dict[str, Any]:
        path = self.resource_dir / "manifest.json"
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BackendError(f"Invalid resource manifest {path}: {exc}") from exc
        if not isinstance(manifest, dict):
            raise BackendError(f"Invalid resource manifest shape: {path}")
        schema = manifest.get("schema")
        required_files = RESOURCE_FILES_BY_SCHEMA.get(schema)
        if required_files is None:
            raise BackendError(f"Unsupported resource manifest schema: {path}")
        bundle_id = manifest.get("bundle_id")
        version = manifest.get("version")
        if (
            not isinstance(bundle_id, str)
            or len(bundle_id) != 64
            or any(character not in "0123456789abcdef" for character in bundle_id)
            or not isinstance(version, str)
        ):
            raise BackendError(f"Invalid resource manifest identity: {path}")
        identity = {
            key: value
            for key, value in manifest.items()
            if key not in {"bundle_id", "version"}
        }
        encoded = json.dumps(
            identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if hashlib.sha256(encoded).hexdigest() != bundle_id:
            raise BackendError(f"Resource manifest identity checksum failed: {path}")
        files = manifest.get("files")
        if not isinstance(files, dict) or set(files) != required_files:
            raise BackendError(f"Resource manifest file set is invalid: {path}")
        if not isinstance(manifest.get("source"), dict) or not isinstance(
            manifest.get("build"), dict
        ):
            raise BackendError(f"Resource manifest provenance is incomplete: {path}")
        if schema == RESOURCE_MANIFEST_V3 and not _has_verified_v3_guesser_gate(manifest):
            raise BackendError(
                f"Resource v3 finite-guesser verification is missing or invalid: {path}"
            )
        for name, metadata in files.items():
            resource = self.resource_dir / name
            if not isinstance(metadata, dict) or not resource.is_file():
                raise BackendError(f"Resource manifest entry is invalid or missing: {name}")
            expected_size = metadata.get("bytes")
            expected_hash = metadata.get("sha256")
            if resource.stat().st_size != expected_size:
                raise BackendError(f"Resource size verification failed: {name}")
            digest = hashlib.sha256(resource.read_bytes()).hexdigest()
            if digest != expected_hash:
                raise BackendError(f"Resource checksum verification failed: {name}")

        return manifest

    def _verify_resource_inventory(self) -> dict[str, Any]:
        """Verify the complete resource directory and its read-only seal.

        Manifest checks establish the expected artifact bytes.  Official
        runtime provenance additionally requires the content-addressed bundle
        itself to contain exactly those artifacts plus ``manifest.json``, with
        no writable regular file or directory.  This small inventory is cheap
        enough to re-hash whenever runtime provenance is requested, so a
        post-construction mutation or chmod cannot retain an official status.
        """

        required_files = set(RESOURCE_FILES_BY_SCHEMA[self.manifest["schema"]])
        expected_entries = required_files | {"manifest.json"}
        try:
            entries = list(self.resource_dir.rglob("*"))
        except OSError:
            entries = []
        observed_entries = {
            path.relative_to(self.resource_dir).as_posix() for path in entries
        }
        missing_entries = sorted(expected_entries - observed_entries)
        unexpected_entries = sorted(observed_entries - expected_entries)

        writable_entries = 0
        writable_directories = 0
        symlinks = 0
        total_bytes = 0
        for path in entries:
            try:
                stat = path.lstat()
            except OSError:
                continue
            if path.is_symlink():
                symlinks += 1
            elif path.is_dir():
                writable_directories += int(bool(stat.st_mode & 0o222))
            elif path.is_file():
                writable_entries += int(bool(stat.st_mode & 0o222))
                total_bytes += stat.st_size

        try:
            root_stat = self.resource_dir.stat()
            root_is_directory = self.resource_dir.is_dir()
        except OSError:
            root_stat = None
            root_is_directory = False
        if root_stat is not None:
            writable_directories += int(bool(root_stat.st_mode & 0o222))
        root_read_only = bool(
            root_is_directory
            and root_stat is not None
            and not root_stat.st_mode & 0o222
        )

        manifest_path = self.resource_dir / "manifest.json"
        manifest_matches = False
        manifest_read_only = False
        manifest_sha256: str | None = None
        try:
            manifest_stat = manifest_path.stat()
            manifest_bytes = manifest_path.read_bytes()
            manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
            described = json.loads(manifest_bytes.decode("utf-8"))
            manifest_matches = (
                manifest_path.is_file()
                and not manifest_path.is_symlink()
                and described == self.manifest
            )
            manifest_read_only = not bool(manifest_stat.st_mode & 0o222)
        except (OSError, UnicodeError, json.JSONDecodeError):
            pass

        artifacts_match = True
        regular_artifacts = 0
        for name in sorted(required_files):
            metadata = self.manifest["files"].get(name)
            candidate = self.resource_dir / name
            try:
                stat = candidate.stat()
                data = candidate.read_bytes()
            except OSError:
                artifacts_match = False
                continue
            if (
                candidate.is_symlink()
                or not candidate.is_file()
                or not isinstance(metadata, dict)
                or stat.st_size != metadata.get("bytes")
                or hashlib.sha256(data).hexdigest() != metadata.get("sha256")
            ):
                artifacts_match = False
                continue
            regular_artifacts += 1

        verified = bool(
            root_is_directory
            and not missing_entries
            and not unexpected_entries
            and symlinks == 0
            and manifest_matches
            and artifacts_match
            and regular_artifacts == len(required_files)
        )
        sealed_read_only = bool(
            verified
            and root_read_only
            and manifest_read_only
            and writable_entries == 0
            and writable_directories == 0
        )
        return {
            "verified": verified,
            "files": regular_artifacts + int(manifest_matches),
            "artifact_files": regular_artifacts,
            "symlinks": symlinks,
            "bytes": total_bytes,
            "manifest_sha256": manifest_sha256,
            "manifest_read_only": manifest_read_only,
            "root_read_only": root_read_only,
            "writable_entries": writable_entries,
            "writable_directories": writable_directories,
            "missing_entries": missing_entries,
            "unexpected_entries": unexpected_entries,
            "sealed_read_only": sealed_read_only,
            "verification_scope": "complete resource bundle",
        }

    def _resolve_toolchain_dir(self, manifest: dict[str, Any]) -> Path:
        """Resolve the immutable toolchain bound into this resource manifest.

        The mutable ``.qazmorph/toolchain`` symlink is only a fast candidate.
        During an atomic upgrade it may already name a newer toolchain while
        ``resources`` still names the previous valid bundle. In that window we
        locate the content-addressed directory whose manifest has the exact
        recorded byte length, SHA-256, and bundle identity.
        """

        toolchain = manifest.get("build", {}).get("toolchain")
        expected = toolchain.get("manifest") if isinstance(toolchain, dict) else None
        expected_bundle = toolchain.get("bundle_id") if isinstance(toolchain, dict) else None
        if (
            not isinstance(expected, dict)
            or not isinstance(expected.get("bytes"), int)
            or not isinstance(expected.get("sha256"), str)
            or not isinstance(expected_bundle, str)
        ):
            raise BackendError("Resource manifest has no valid toolchain binding")

        candidates = [self.runtime_dir / "toolchain"]
        immutable_root = self.runtime_dir / "toolchains"
        if immutable_root.is_dir():
            candidates.extend(sorted(path for path in immutable_root.iterdir() if path.is_dir()))

        checked: list[str] = []
        seen: set[Path] = set()
        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=True)
            except OSError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            candidate_manifest = resolved / "manifest.json"
            checked.append(str(candidate_manifest))
            if not candidate_manifest.is_file():
                continue
            if candidate_manifest.stat().st_size != expected["bytes"]:
                continue
            data = candidate_manifest.read_bytes()
            if hashlib.sha256(data).hexdigest() != expected["sha256"]:
                continue
            try:
                described = json.loads(data.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                continue
            if not isinstance(described, dict) or described.get("bundle_id") != expected_bundle:
                continue
            return resolved

        locations = "\n  - ".join(checked) or "(none)"
        raise BackendError(
            "Verified runtime toolchain bound to the resource manifest is unavailable. "
            "Checked:\n  - " + locations
        )

    def _read_bound_toolchain_manifest(self) -> dict[str, Any]:
        path = self.toolchain_dir / "manifest.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise BackendError(f"Bound toolchain manifest is invalid: {exc}") from exc
        if not isinstance(value, dict) or not isinstance(value.get("commands"), dict):
            raise BackendError("Bound toolchain manifest has no command inventory")
        if not isinstance(value.get("files"), dict):
            raise BackendError("Bound toolchain manifest has no file inventory")
        return value

    def _verify_current_toolchain_manifest(self) -> dict[str, Any]:
        """Re-read the bound manifest and verify every recorded identity."""

        binding = getattr(
            self,
            "toolchain_binding",
            self.manifest.get("build", {}).get("toolchain"),
        )
        expected = binding.get("manifest") if isinstance(binding, dict) else None
        expected_bundle = binding.get("bundle_id") if isinstance(binding, dict) else None
        if (
            not isinstance(expected, dict)
            or not isinstance(expected.get("bytes"), int)
            or not isinstance(expected.get("sha256"), str)
            or not isinstance(expected_bundle, str)
        ):
            raise BackendError("Active runtime has no valid manifest binding")

        path = self.toolchain_dir / "manifest.json"
        try:
            data = path.read_bytes()
            stat = path.stat()
        except OSError as exc:
            raise BackendError("Bound toolchain manifest is unavailable") from exc
        if not path.is_file() or path.is_symlink():
            raise BackendError("Bound toolchain manifest is not a regular file")
        digest = hashlib.sha256(data).hexdigest()
        if stat.st_size != expected["bytes"] or digest != expected["sha256"]:
            raise BackendError(
                "Bound toolchain manifest identity differs from the resource binding"
            )
        try:
            described = json.loads(data.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise BackendError("Bound toolchain manifest is no longer valid JSON") from exc
        if described != self.toolchain_manifest:
            raise BackendError(
                "Bound toolchain manifest contents changed after initialization"
            )
        if not isinstance(described, dict) or described.get("bundle_id") != expected_bundle:
            raise BackendError(
                "Bound toolchain manifest bundle identity differs from the resource binding"
            )
        return {
            "path": str(path.resolve()),
            "bytes": stat.st_size,
            "sha256": digest,
            "bundle_id": expected_bundle,
            "verified": True,
        }

    def _verify_bound_toolchain_inventory(
        self, *, force_rehash: bool = False
    ) -> dict[str, Any]:
        """Verify every immutable toolchain file, including loaded libraries.

        Command verification alone does not establish the identity of the
        shared objects selected through ``LD_LIBRARY_PATH``.  The manifest is
        small enough to validate the complete bundle.  A process-local cache
        avoids hashing unchanged content twice when an evaluator constructs
        multiple analyzers; a cheap lstat fingerprint is still recomputed so
        ordinary replacement or mutation invalidates that cache. Runtime
        provenance passes ``force_rehash=True`` to bypass the content cache and
        establish a fresh post-run byte identity for every regular file.
        """

        files = self.toolchain_manifest["files"]
        if not files:
            raise BackendError("Bound toolchain manifest has an empty file inventory")

        observed_entries = {
            path.relative_to(self.toolchain_dir).as_posix()
            for path in self.toolchain_dir.rglob("*")
            if path.is_file() or path.is_symlink()
        }
        expected_entries = set(files) | {"manifest.json"}
        if observed_entries != expected_entries:
            unexpected = sorted(observed_entries - expected_entries)
            missing = sorted(expected_entries - observed_entries)
            raise BackendError(
                "Bound toolchain extracted inventory differs from its manifest "
                f"(unexpected={unexpected[:3]!r}, missing={missing[:3]!r})"
            )

        fingerprint: list[
            tuple[str, int, int, int, int, int, int, str | None]
        ] = []
        regular_files: list[tuple[str, Path, dict[str, Any]]] = []
        symlink_count = 0
        total_bytes = 0
        writable_entries = 0
        for relative_name, metadata in sorted(files.items()):
            if not isinstance(relative_name, str) or not isinstance(metadata, dict):
                raise BackendError("Bound toolchain file inventory is invalid")
            relative = Path(relative_name)
            if relative.is_absolute() or ".." in relative.parts:
                raise BackendError(f"Bound toolchain file path is unsafe: {relative_name!r}")
            candidate = self.toolchain_dir / relative
            kind = metadata.get("kind")
            if kind == "symlink":
                expected_target = metadata.get("target")
                if not isinstance(expected_target, str):
                    raise BackendError(
                        f"Bound toolchain symlink inventory is invalid: {relative_name}"
                    )
                try:
                    observed_target = candidate.readlink().as_posix()
                    stat = candidate.lstat()
                except OSError as exc:
                    raise BackendError(
                        f"Bound toolchain symlink is unavailable: {relative_name}"
                    ) from exc
                if observed_target != expected_target:
                    raise BackendError(
                        f"Bound toolchain symlink target verification failed: {relative_name}"
                    )
                try:
                    candidate.resolve(strict=True).relative_to(self.toolchain_dir)
                except (OSError, ValueError) as exc:
                    raise BackendError(
                        f"Bound toolchain symlink escapes its bundle: {relative_name}"
                    ) from exc
                fingerprint.append(
                    (
                        relative_name,
                        stat.st_size,
                        stat.st_mtime_ns,
                        stat.st_ctime_ns,
                        stat.st_mode,
                        stat.st_ino,
                        stat.st_dev,
                        observed_target,
                    )
                )
                symlink_count += 1
                continue
            if kind != "file":
                raise BackendError(
                    f"Bound toolchain file kind is invalid: {relative_name}"
                )
            expected_size = metadata.get("bytes")
            expected_hash = metadata.get("sha256")
            if not isinstance(expected_size, int) or not isinstance(expected_hash, str):
                raise BackendError(
                    f"Bound toolchain file inventory is invalid: {relative_name}"
                )
            try:
                stat = candidate.stat()
            except OSError as exc:
                raise BackendError(
                    f"Bound toolchain file is unavailable: {relative_name}"
                ) from exc
            if not candidate.is_file() or candidate.is_symlink():
                raise BackendError(
                    f"Bound toolchain regular file is invalid: {relative_name}"
                )
            if stat.st_size != expected_size:
                raise BackendError(
                    f"Bound toolchain file size verification failed: {relative_name}"
                )
            fingerprint.append(
                (
                    relative_name,
                    stat.st_size,
                    stat.st_mtime_ns,
                    stat.st_ctime_ns,
                    stat.st_mode,
                    stat.st_ino,
                    stat.st_dev,
                    None,
                )
            )
            writable_entries += int(bool(stat.st_mode & 0o222))
            regular_files.append((relative_name, candidate, metadata))
            total_bytes += expected_size

        manifest_path = self.toolchain_dir / "manifest.json"
        try:
            manifest_stat = manifest_path.stat()
            root_stat = self.toolchain_dir.stat()
        except OSError as exc:
            raise BackendError("Bound toolchain read-only seal is unavailable") from exc
        manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        manifest_read_only = not bool(manifest_stat.st_mode & 0o222)
        directories = [self.toolchain_dir] + [
            path for path in self.toolchain_dir.rglob("*") if path.is_dir() and not path.is_symlink()
        ]
        writable_directories = sum(
            bool(path.stat().st_mode & 0o222) for path in directories
        )
        root_read_only = not bool(root_stat.st_mode & 0o222)
        sealed_read_only = (
            manifest_read_only
            and root_read_only
            and writable_entries == 0
            and writable_directories == 0
        )
        cache_key = (str(self.toolchain_dir), manifest_sha)
        frozen_fingerprint = tuple(fingerprint)
        content_rehashed = bool(
            force_rehash
            or not sealed_read_only
            or self._verified_toolchain_inventories.get(cache_key) != frozen_fingerprint
        )
        if content_rehashed:
            for relative_name, candidate, metadata in regular_files:
                digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
                if digest != metadata["sha256"]:
                    raise BackendError(
                        f"Bound toolchain file checksum failed: {relative_name}"
                    )
            if sealed_read_only:
                self._verified_toolchain_inventories[cache_key] = frozen_fingerprint
            else:
                self._verified_toolchain_inventories.pop(cache_key, None)

        return {
            "verified": True,
            "files": len(regular_files),
            "symlinks": symlink_count,
            "bytes": total_bytes,
            "manifest_sha256": manifest_sha,
            "manifest_read_only": manifest_read_only,
            "root_read_only": root_read_only,
            "writable_entries": writable_entries,
            "writable_directories": writable_directories,
            "sealed_read_only": sealed_read_only,
            "verification_scope": "complete extracted toolchain bundle",
            "force_rehash": force_rehash,
            "content_rehashed": content_rehashed,
            "byte_closed": False,
        }

    def _environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        self._ambient_library_path = environment.get("LD_LIBRARY_PATH")
        self._ambient_ld_preload = environment.get("LD_PRELOAD")
        self._ambient_ld_audit = environment.get("LD_AUDIT")
        self._ambient_dyld_library_path = environment.get("DYLD_LIBRARY_PATH")
        self._ambient_dyld_insert_libraries = environment.get(
            "DYLD_INSERT_LIBRARIES"
        )
        for key in ("CG3_DEFAULT", "CG3_OVERRIDE"):
            environment.pop(key, None)
        if not sys.platform.startswith("linux"):
            return environment
        prefixes = (
            self.toolchain_dir / "usr" / "lib" / "x86_64-linux-gnu",
            self.toolchain_dir / "usr" / "lib",
        )
        library_path = [str(path) for path in prefixes if path.is_dir()]
        existing = self._ambient_library_path
        if existing:
            library_path.append(existing)
        if library_path:
            environment["LD_LIBRARY_PATH"] = os.pathsep.join(library_path)
        return environment

    def _find_executable(self, name: str, env_name: str, *, required: bool = True) -> str | None:
        explicit = os.environ.get(env_name)
        if explicit:
            candidate = Path(explicit).expanduser()
            if candidate.is_file() and os.access(candidate, os.X_OK):
                self._executable_origins[name] = f"explicit:{env_name}"
                self._executable_verified[name] = False
                return str(candidate)
            raise BackendError(f"Configured executable {env_name} is invalid: {candidate}")

        commands = self.toolchain_manifest["commands"]
        command = commands.get(name)
        if not isinstance(command, dict) or not isinstance(command.get("path"), str):
            if required:
                raise BackendError(f"Bound toolchain manifest has no command {name!r}")
            return None
        relative = Path(command["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise BackendError(f"Bound toolchain command path is unsafe: {name!r}")
        candidate = self.toolchain_dir / relative
        files = self.toolchain_manifest["files"]
        file_record = files.get(relative.as_posix())
        expected_hash = command.get("sha256")
        if isinstance(file_record, dict) and file_record.get("kind") == "symlink":
            target = file_record.get("target")
            try:
                observed_target = candidate.readlink().as_posix()
            except OSError as exc:
                raise BackendError(f"Bound toolchain command symlink is unavailable: {name!r}") from exc
            if not isinstance(target, str) or observed_target != target:
                raise BackendError(f"Bound toolchain command symlink is invalid: {name!r}")
            resolved_candidate = candidate.resolve()
            try:
                resolved_relative = resolved_candidate.relative_to(
                    self.toolchain_dir
                ).as_posix()
            except ValueError as exc:
                raise BackendError(
                    f"Bound toolchain command escapes its bundle: {name!r}"
                ) from exc
            file_record = files.get(resolved_relative)
            candidate = resolved_candidate
        if (
            not isinstance(file_record, dict)
            or not isinstance(file_record.get("bytes"), int)
            or not isinstance(file_record.get("sha256"), str)
            or not isinstance(expected_hash, str)
            or expected_hash != file_record["sha256"]
        ):
            raise BackendError(f"Bound toolchain command inventory is invalid: {name!r}")
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            raise BackendError(f"Bound toolchain executable is unavailable: {candidate}")
        if candidate.stat().st_size != file_record["bytes"]:
            raise BackendError(f"Bound toolchain executable size verification failed: {name}")
        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if digest != expected_hash:
            raise BackendError(f"Bound toolchain executable checksum failed: {name}")
        self._executable_origins[name] = getattr(
            self, "toolchain_origin", "resource-bound-toolchain"
        )
        self._executable_verified[name] = True
        return str(candidate)

    @property
    def resource_version(self) -> str:
        return str(self.manifest["version"])

    def runtime_provenance(self) -> dict[str, Any]:
        """Freshly verify every runtime byte and return controlled provenance."""

        resource_inventory = self._verify_resource_inventory()
        self._resource_inventory = resource_inventory

        verification_error: str | None = None
        try:
            toolchain = self._verify_current_toolchain_manifest()
        except BackendError as exc:
            verification_error = str(exc)
            toolchain = {
                "path": str((self.toolchain_dir / "manifest.json").resolve()),
                "verified": False,
                "error": verification_error,
            }

        if verification_error is None:
            try:
                inventory = self._verify_bound_toolchain_inventory(force_rehash=True)
                self._toolchain_inventory = inventory
            except BackendError as exc:
                verification_error = str(exc)
                inventory = {
                    **dict(self._toolchain_inventory),
                    "verified": False,
                    "sealed_read_only": False,
                    "force_rehash": True,
                    "content_rehashed": True,
                    "error": verification_error,
                }
        else:
            inventory = {
                **dict(self._toolchain_inventory),
                "verified": False,
                "sealed_read_only": False,
                "force_rehash": True,
                "content_rehashed": False,
                "error": verification_error,
            }

        fresh_toolchain_verified = bool(
            toolchain.get("verified") and inventory.get("verified")
        )
        toolchain_origin = getattr(
            self, "toolchain_origin", "resource-bound-toolchain"
        )
        bound_origins = {"resource-bound-toolchain", "platform-runtime-lock"}
        executables: dict[str, dict[str, int | str | bool] | None] = {}
        unverified_overrides: set[str] = set()
        bound_executable_errors: list[str] = []
        for name, value in {
            "hfst-proc": self.hfst_proc,
            "cg-proc": self.cg_proc,
            "hfst-lookup": self.hfst_lookup,
            "hfst-optimized-lookup": self.hfst_optimized_lookup,
        }.items():
            if value is None:
                executables[name] = None
                continue
            origin = self._executable_origins.get(name, "unknown")
            initially_verified = self._executable_verified.get(name, False)
            verified = bool(
                initially_verified
                and (
                    origin not in bound_origins
                    or fresh_toolchain_verified
                )
            )
            path = Path(value).resolve()
            try:
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                    stat = os.fstat(stream.fileno())
                executable_error: str | None = None
                if origin in bound_origins:
                    try:
                        relative_name = path.relative_to(
                            self.toolchain_dir.resolve()
                        ).as_posix()
                    except ValueError:
                        relative_name = ""
                    expected_file = self.toolchain_manifest["files"].get(
                        relative_name
                    )
                    if (
                        not isinstance(expected_file, dict)
                        or expected_file.get("kind") != "file"
                        or stat.st_size != expected_file.get("bytes")
                        or digest.hexdigest() != expected_file.get("sha256")
                    ):
                        verified = False
                        executable_error = (
                            "bound executable identity changed after inventory verification"
                        )
                        bound_executable_errors.append(name)
                executable: dict[str, int | str | bool] = {
                    "path": str(path),
                    "bytes": stat.st_size,
                    "sha256": digest.hexdigest(),
                    "origin": origin,
                    "verified": verified,
                }
                if executable_error is not None:
                    executable["error"] = executable_error
            except OSError:
                verified = False
                executable = {
                    "path": str(path),
                    "origin": origin,
                    "verified": False,
                    "error": "runtime executable is unavailable during provenance verification",
                }
                if origin in bound_origins:
                    bound_executable_errors.append(name)
            executables[name] = executable
            if not verified and origin not in bound_origins:
                unverified_overrides.add(origin)

        if bound_executable_errors:
            executable_error = (
                "Bound toolchain executable verification failed after inventory rehash: "
                + ", ".join(sorted(set(bound_executable_errors)))
            )
            verification_error = (
                f"{verification_error}; {executable_error}"
                if verification_error is not None
                else executable_error
            )
            fresh_toolchain_verified = False
            inventory = {
                **inventory,
                "verified": False,
                "sealed_read_only": False,
                "error": verification_error,
            }

        extracted_subset_verified = (
            bool(
                fresh_toolchain_verified
                and resource_inventory.get("verified")
            )
            and not unverified_overrides
        )
        non_official_reasons = [
            f"unverified runtime executable override: {origin}"
            for origin in sorted(unverified_overrides)
        ]
        if verification_error is not None:
            non_official_reasons.append(
                f"bound runtime verification failed: {verification_error}"
            )
        if self.manifest["schema"] == RESOURCE_MANIFEST_V2:
            non_official_reasons.append(
                "legacy resource v2/toolchain is not sealed; functional rollback only"
            )
        else:
            if not self.guesser_verified_finite:
                non_official_reasons.append(
                    "resource v3 has no verified finite-guesser proof"
                )
            if verification_error is None and not inventory.get("sealed_read_only"):
                non_official_reasons.append(
                    (
                        "resource v3 bound toolchain is not sealed read-only"
                        if toolchain_origin == "resource-bound-toolchain"
                        else "resource v3 active platform runtime is not sealed read-only"
                    )
                )
            if not resource_inventory.get("verified"):
                non_official_reasons.append(
                    "resource v3 bundle inventory is not completely verified"
                )
            elif not resource_inventory.get("sealed_read_only"):
                non_official_reasons.append(
                    "resource v3 bundle is not sealed read-only"
                )
        if sys.platform.startswith("linux"):
            if getattr(self, "_ambient_library_path", None):
                non_official_reasons.append(
                    "ambient LD_LIBRARY_PATH extends the dynamic-library search path"
                )
            if getattr(self, "_ambient_ld_preload", None):
                non_official_reasons.append(
                    "ambient LD_PRELOAD is present and can inject unverified code"
                )
            if getattr(self, "_ambient_ld_audit", None):
                non_official_reasons.append(
                    "ambient LD_AUDIT is present and can inject unverified code"
                )
        elif sys.platform == "darwin":
            if getattr(self, "_ambient_dyld_library_path", None):
                non_official_reasons.append(
                    "ambient DYLD_LIBRARY_PATH extends the dynamic-library search path"
                )
            if getattr(self, "_ambient_dyld_insert_libraries", None):
                non_official_reasons.append(
                    "ambient DYLD_INSERT_LIBRARIES is present and can inject unverified code"
                )
        official = extracted_subset_verified and not non_official_reasons
        loader_environment = {
            name: {
                "present": bool(value),
                "sha256": (
                    hashlib.sha256(os.fsencode(value)).hexdigest()
                    if value
                    else None
                ),
            }
            for name, value in (
                ("LD_PRELOAD", getattr(self, "_ambient_ld_preload", None)),
                ("LD_AUDIT", getattr(self, "_ambient_ld_audit", None)),
                (
                    "DYLD_LIBRARY_PATH",
                    getattr(self, "_ambient_dyld_library_path", None),
                ),
                (
                    "DYLD_INSERT_LIBRARIES",
                    getattr(self, "_ambient_dyld_insert_libraries", None),
                ),
            )
        }
        resource_build_toolchain = getattr(
            self,
            "resource_build_toolchain_binding",
            self.manifest.get("build", {}).get("toolchain"),
        )
        active_binding = getattr(self, "toolchain_binding", resource_build_toolchain)
        active_runtime = {
            "origin": toolchain_origin,
            "bundle_id": (
                active_binding.get("bundle_id")
                if isinstance(active_binding, dict)
                else None
            ),
            "platform_lock": getattr(self, "platform_runtime_lock_entry", None),
        }
        if sys.platform == "darwin":
            dynamic_dependency_closure = (
                "non-system Mach-O dependencies are included in the active runtime "
                "manifest; Apple libSystem and libc++ remain host System Libraries"
            )
        elif sys.platform.startswith("linux"):
            dynamic_dependency_closure = (
                "host ELF dependencies outside the extracted manifest are not byte-locked"
            )
        elif sys.platform == "win32":
            dynamic_dependency_closure = (
                "Windows system DLLs outside the extracted manifest are not byte-locked"
            )
        else:
            dynamic_dependency_closure = (
                "host system libraries outside the extracted manifest are not byte-locked"
            )
        return {
            "official": official,
            "verified": extracted_subset_verified,
            "verification_scope": "complete resource bundle and complete active runtime bundle",
            "byte_closed": False,
            "dynamic_dependency_closure": dynamic_dependency_closure,
            "guesser_runtime": {
                "format": self.guesser_format,
                "verified_finite": self.guesser_verified_finite,
                "productive_safe": self.guesser_productive_safe,
                "reason": self.guesser_safety_reason,
            },
            "non_official_reasons": non_official_reasons,
            "executables": executables,
            "toolchain_manifest": toolchain,
            "resource_build_toolchain": resource_build_toolchain,
            "active_runtime": active_runtime,
            "resource_inventory": resource_inventory,
            "toolchain_inventory": inventory,
            "environment": {
                "LANG": self.environment.get("LANG"),
                "LC_ALL": self.environment.get("LC_ALL"),
                "LD_LIBRARY_PATH": self.environment.get("LD_LIBRARY_PATH"),
                **loader_environment,
            },
        }

    @staticmethod
    def _hyphen_protection_indices(text: str, *, timeout: float) -> set[int]:
        """Fence the one lossy HFST tokenizer suffix while retaining compounds.

        In the pinned analyzer, an otherwise independent ``-а`` component is
        consumed after the hyphen (``йа-а`` becomes ``йа-``). Other unknown
        hyphenated forms are tokenized losslessly, and valid compounds such as
        ``сөз-ау`` and ``азық-түлік`` must remain available as whole readings.
        The lexical interjection ``а-а`` is a deliberate exception and is
        recognized losslessly by the FST without fencing.
        """

        del timeout  # Kept in the private signature for call-site symmetry.
        protected: set[int] = set()
        for surface, indices in _hyphen_chains(text):
            if surface.casefold() == "а-а":
                continue
            for index in indices:
                component_end = index + 1
                while component_end < len(text) and (
                    text[component_end].isalnum()
                    or unicodedata.category(text[component_end]).startswith("M")
                ):
                    component_end += 1
                suffix = text[index + 1 : component_end]
                if suffix.casefold() == "а":
                    protected.add(index)

        # The lossy suffix does not require an alphanumeric component on the
        # left: hfst-proc also consumes it in ``-а``, ``№-а``, and ``!-а``.
        # Fence every remaining orthographic hyphen followed by the exact
        # one-letter suffix, except the standalone lexical interjection а-а.
        for index, character in enumerate(text):
            if character not in ORTHOGRAPHIC_HYPHENS or index + 1 >= len(text):
                continue
            component_end = index + 1
            while component_end < len(text) and (
                text[component_end].isalnum()
                or unicodedata.category(text[component_end]).startswith("M")
            ):
                component_end += 1
            if text[index + 1 : component_end].casefold() != "а":
                continue
            left_start = index
            while left_start > 0 and (
                text[left_start - 1].isalnum()
                or unicodedata.category(text[left_start - 1]).startswith("M")
            ):
                left_start -= 1
            standalone_interjection = (
                text[left_start:index].casefold() == "а"
                and left_start + 1 == index
                and component_end == index + 2
                and (left_start == 0 or text[left_start - 1] not in ORTHOGRAPHIC_HYPHENS)
                and (
                    component_end == len(text)
                    or text[component_end] not in ORTHOGRAPHIC_HYPHENS
                )
            )
            if not standalone_interjection:
                protected.add(index)
        return protected

    def _run_hfst(self, backend_input: str, *, zero_flush: bool, timeout: float) -> str:
        command = [str(self.hfst_proc), "-w"]
        if zero_flush:
            command.append("-z")
        command.append(str(self.analyzer_path))
        try:
            result = subprocess.run(
                command,
                input=backend_input,
                text=True,
                encoding="utf-8",
                capture_output=True,
                check=False,
                timeout=timeout,
                env=self.environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BackendError(f"HFST analysis failed: {exc}") from exc
        if result.returncode:
            raise BackendError(f"HFST analysis failed ({result.returncode}): {result.stderr.strip()}")
        return result.stdout

    def _run_cg(self, stream: str, *, timeout: float) -> str:
        if not self.cg_proc or not self.grammar_path.is_file():
            raise BackendError("Contextual mode requested, but cg-proc or kaz.rlx.bin is unavailable")
        try:
            selected = subprocess.run(
                [str(self.cg_proc), str(self.grammar_path)],
                input=stream,
                text=True,
                encoding="utf-8",
                capture_output=True,
                check=False,
                timeout=timeout,
                env=self.environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BackendError(f"Constraint Grammar disambiguation failed: {exc}") from exc
        if selected.returncode:
            raise BackendError(
                f"Constraint Grammar disambiguation failed ({selected.returncode}): "
                f"{selected.stderr.strip()}"
            )
        return selected.stdout

    def analyze_stream_pair(
        self,
        text: str,
        *,
        disambiguate: bool = False,
        timeout: float = 120.0,
    ) -> tuple[str, str | None]:
        """Return the full lattice and, when requested, its CG projection.

        HFST is executed once.  Keeping the pre-CG stream is important for
        multi-token dictionary spans: contextual selection must not erase the
        legal phrase lattice that the public API promises to retain.
        """

        # hfst-proc does not flush a final lexical unit unless it sees a token
        # boundary. Add a private boundary and remove it from both streams.
        added_boundary = bool(text) and not text[-1].isspace()
        protected_hyphens = self._hyphen_protection_indices(text, timeout=timeout)
        backend_input = prepare_apertium_text(
            text, protected_hyphens=protected_hyphens
        ) + ("\n" if added_boundary else "")
        raw_lattice = self._run_hfst(backend_input, zero_flush=False, timeout=timeout)
        raw_contextual = self._run_cg(raw_lattice, timeout=timeout) if disambiguate else None
        if added_boundary and raw_lattice.endswith("\n"):
            raw_lattice = raw_lattice[:-1]
        if added_boundary and raw_contextual is not None and raw_contextual.endswith("\n"):
            raw_contextual = raw_contextual[:-1]
        return (
            strip_boundary_superblanks(raw_lattice),
            strip_boundary_superblanks(raw_contextual) if raw_contextual is not None else None,
        )

    def analyze_atomic_stream_pair(
        self,
        text: str,
        boundaries: tuple[tuple[int, int], ...],
        *,
        disambiguate: bool = False,
        timeout: float = 120.0,
    ) -> tuple[str, str | None]:
        """Analyze predetermined source atoms in one NUL-flushed HFST pass.

        NUL is backend control data here. A literal caller NUL is first moved
        into a private superblank by ``prepare_apertium_text`` and is therefore
        distinguishable from these flush markers. The returned stream contains
        no control NULs and can be passed through CG as one context stream.
        """

        if not text:
            if boundaries:
                raise ValueError("empty atomic input cannot have boundaries")
            return "", "" if disambiguate else None
        cursor = 0
        protected = self._hyphen_protection_indices(text, timeout=timeout)
        chunks: list[str] = []
        for start, end in boundaries:
            if start != cursor or end <= start or end > len(text):
                raise ValueError("atomic boundaries must be a contiguous exact partition")
            local_hyphens = {
                index - start for index in protected if start <= index < end
            }
            chunks.append(
                prepare_apertium_text(
                    text[start:end], protected_hyphens=local_hyphens
                )
            )
            cursor = end
        if cursor != len(text):
            raise ValueError("atomic boundaries do not cover the input")

        backend_input = "\x00".join(chunks) + "\x00"
        raw_lattice = self._run_hfst(backend_input, zero_flush=True, timeout=timeout)
        # hfst-apertium-proc can place the flush NUL before or after the cohort;
        # none are caller data because literal NUL was protected above.
        raw_lattice = raw_lattice.replace("\x00", "")
        raw_contextual = self._run_cg(raw_lattice, timeout=timeout) if disambiguate else None
        return (
            strip_boundary_superblanks(raw_lattice),
            strip_boundary_superblanks(raw_contextual) if raw_contextual is not None else None,
        )

    def analyze_stream(self, text: str, *, disambiguate: bool = False, timeout: float = 120.0) -> str:
        """Compatibility wrapper returning the requested single stream."""

        lattice, contextual = self.analyze_stream_pair(
            text, disambiguate=disambiguate, timeout=timeout
        )
        return contextual if contextual is not None else lattice

    def generate(self, lexical_form: str, *, limit: int = 128, timeout: float = 10.0) -> list[str]:
        if limit < 1:
            raise ValueError("generation limit must be positive")
        generator = self.resource_dir / "kaz.autogen.hfstol"
        if not self.hfst_optimized_lookup or not generator.is_file():
            raise BackendError("Morphological generator resource or hfst-optimized-lookup is unavailable")
        command = [
            str(self.hfst_optimized_lookup),
            "-q",
            "-u",
            "-n",
            str(limit),
            str(generator),
        ]
        try:
            result = subprocess.run(
                command,
                input=lexical_form + "\n",
                text=True,
                encoding="utf-8",
                capture_output=True,
                check=False,
                timeout=timeout,
                env=self.environment,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BackendError(f"HFST generation failed: {exc}") from exc
        if result.returncode:
            raise BackendError(f"HFST generation failed ({result.returncode}): {result.stderr.strip()}")
        forms: list[str] = []
        for line in result.stdout.splitlines():
            fields = line.split("\t")
            if (
                len(fields) >= 2
                and fields[0] == lexical_form
                and "+?" not in fields[1:]
            ):
                forms.append(fields[1])
        return list(dict.fromkeys(forms))
