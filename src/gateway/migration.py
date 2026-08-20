"""Filesystem migration from the APG runtime directory to PrivacyFlow."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gateway.compat import CANONICAL_STATE_DIR, LEGACY_STATE_DIR, map_state_value


class MigrationError(RuntimeError):
    def __init__(self, message: str, *, code: str = "PF_MIGRATION_FAILED") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class MigrationResult:
    source: Path
    destination: Path
    backup: Path | None
    files: int
    changed: bool

    def summary(self) -> dict[str, Any]:
        return {
            "source": str(self.source),
            "destination": str(self.destination),
            "backup": str(self.backup) if self.backup else None,
            "files": self.files,
            "changed": self.changed,
        }


_MIGRATABLE_JSON_NAMES = {
    "launcher.json",
    "agent-connections.json",
    "detector-control.json",
    "local-models.json",
    "pf-runtime.json",
    "apg-runtime.json",
}


def rollback_migration(result: MigrationResult) -> None:
    """Remove only artifacts created by one failed migration attempt."""

    _remove_temporary(result.destination)
    if result.backup is not None:
        _remove_temporary(result.backup)


def default_state_paths(base: Path | None = None) -> tuple[Path, Path]:
    root = Path.cwd() if base is None else Path(base)
    return root / LEGACY_STATE_DIR, root / CANONICAL_STATE_DIR


def migrate_state(
    source: Path | None = None,
    destination: Path | None = None,
    *,
    backup_root: Path | None = None,
) -> MigrationResult:
    """Copy and validate an APG state tree without deleting the source.

    The source remains available as a safety backup.  A destination that
    already exists is treated as an operator conflict instead of being
    merged, because merging credentials or transaction snapshots is unsafe.
    """

    default_source, default_destination = default_state_paths()
    source_path = (source or default_source).expanduser().resolve()
    destination_path = (destination or default_destination).expanduser().resolve()
    if not source_path.exists():
        raise MigrationError(f"Legacy state directory does not exist: {source_path}", code="PF_MIGRATION_SOURCE_MISSING")
    if not source_path.is_dir():
        raise MigrationError(f"Legacy state path is not a directory: {source_path}", code="PF_MIGRATION_SOURCE_INVALID")
    if destination_path.exists():
        raise MigrationError(
            f"PrivacyFlow state directory already exists: {destination_path}. "
            "Resolve it before retrying migration.",
            code="PF_MIGRATION_DEST_EXISTS",
        )

    lock_path = destination_path.parent / f"{destination_path.name}.migrate.lock"
    temporary_path = destination_path.parent / f".{destination_path.name}.tmp-{uuid.uuid4().hex}"
    backup_path: Path | None = None
    backup_created = False
    lock = None
    lock_created = False
    replaced_destination = False
    try:
        try:
            lock = lock_path.open("x", encoding="utf-8")
            lock_created = True
            lock.write(f"pid={os.getpid()}\ntime={time.time()}\n")
            lock.flush()
            os.chmod(lock_path, 0o600)
        except FileExistsError as exc:
            raise MigrationError("Another PrivacyFlow migration is already running.", code="PF_MIGRATION_LOCKED") from exc

        backup_parent = (backup_root or source_path.parent / f"{source_path.name}.legacy").resolve()
        backup_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(backup_parent, 0o700)
        # Include a random suffix so a retry in the same second never points
        # at an existing safety backup.  Never remove a pre-existing backup
        # while cleaning up a failed migration attempt.
        backup_path = backup_parent / f"{int(time.time())}-{uuid.uuid4().hex[:8]}"
        backup_created = True
        _copy_tree(source_path, backup_path)
        _verify_copy(source_path, backup_path)

        _copy_tree(source_path, temporary_path)
        _verify_copy(source_path, temporary_path)
        files = _rewrite_state_tree(temporary_path)
        _validate_migrated_state_tree(temporary_path)
        _verify_tree(temporary_path)
        os.chmod(temporary_path, 0o700)
        temporary_path.replace(destination_path)
        replaced_destination = True
        _make_read_only(backup_path)
        return MigrationResult(source_path, destination_path, backup_path, files, True)
    except MigrationError:
        _remove_temporary(temporary_path)
        if replaced_destination:
            _remove_temporary(destination_path)
        if backup_created and backup_path is not None and backup_path.exists():
            _remove_temporary(backup_path)
        raise
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        _remove_temporary(temporary_path)
        if replaced_destination:
            _remove_temporary(destination_path)
        if backup_created and backup_path is not None and backup_path.exists():
            _remove_temporary(backup_path)
        raise MigrationError(f"Could not migrate PrivacyFlow state: {exc}") from exc
    finally:
        if lock is not None:
            lock.close()
        if lock_created:
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass


def _copy_tree(source: Path, destination: Path) -> None:
    if destination.exists():
        raise MigrationError(f"Migration destination already exists: {destination}", code="PF_MIGRATION_DEST_EXISTS")
    destination.mkdir(parents=True, mode=0o700)
    os.chmod(destination, 0o700)
    for current, directories, filenames in os.walk(source, followlinks=False):
        current_path = Path(current)
        relative = current_path.relative_to(source)
        target_dir = destination / relative
        if relative != Path("."):
            if current_path.is_symlink():
                raise MigrationError(f"Symbolic links are not allowed in state migration: {current_path}", code="PF_MIGRATION_SYMLINK")
            target_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(target_dir, current_path.stat().st_mode & 0o7777)
        for directory in directories:
            directory_path = current_path / directory
            if directory_path.is_symlink():
                raise MigrationError(f"Symbolic links are not allowed in state migration: {directory_path}", code="PF_MIGRATION_SYMLINK")
        for filename in filenames:
            source_file = current_path / filename
            if source_file.is_symlink() or not source_file.is_file():
                raise MigrationError(f"Only regular files may be migrated: {source_file}", code="PF_MIGRATION_FILE_INVALID")
            target_file = target_dir / filename
            shutil.copy2(source_file, target_file)


def _rewrite_state_tree(root: Path) -> int:
    changed_files = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if path.name not in _MIGRATABLE_JSON_NAMES:
            if path.suffix.lower() == ".json":
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if _contains_reserved_namespace(payload):
                    raise MigrationError(
                        f"Unknown PrivacyFlow configuration contains a reserved provider: {path}",
                        code="PF_MIGRATION_UNKNOWN_CONFIG",
                    )
            continue
        if path.name == "apg-runtime.json":
            target = path.with_name("pf-runtime.json")
            path.replace(target)
            path = target
        if path.suffix.lower() != ".json":
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            if path.name == "detector-control.json":
                # Custom detector state is no longer part of PrivacyFlow. An
                # unreadable legacy editor state must not make the fixed
                # built-in protection pipeline unbootable; the untouched
                # bytes remain in the read-only legacy backup.
                payload = {}
            else:
                raise MigrationError(
                    f"PrivacyFlow state is not valid JSON: {path}",
                    code="PF_MIGRATION_STATE_INVALID",
                ) from exc
        rewritten = map_state_value(payload)
        if path.name == "detector-control.json":
            enabled = rewritten.get("pf_enabled", rewritten.get("apg_enabled", True)) if isinstance(rewritten, dict) else True
            rewritten = {
                "version": 3,
                "builtin_ruleset_revision": 4,
                "pf_enabled": enabled if isinstance(enabled, bool) else True,
            }
        if rewritten == payload:
            continue
        path.write_text(json.dumps(rewritten, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        changed_files += 1
    return changed_files


def _validate_migrated_state_tree(root: Path) -> None:
    """Reject a copied state tree that would fail during the next startup."""

    for name in _MIGRATABLE_JSON_NAMES - {"apg-runtime.json"}:
        path = root / name
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MigrationError(
                f"PrivacyFlow state is not valid JSON: {path}",
                code="PF_MIGRATION_STATE_INVALID",
            ) from exc
        if not isinstance(payload, dict):
            raise MigrationError(
                f"PrivacyFlow state must contain a JSON object: {path}",
                code="PF_MIGRATION_STATE_INVALID",
            )
        if name == "launcher.json":
            keys = payload.get("connector_api_keys", {})
            if not isinstance(keys, dict):
                raise MigrationError("Launcher Connector keys are invalid.", code="PF_MIGRATION_STATE_INVALID")
        elif name == "agent-connections.json":
            if not isinstance(payload.get("active", {}), dict) or not isinstance(payload.get("completed", {}), dict):
                raise MigrationError("Agent Connector transaction state is invalid.", code="PF_MIGRATION_STATE_INVALID")
            _validate_connector_snapshots(root, payload)
        elif name == "local-models.json":
            if payload.get("version") != 2 or not isinstance(payload.get("manual_models", []), list) or not isinstance(payload.get("records", {}), dict):
                raise MigrationError("Local model state version is unsupported.", code="PF_MIGRATION_STATE_VERSION_UNSUPPORTED")

    for path in [*root.rglob("*.sqlite"), *root.rglob("*.sqlite3")]:
        try:
            connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            try:
                result = connection.execute("PRAGMA quick_check").fetchone()
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise MigrationError(f"SQLite state is invalid: {path}", code="PF_MIGRATION_SQLITE_INVALID") from exc
        if not result or result[0] != "ok":
            raise MigrationError(f"SQLite state failed integrity validation: {path}", code="PF_MIGRATION_SQLITE_INVALID")


def _validate_connector_snapshots(root: Path, payload: dict[str, Any]) -> None:
    for connector_id, active in payload.get("active", {}).items():
        if not isinstance(connector_id, str) or not isinstance(active, dict) or not isinstance(active.get("files", []), list):
            raise MigrationError("Agent Connector transaction state is invalid.", code="PF_MIGRATION_STATE_INVALID")
        for item in active.get("files", []):
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise MigrationError("Agent Connector file state is invalid.", code="PF_MIGRATION_STATE_INVALID")
            snapshot = item.get("snapshot")
            if item.get("existed") and (not isinstance(snapshot, str) or not (root / snapshot).is_file()):
                raise MigrationError("Agent Connector snapshot is missing.", code="PF_MIGRATION_SNAPSHOT_MISSING")


def _verify_tree(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            raise MigrationError(f"Migration produced a symbolic link: {path}", code="PF_MIGRATION_SYMLINK")
        if path.is_file():
            _ = _sha256(path)


def _verify_copy(source: Path, destination: Path) -> None:
    """Verify a copied tree before any namespace rewriting occurs."""

    source_manifest = _tree_manifest(source)
    destination_manifest = _tree_manifest(destination)
    if source_manifest != destination_manifest:
        raise MigrationError(
            "PrivacyFlow migration copy failed hash verification.",
            code="PF_MIGRATION_HASH_MISMATCH",
        )


def _tree_manifest(root: Path) -> dict[str, tuple[str, int]]:
    manifest: dict[str, tuple[str, int]] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise MigrationError(f"Symbolic links are not allowed in migration: {path}", code="PF_MIGRATION_SYMLINK")
        if path.is_file():
            relative = str(path.relative_to(root))
            manifest[relative] = (_sha256(path), path.stat().st_mode & 0o7777)
    return manifest


def _contains_reserved_namespace(value: Any, *, key: str | None = None) -> bool:
    """Detect structured PF/APG provider ownership in an unknown JSON file."""

    if isinstance(value, dict):
        for raw_key, child in value.items():
            child_key = str(raw_key)
            if child_key in {"apg", "pf", "APG", "PF", "apg_enabled", "pf_enabled", "apg_core", "pf_core"}:
                if key in {"model_providers", "providers", "modelPresets", "connector_api_keys", "env", "credentials", "environment"} or child_key in {"apg_enabled", "pf_enabled", "apg_core", "pf_core"}:
                    return True
            if child_key.startswith(("APG_", "PF_")) and key in {"env", "credentials", "environment"}:
                return True
            if child_key in {"provider", "provider_id", "model_provider"} and child in {"apg", "pf"}:
                return True
            if _contains_reserved_namespace(child, key=child_key):
                return True
        return False
    if isinstance(value, list):
        return any(_contains_reserved_namespace(item, key=key) for item in value)
    return False


def _make_read_only(root: Path) -> None:
    """Make the retained legacy copy inspectable but not writable."""

    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        mode = path.stat().st_mode & 0o7777
        if path.is_dir():
            os.chmod(path, mode & ~0o222)
        elif path.is_file():
            os.chmod(path, mode & ~0o222)
    os.chmod(root, root.stat().st_mode & 0o7777 & ~0o222)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _remove_temporary(path: Path) -> None:
    if not path.exists():
        return
    if path.is_dir():
        # Successful safety backups are intentionally read-only. The outer
        # transaction may still need to remove the backup if Connector
        # migration fails, so restore owner permissions only on this exact
        # per-attempt tree before deleting it.
        for child in sorted(path.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            if child.is_symlink():
                child.unlink()
            elif child.is_dir():
                os.chmod(child, child.stat().st_mode | 0o700)
            else:
                os.chmod(child, child.stat().st_mode | 0o600)
        os.chmod(path, path.stat().st_mode | 0o700)
        shutil.rmtree(path)
    else:
        path.unlink()
