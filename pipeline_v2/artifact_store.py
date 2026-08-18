"""Content-addressed immutable artifact persistence for pipeline_v2."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping


class ArtifactIntegrityError(ValueError):
    pass


@dataclass(frozen=True)
class ArtifactRef:
    ref: str
    digest: str
    media_type: str

    def to_dict(self) -> dict[str, str]:
        return {"artifact_ref": self.ref, "artifact_digest": self.digest, "media_type": self.media_type}


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


class ArtifactStore:
    """A ref+digest checked content store; layout is intentionally non-semantic."""

    def __init__(self, root: str | Path) -> None:
        root_path = Path(root).expanduser().absolute()
        root_path.mkdir(parents=True, exist_ok=True)
        if root_path.is_symlink() or not root_path.is_dir():
            raise ArtifactIntegrityError("artifact root must be a real directory")
        self.root = root_path.resolve()
        self._mkdir("store/sha256")
        self._mkdir("refs/sha256")

    @staticmethod
    def _validate_ref(ref: str) -> str:
        if not isinstance(ref, str) or not ref.strip():
            raise ArtifactIntegrityError("artifact ref must be non-empty")
        path = PurePosixPath(ref)
        if path.is_absolute() or ".." in path.parts or "\\" in ref or "\x00" in ref:
            raise ArtifactIntegrityError("artifact ref must be a safe logical reference")
        return ref

    def _safe_path(self, relative: str) -> Path:
        parts = PurePosixPath(relative).parts
        if not parts or ".." in parts or PurePosixPath(relative).is_absolute():
            raise ArtifactIntegrityError("unsafe artifact-store path")
        current = self.root
        for part in parts[:-1]:
            current = current / part
            if current.exists() and current.is_symlink():
                raise ArtifactIntegrityError("artifact-store symlink escape")
        target = self.root.joinpath(*parts)
        try:
            target.resolve().relative_to(self.root)
        except ValueError as exc:
            raise ArtifactIntegrityError("artifact-store path escapes root") from exc
        return target

    def _mkdir(self, relative: str) -> Path:
        target = self._safe_path(relative + "/x").parent
        fd = self._open_directory(relative, create=True)
        os.close(fd)
        return target

    def _open_directory(self, relative: str, *, create: bool) -> int:
        """Open a directory chain beneath the store without following symlinks."""
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            current = os.open(self.root, flags)
            for part in PurePosixPath(relative).parts:
                if part in {"", ".", ".."}:
                    raise ArtifactIntegrityError("unsafe artifact-store directory")
                try:
                    child = os.open(part, flags, dir_fd=current)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(part, 0o700, dir_fd=current)
                    child = os.open(part, flags, dir_fd=current)
                os.close(current)
                current = child
            return current
        except ArtifactIntegrityError:
            if "current" in locals():
                os.close(current)
            raise
        except OSError as exc:
            if "current" in locals():
                os.close(current)
            raise ArtifactIntegrityError("artifact-store directory is unsafe") from exc

    def _relative(self, path: Path) -> PurePosixPath:
        try:
            return PurePosixPath(path.relative_to(self.root).as_posix())
        except ValueError as exc:
            raise ArtifactIntegrityError("artifact-store path escapes root") from exc

    @staticmethod
    def _read_fd(fd: int) -> bytes:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ArtifactIntegrityError("artifact-store entry is not a regular file")
        with os.fdopen(fd, "rb") as handle:
            return handle.read()

    def _read_file(self, path: Path) -> bytes:
        relative = self._relative(path)
        parent = self._open_directory(str(relative.parent), create=False)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            return self._read_fd(os.open(relative.name, flags, dir_fd=parent))
        except OSError as exc:
            raise ArtifactIntegrityError("artifact-store entry is unavailable") from exc
        finally:
            os.close(parent)

    def _write_create_only(self, path: Path, payload: bytes) -> None:
        relative = self._relative(path)
        parent = self._open_directory(str(relative.parent), create=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            try:
                fd = os.open(relative.name, flags, 0o600, dir_fd=parent)
            except FileExistsError:
                read_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                existing = self._read_fd(os.open(relative.name, read_flags, dir_fd=parent))
                if existing != payload:
                    raise ArtifactIntegrityError("immutable artifact collision")
                return
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush(); os.fsync(handle.fileno())
        finally:
            os.close(parent)

    def _content_path(self, digest: str) -> Path:
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ArtifactIntegrityError("invalid sha256 digest")
        return self._safe_path(f"store/sha256/{digest[:2]}/{digest}")

    def _association_path(self, ref: str) -> Path:
        ref_hash = hashlib.sha256(ref.encode("utf-8")).hexdigest()
        return self._safe_path(f"refs/sha256/{ref_hash[:2]}/{ref_hash}.json")

    def put_raw(self, ref: str, data: bytes, *, media_type: str = "application/octet-stream") -> ArtifactRef:
        ref = self._validate_ref(ref)
        if not isinstance(data, bytes):
            raise TypeError("raw artifacts must be bytes")
        digest = hashlib.sha256(data).hexdigest()
        content = self._content_path(digest)
        self._write_create_only(content, data)
        if hashlib.sha256(self._read_file(content)).hexdigest() != digest:
            raise ArtifactIntegrityError("stored content digest mismatch")
        association = ArtifactRef(ref, digest, media_type)
        self._write_create_only(self._association_path(ref), _json_bytes(association.to_dict()))
        return association

    def put_canonical(
        self, ref: str, value: Any, *, media_type: str = "application/json",
        serializer: Callable[[Any], bytes] | None = None, validator: Callable[[Any], None] | None = None,
    ) -> ArtifactRef:
        if validator is not None:
            validator(value)
        elif isinstance(value, Mapping):
            self._validate_known_canonical(value)
        payload = serializer(value) if serializer is not None else _json_bytes(value)
        return self.put_raw(ref, payload, media_type=media_type)

    @staticmethod
    def _validate_known_canonical(value: Mapping[str, Any]) -> None:
        """Dispatch only frozen validators; unknown operational JSON stays explicit."""
        schema = str(value.get("schema_version") or "")
        if schema == "cipherlens.vc.v0_3":
            from contract_miner.schema import validate_vc_or_raise; validate_vc_or_raise(value)
        elif schema == "cipherlens.transfer_signature.v0.1":
            from transfer_signature.canonical import validate_signature_or_raise; validate_signature_or_raise(value)
        elif schema == "cipherlens.candidate_binding.v0.1":
            from candidate_binding.validate import validate_candidate_binding_or_raise; validate_candidate_binding_or_raise(value)
        elif schema == "cipherlens.candidate_binding_validation.v0.1":
            from candidate_binding.validate import validate_validation_artifact_or_raise; validate_validation_artifact_or_raise(value)
        elif schema == "cipherlens.template_binding_merge.v0.1":
            from template_binding_merge.validate import validate_merge_or_raise; validate_merge_or_raise(value)
        elif schema == "cipherlens.bound_template_source.v0.1":
            from template_binding_merge.validate import validate_bound_source_or_raise; validate_bound_source_or_raise(value)
        elif schema == "cipherlens.bound_source_map.v0.1":
            from template_binding_merge.validate import validate_source_map_or_raise; validate_source_map_or_raise(value)
        elif schema == "cipherlens.template_binding_merge_validation.v0.1":
            from template_binding_merge.validate import validate_merge_validation_or_raise; validate_merge_validation_or_raise(value)
        else:
            from execution_model.model import SCHEMA_VERSIONS
            if schema in SCHEMA_VERSIONS.values():
                from execution_model.registry import validate_artifact_or_raise; validate_artifact_or_raise(value)

    def get(self, ref: str, digest: str) -> bytes:
        ref = self._validate_ref(ref)
        association = self._association_path(ref)
        record = json.loads(self._read_file(association).decode("utf-8"))
        if record.get("artifact_ref") != ref or record.get("artifact_digest") != digest:
            raise ArtifactIntegrityError("artifact ref/digest mismatch")
        content = self._content_path(digest)
        data = self._read_file(content)
        if hashlib.sha256(data).hexdigest() != digest:
            raise ArtifactIntegrityError("artifact digest spoofing detected")
        return data

    def verify(self, ref: str, digest: str) -> bool:
        try:
            self.get(ref, digest)
            return True
        except (ArtifactIntegrityError, OSError, json.JSONDecodeError):
            return False

    def exists(self, ref: str, digest: str) -> bool:
        return self.verify(ref, digest)

    def link_attempt(self, campaign_id: str, attempt_id: str, artifact: ArtifactRef) -> ArtifactRef:
        if not campaign_id or not attempt_id:
            raise ArtifactIntegrityError("campaign and attempt identifiers are required")
        return self.put_canonical(
            f"campaigns/{campaign_id}/attempts/{attempt_id}/{artifact.digest}.link.json",
            {"campaign_id": campaign_id, "attempt_id": attempt_id, "artifact": artifact.to_dict()},
        )
