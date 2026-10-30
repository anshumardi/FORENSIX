"""Local Ed25519 detached signatures for generated reports."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .config import Settings


def _key_paths(settings: Settings) -> tuple[Path, Path]:
    directory = settings.base_dir / "keys"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "ed25519-private.pem", directory / "ed25519-public.pem"


def ensure_signing_key(settings: Settings) -> tuple[Path, Path, str]:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise RuntimeError("cryptography is required for report signing") from exc
    private_path, public_path = _key_paths(settings)
    if not private_path.exists() or not public_path.exists():
        private = Ed25519PrivateKey.generate()
        public = private.public_key()
        private_path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        public_path.write_bytes(public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        private_path.chmod(0o600)
        public_path.chmod(0o644)
    public_bytes = public_path.read_bytes()
    fingerprint = hashlib.sha256(public_bytes).hexdigest()
    return private_path, public_path, fingerprint


def sign_report(settings: Settings, report_path: Path) -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization

    private_path, public_path, fingerprint = ensure_signing_key(settings)
    private = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    signature_name = f"{report_path.name}.sig"
    signature_path = report_path.with_name(signature_name)
    signature_path.write_bytes(private.sign(report_path.read_bytes()))
    signature_path.chmod(0o444)
    return signature_name, fingerprint


def verify_report(report_path: Path, signature_path: Path, public_key_path: Path) -> str:
    from cryptography.hazmat.primitives import serialization

    public = serialization.load_pem_public_key(public_key_path.read_bytes())
    public.verify(signature_path.read_bytes(), report_path.read_bytes())
    return hashlib.sha256(public_key_path.read_bytes()).hexdigest()
