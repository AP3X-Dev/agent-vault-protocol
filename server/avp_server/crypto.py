from __future__ import annotations

import base64
import json
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import settings


class KeyProviderError(Exception):
    """Raised when key provider cannot provide a valid key."""
    pass


def _urlsafe_b64decode_padded(s: str) -> bytes:
    s = s.strip()
    if not s:
        return b""
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


class KeyProvider(ABC):
    """Abstract interface for encryption key providers.

    In production, implement this with a KMS-backed provider.
    """

    @abstractmethod
    def get_current_dek(self) -> Tuple[bytes, str]:
        """Return (dek_bytes, key_version) for encryption."""
        pass

    @abstractmethod
    def decrypt_with_key_version(self, key_version: str, blob: bytes) -> bytes:
        """Decrypt ciphertext using the specified key version.

        Args:
            key_version: The key version that was used for encryption
            blob: The ciphertext (nonce + encrypted data)

        Returns:
            The decrypted plaintext bytes
        """
        pass

    @property
    @abstractmethod
    def is_ephemeral(self) -> bool:
        """Return True if using an ephemeral (non-persistent) key."""
        pass


@dataclass(frozen=True)
class LocalEnvKeyProvider(KeyProvider):
    """Local key provider that reads DEK from environment.

    Supports:
    - Single key version (current implementation)
    - Strict production mode (fails if key missing/invalid)
    - Dev mode with optional ephemeral key

    For key rotation support, extend this to maintain a mapping
    of key_version -> dek_bytes.
    """
    dek: bytes
    key_version: str
    _is_ephemeral: bool

    def get_current_dek(self) -> Tuple[bytes, str]:
        return (self.dek, self.key_version)

    def decrypt_with_key_version(self, key_version: str, blob: bytes) -> bytes:
        # For v1, we only support single key version
        # Future: maintain a map of old versions for rotation
        if key_version != self.key_version and not self._is_ephemeral:
            # In production with stable keys, version mismatch is an error
            # With ephemeral keys, we accept any version (dev convenience)
            raise KeyProviderError(f"key version mismatch: stored={key_version}, current={self.key_version}")

        if len(blob) < 13:
            raise ValueError("ciphertext too short")
        nonce = blob[:12]
        ct = blob[12:]
        aesgcm = AESGCM(self.dek)
        return aesgcm.decrypt(nonce, ct, None)

    @property
    def is_ephemeral(self) -> bool:
        return self._is_ephemeral

    @staticmethod
    def from_settings() -> "LocalEnvKeyProvider":
        """Create key provider from settings with strict validation.

        Raises:
            KeyProviderError: If key is invalid/missing and ephemeral is not allowed
        """
        raw = settings.dek_b64
        dek: Optional[bytes] = None
        decode_error: Optional[str] = None

        try:
            decoded = _urlsafe_b64decode_padded(raw)
            if len(decoded) == 32:
                dek = decoded
            elif len(decoded) == 0:
                decode_error = "AVP_DEK_B64 is empty"
            else:
                decode_error = f"AVP_DEK_B64 decoded to {len(decoded)} bytes, expected 32"
        except Exception as e:
            decode_error = f"AVP_DEK_B64 is not valid base64: {e}"

        # Determine if we can use ephemeral key
        can_use_ephemeral = settings.dev_mode and settings.allow_ephemeral_dek

        if dek is not None:
            # Valid key provided
            return LocalEnvKeyProvider(
                dek=dek,
                key_version=settings.key_version,
                _is_ephemeral=False
            )

        if can_use_ephemeral:
            # Dev mode with ephemeral allowed - generate temporary key
            # WARNING: Secrets encrypted with this key are lost on restart!
            import logging
            logging.warning(
                "AVP: Using ephemeral encryption key. "
                "Secrets will be UNRECOVERABLE after restart. "
                "This is only acceptable for development."
            )
            return LocalEnvKeyProvider(
                dek=secrets.token_bytes(32),
                key_version="ephemeral",
                _is_ephemeral=True
            )

        # No valid key and ephemeral not allowed - fail
        if settings.dev_mode:
            raise KeyProviderError(
                f"{decode_error}. "
                f"Set AVP_DEK_B64 to a valid 32-byte base64 key, or "
                f"set AVP_ALLOW_EPHEMERAL_DEK=true for development (secrets will be lost on restart)."
            )
        else:
            raise KeyProviderError(
                f"Production mode requires valid encryption key. {decode_error}. "
                f"Set AVP_DEK_B64 to a valid 32-byte base64-encoded key."
            )


# Module-level singleton - will raise on import if key invalid in production
_key_provider: Optional[LocalEnvKeyProvider] = None


def _get_key_provider() -> LocalEnvKeyProvider:
    """Get or initialize the key provider singleton."""
    global _key_provider
    if _key_provider is None:
        _key_provider = LocalEnvKeyProvider.from_settings()
    return _key_provider


def validate_key_provider() -> None:
    """Validate key provider on startup. Call this during app initialization.

    Raises:
        KeyProviderError: If key configuration is invalid
    """
    _get_key_provider()


def encrypt_json(data: Dict[str, Any]) -> bytes:
    """Encrypt a JSON-serializable dict using AES-GCM."""
    provider = _get_key_provider()
    dek, _ = provider.get_current_dek()
    plaintext = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    aesgcm = AESGCM(dek)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_json(blob: bytes, key_version: Optional[str] = None) -> Dict[str, Any]:
    """Decrypt a JSON blob encrypted with encrypt_json.

    Args:
        blob: The ciphertext (nonce + encrypted data)
        key_version: Optional key version hint (for future key rotation support)
    """
    provider = _get_key_provider()
    # For v1, we use current key version for all decryption
    # Future: use key_version parameter for rotation support
    version_to_use = key_version or provider.key_version
    pt = provider.decrypt_with_key_version(version_to_use, blob)
    return json.loads(pt.decode("utf-8"))


def current_key_version() -> str:
    """Get the current key version string."""
    provider = _get_key_provider()
    _, version = provider.get_current_dek()
    return version


def is_using_ephemeral_key() -> bool:
    """Check if the current key provider is using an ephemeral key."""
    provider = _get_key_provider()
    return provider.is_ephemeral
