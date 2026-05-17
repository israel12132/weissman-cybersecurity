"""
src/vault_client.py
===================
HashiCorp Vault integration for centralized secrets management.

Supports:
- KV v2 secrets engine
- Dynamic database credentials
- Encryption as a service
- Token renewal
- Graceful fallback to environment variables

Usage:
    from src.vault_client import get_secret, set_secret

    # Get secret
    api_key = get_secret("nvd_api_key")

    # Set secret
    set_secret("new_api_key", "secret_value")

Configuration:
    VAULT_ADDR=http://localhost:8200
    VAULT_TOKEN=your-token  # Or use VAULT_ROLE_ID + VAULT_SECRET_ID for AppRole
    VAULT_NAMESPACE=admin  # Optional, for Vault Enterprise
"""

import logging
import os
from typing import Optional, Dict, Any
from threading import Lock

logger = logging.getLogger("weissman.vault")

# Vault configuration
VAULT_ADDR = os.getenv("VAULT_ADDR", "http://localhost:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")
VAULT_ROLE_ID = os.getenv("VAULT_ROLE_ID")
VAULT_SECRET_ID = os.getenv("VAULT_SECRET_ID")
VAULT_NAMESPACE = os.getenv("VAULT_NAMESPACE")
VAULT_MOUNT_POINT = os.getenv("VAULT_MOUNT_POINT", "weissman")

# Lazy-init client
_vault_client: Optional[Any] = None
_vault_init_lock = Lock()


def _get_vault_client():
    """Lazy initialization of Vault client."""
    global _vault_client

    if _vault_client is not None:
        return _vault_client

    with _vault_init_lock:
        if _vault_client is not None:
            return _vault_client

        try:
            import hvac

            # Create client
            client = hvac.Client(url=VAULT_ADDR, namespace=VAULT_NAMESPACE)

            # Authenticate
            if VAULT_TOKEN:
                client.token = VAULT_TOKEN
                logger.info("vault: authenticated with token")
            elif VAULT_ROLE_ID and VAULT_SECRET_ID:
                response = client.auth.approle.login(
                    role_id=VAULT_ROLE_ID,
                    secret_id=VAULT_SECRET_ID,
                )
                client.token = response["auth"]["client_token"]
                logger.info("vault: authenticated with AppRole")
            else:
                logger.warning("vault: no credentials provided, falling back to env vars")
                return None

            # Verify authentication
            if not client.is_authenticated():
                logger.warning("vault: authentication failed")
                return None

            _vault_client = client
            logger.info("vault: client initialized successfully")
            return _vault_client

        except ImportError:
            logger.warning("vault: hvac library not installed, using env fallback")
            return None
        except Exception as exc:
            logger.warning("vault: initialization failed (%s), using env fallback", exc)
            return None


def get_secret(key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Retrieve secret from Vault or environment variable fallback.

    Parameters
    ----------
    key : str
        Secret key name
    default : str, optional
        Default value if secret not found

    Returns
    -------
    str or None
        Secret value

    Examples
    --------
    >>> api_key = get_secret("nvd_api_key")
    >>> db_password = get_secret("database_password", default="changeme")
    """
    client = _get_vault_client()

    if client is not None:
        try:
            # Read from KV v2 engine
            secret = client.secrets.kv.v2.read_secret_version(
                path=key,
                mount_point=VAULT_MOUNT_POINT,
            )

            value = secret["data"]["data"].get("value")
            if value:
                logger.debug("vault: retrieved secret %s", key)
                return value

        except Exception as exc:
            logger.warning("vault: failed to read secret %s (%s)", key, exc)

    # Fallback to environment variable
    env_value = os.getenv(key.upper())
    if env_value:
        logger.debug("vault: using env fallback for %s", key)
        return env_value

    return default


def set_secret(key: str, value: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
    """
    Store secret in Vault.

    Parameters
    ----------
    key : str
        Secret key name
    value : str
        Secret value
    metadata : dict, optional
        Additional metadata to store

    Returns
    -------
    bool
        True if successful, False otherwise

    Examples
    --------
    >>> set_secret("api_key", "secret_value_here")
    >>> set_secret("db_creds", "password", metadata={"rotation_date": "2024-01-01"})
    """
    client = _get_vault_client()

    if client is None:
        logger.warning("vault: cannot set secret %s, client unavailable", key)
        return False

    try:
        # Write to KV v2 engine
        client.secrets.kv.v2.create_or_update_secret(
            path=key,
            secret={"value": value, **(metadata or {})},
            mount_point=VAULT_MOUNT_POINT,
        )
        logger.info("vault: stored secret %s", key)
        return True

    except Exception as exc:
        logger.error("vault: failed to store secret %s (%s)", key, exc)
        return False


def delete_secret(key: str) -> bool:
    """
    Delete secret from Vault.

    Parameters
    ----------
    key : str
        Secret key name

    Returns
    -------
    bool
        True if successful, False otherwise
    """
    client = _get_vault_client()

    if client is None:
        return False

    try:
        client.secrets.kv.v2.delete_metadata_and_all_versions(
            path=key,
            mount_point=VAULT_MOUNT_POINT,
        )
        logger.info("vault: deleted secret %s", key)
        return True

    except Exception as exc:
        logger.error("vault: failed to delete secret %s (%s)", key, exc)
        return False


def encrypt_data(plaintext: str, context: Optional[str] = None) -> Optional[str]:
    """
    Encrypt data using Vault's transit engine.

    Parameters
    ----------
    plaintext : str
        Data to encrypt
    context : str, optional
        Additional context for key derivation

    Returns
    -------
    str or None
        Encrypted ciphertext (base64 encoded)

    Examples
    --------
    >>> ciphertext = encrypt_data("sensitive data")
    >>> print(ciphertext)
    vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM13ok481zoCmHnSeDX9vyf7w==
    """
    client = _get_vault_client()

    if client is None:
        logger.warning("vault: encryption unavailable")
        return None

    try:
        import base64

        # Encode plaintext
        plaintext_b64 = base64.b64encode(plaintext.encode()).decode()

        # Encrypt with transit engine
        response = client.secrets.transit.encrypt_data(
            name="weissman-encryption-key",
            plaintext=plaintext_b64,
            context=base64.b64encode(context.encode()).decode() if context else None,
        )

        ciphertext = response["data"]["ciphertext"]
        logger.debug("vault: encrypted data (length=%d)", len(plaintext))
        return ciphertext

    except Exception as exc:
        logger.error("vault: encryption failed (%s)", exc)
        return None


def decrypt_data(ciphertext: str, context: Optional[str] = None) -> Optional[str]:
    """
    Decrypt data using Vault's transit engine.

    Parameters
    ----------
    ciphertext : str
        Encrypted ciphertext from encrypt_data()
    context : str, optional
        Additional context used during encryption

    Returns
    -------
    str or None
        Decrypted plaintext

    Examples
    --------
    >>> plaintext = decrypt_data(ciphertext)
    >>> print(plaintext)
    sensitive data
    """
    client = _get_vault_client()

    if client is None:
        logger.warning("vault: decryption unavailable")
        return None

    try:
        import base64

        # Decrypt with transit engine
        response = client.secrets.transit.decrypt_data(
            name="weissman-encryption-key",
            ciphertext=ciphertext,
            context=base64.b64encode(context.encode()).decode() if context else None,
        )

        plaintext_b64 = response["data"]["plaintext"]
        plaintext = base64.b64decode(plaintext_b64).decode()

        logger.debug("vault: decrypted data (length=%d)", len(plaintext))
        return plaintext

    except Exception as exc:
        logger.error("vault: decryption failed (%s)", exc)
        return None


def renew_token() -> bool:
    """
    Renew Vault token to extend lease.

    Returns
    -------
    bool
        True if renewal successful, False otherwise
    """
    client = _get_vault_client()

    if client is None:
        return False

    try:
        client.auth.token.renew_self()
        logger.info("vault: token renewed successfully")
        return True

    except Exception as exc:
        logger.warning("vault: token renewal failed (%s)", exc)
        return False


def get_database_credentials(role: str = "weissman-db") -> Optional[Dict[str, str]]:
    """
    Get dynamic database credentials from Vault.

    Parameters
    ----------
    role : str
        Vault database role name

    Returns
    -------
    dict or None
        {"username": "...", "password": "..."}

    Examples
    --------
    >>> creds = get_database_credentials("weissman-db")
    >>> print(creds["username"])
    v-token-weissman-db-AbCdEf123
    """
    client = _get_vault_client()

    if client is None:
        return None

    try:
        response = client.secrets.database.generate_credentials(name=role)
        creds = response["data"]

        logger.info("vault: generated database credentials for role %s", role)
        return {
            "username": creds["username"],
            "password": creds["password"],
        }

    except Exception as exc:
        logger.error("vault: failed to generate db credentials (%s)", exc)
        return None


def health_check() -> Dict[str, Any]:
    """
    Check Vault health and connection status.

    Returns
    -------
    dict
        {
            "enabled": bool,
            "authenticated": bool,
            "addr": str,
            "version": str or None,
        }
    """
    client = _get_vault_client()

    if client is None:
        return {
            "enabled": False,
            "authenticated": False,
            "addr": VAULT_ADDR,
            "version": None,
        }

    try:
        health = client.sys.read_health_status(method="GET")
        return {
            "enabled": True,
            "authenticated": client.is_authenticated(),
            "addr": VAULT_ADDR,
            "version": health.get("version"),
            "sealed": health.get("sealed", True),
        }

    except Exception as exc:
        logger.warning("vault: health check failed (%s)", exc)
        return {
            "enabled": True,
            "authenticated": False,
            "addr": VAULT_ADDR,
            "version": None,
            "error": str(exc),
        }
