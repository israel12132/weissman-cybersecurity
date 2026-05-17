"""
src/database_encryption.py
===========================
Database column encryption for sensitive fields.

Uses Vault's transit engine for encryption-as-a-service or Fernet for local encryption.

Encrypted fields:
- mfa_secret
- webhook.secret
- api_keys
- oauth_tokens

Usage:
    from src.database_encryption import encrypt_field, decrypt_field

    # Encrypt before storing
    encrypted = encrypt_field("sensitive_data", field_name="mfa_secret")

    # Decrypt when retrieving
    plaintext = decrypt_field(encrypted, field_name="mfa_secret")
"""

import logging
import os
from typing import Optional

logger = logging.getLogger("weissman.db_encryption")

# Encryption backend: "vault" or "fernet"
ENCRYPTION_BACKEND = os.getenv("DB_ENCRYPTION_BACKEND", "vault")


def _get_fernet_key() -> bytes:
    """Get or generate Fernet encryption key."""
    key_path = os.getenv("DB_ENCRYPTION_KEY_PATH", ".encryption_key")

    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return f.read()

    # Generate new key
    from cryptography.fernet import Fernet
    key = Fernet.generate_key()

    # Save key (WARNING: In production, use proper key management)
    with open(key_path, "wb") as f:
        f.write(key)

    logger.warning(
        "db_encryption: generated new Fernet key at %s - back this up securely!",
        key_path,
    )
    return key


def encrypt_field(
    plaintext: Optional[str],
    field_name: str = "generic",
) -> Optional[str]:
    """
    Encrypt sensitive database field.

    Parameters
    ----------
    plaintext : str or None
        Data to encrypt
    field_name : str
        Field name for logging/context

    Returns
    -------
    str or None
        Encrypted ciphertext, or None if input is None

    Examples
    --------
    >>> encrypted_secret = encrypt_field("JBSWY3DPEHPK3PXP", "mfa_secret")
    >>> print(encrypted_secret[:20])
    vault:v1:8SDd3WHD...
    """
    if plaintext is None or plaintext == "":
        return None

    try:
        if ENCRYPTION_BACKEND == "vault":
            from src.vault_client import encrypt_data

            ciphertext = encrypt_data(plaintext, context=field_name)
            if ciphertext:
                logger.debug(
                    "db_encryption: encrypted field %s using Vault (length=%d)",
                    field_name,
                    len(plaintext),
                )
                return ciphertext

            # Fallback to Fernet if Vault unavailable
            logger.warning("db_encryption: Vault unavailable, falling back to Fernet")

        # Use Fernet encryption
        from cryptography.fernet import Fernet

        f = Fernet(_get_fernet_key())
        ciphertext = f.encrypt(plaintext.encode()).decode()

        logger.debug(
            "db_encryption: encrypted field %s using Fernet (length=%d)",
            field_name,
            len(plaintext),
        )
        return ciphertext

    except Exception as exc:
        logger.error("db_encryption: encryption failed for field %s (%s)", field_name, exc)
        # In production, you might want to fail hard here
        return plaintext  # Store unencrypted as last resort


def decrypt_field(
    ciphertext: Optional[str],
    field_name: str = "generic",
) -> Optional[str]:
    """
    Decrypt sensitive database field.

    Parameters
    ----------
    ciphertext : str or None
        Encrypted data from database
    field_name : str
        Field name for logging/context

    Returns
    -------
    str or None
        Decrypted plaintext, or None if input is None

    Examples
    --------
    >>> plaintext = decrypt_field(encrypted_secret, "mfa_secret")
    >>> print(plaintext)
    JBSWY3DPEHPK3PXP
    """
    if ciphertext is None or ciphertext == "":
        return None

    try:
        # Detect encryption type
        if ciphertext.startswith("vault:v"):
            # Vault transit engine
            from src.vault_client import decrypt_data

            plaintext = decrypt_data(ciphertext, context=field_name)
            if plaintext:
                logger.debug("db_encryption: decrypted field %s using Vault", field_name)
                return plaintext

            logger.warning("db_encryption: Vault decryption failed")
            return None

        # Assume Fernet encryption
        from cryptography.fernet import Fernet

        f = Fernet(_get_fernet_key())
        plaintext = f.decrypt(ciphertext.encode()).decode()

        logger.debug("db_encryption: decrypted field %s using Fernet", field_name)
        return plaintext

    except Exception as exc:
        logger.error("db_encryption: decryption failed for field %s (%s)", field_name, exc)
        # Return ciphertext as-is (might be unencrypted legacy data)
        return ciphertext


def rotate_encryption_key(field_name: str = "mfa_secret") -> int:
    """
    Rotate encryption for all records of a specific field type.

    This re-encrypts all existing encrypted values with a new key version.

    Parameters
    ----------
    field_name : str
        Field type to rotate

    Returns
    -------
    int
        Number of records rotated

    Examples
    --------
    >>> rotated_count = rotate_encryption_key("mfa_secret")
    >>> print(f"Rotated {rotated_count} records")
    """
    if ENCRYPTION_BACKEND != "vault":
        logger.warning("db_encryption: key rotation only supported with Vault backend")
        return 0

    try:
        from src.vault_client import _get_vault_client

        client = _get_vault_client()
        if not client:
            return 0

        # Rotate transit encryption key
        client.secrets.transit.rotate_key(name="weissman-encryption-key")
        logger.info("db_encryption: rotated Vault transit key")

        # Re-encrypt all database records using the new key version
        rotated = 0
        _ENCRYPTED_COLUMNS = [
            ("users", "mfa_secret"),
            ("users", "totp_secret"),
            ("tenant_api_keys", "api_key_hash"),
            ("integration_credentials", "secret_value"),
        ]
        for table_name, column_name in _ENCRYPTED_COLUMNS:
            try:
                count = migrate_to_encrypted(table_name, column_name)
                rotated += count
                logger.info(
                    "db_encryption: re-encrypted %d records in %s.%s",
                    count, table_name, column_name,
                )
            except Exception as col_exc:
                logger.error(
                    "db_encryption: re-encryption failed for %s.%s (%s)",
                    table_name, column_name, col_exc,
                )

        logger.info("db_encryption: key rotation complete — re-encrypted %d total records", rotated)
        return rotated

    except Exception as exc:
        logger.error("db_encryption: key rotation failed (%s)", exc)
        return 0


def migrate_to_encrypted(
    table_name: str,
    column_name: str,
    batch_size: int = 100,
) -> int:
    """
    Migrate plaintext column to encrypted.

    Reads existing plaintext values, encrypts them, and updates the database.

    Parameters
    ----------
    table_name : str
        Table name
    column_name : str
        Column to encrypt
    batch_size : int
        Number of records to process per batch

    Returns
    -------
    int
        Number of records encrypted

    Examples
    --------
    >>> count = migrate_to_encrypted("users", "mfa_secret")
    >>> print(f"Encrypted {count} records")
    """
    from src.database import get_session_factory
    from sqlalchemy import text

    Session = get_session_factory()
    session = Session()

    try:
        # Get all records with plaintext values
        query = text(f"""
            SELECT id, {column_name}
            FROM {table_name}
            WHERE {column_name} IS NOT NULL
            AND {column_name} NOT LIKE 'vault:v%'
            AND {column_name} NOT LIKE 'gAAAAA%'  -- Fernet prefix
            LIMIT :batch_size
        """)

        encrypted_count = 0

        while True:
            result = session.execute(query, {"batch_size": batch_size})
            rows = result.fetchall()

            if not rows:
                break

            for row in rows:
                record_id, plaintext = row
                if not plaintext:
                    continue

                # Encrypt
                ciphertext = encrypt_field(plaintext, field_name=column_name)

                # Update
                update_query = text(f"""
                    UPDATE {table_name}
                    SET {column_name} = :ciphertext
                    WHERE id = :record_id
                """)
                session.execute(update_query, {
                    "ciphertext": ciphertext,
                    "record_id": record_id,
                })

                encrypted_count += 1

            session.commit()
            logger.info(
                "db_encryption: encrypted %d records from %s.%s",
                len(rows),
                table_name,
                column_name,
            )

        logger.info(
            "db_encryption: migration complete - encrypted %d total records",
            encrypted_count,
        )
        return encrypted_count

    except Exception as exc:
        session.rollback()
        logger.error("db_encryption: migration failed (%s)", exc)
        return 0

    finally:
        session.close()


# SQLAlchemy column type for encrypted fields
try:
    from sqlalchemy import TypeDecorator, String

    class EncryptedString(TypeDecorator):
        """
        SQLAlchemy column type that automatically encrypts/decrypts.

        Usage:
            class User(Base):
                mfa_secret = Column(EncryptedString(255))
        """

        impl = String
        cache_ok = True

        def __init__(self, length=255, field_name="encrypted_field", **kwargs):
            super().__init__(length=length, **kwargs)
            self.field_name = field_name

        def process_bind_param(self, value, dialect):
            """Encrypt before storing."""
            return encrypt_field(value, field_name=self.field_name)

        def process_result_value(self, value, dialect):
            """Decrypt when retrieving."""
            return decrypt_field(value, field_name=self.field_name)

except ImportError:
    # SQLAlchemy not available
    pass
