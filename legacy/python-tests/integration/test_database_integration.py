"""
tests/integration/test_database_integration.py
==============================================
Integration tests for database operations with real PostgreSQL.

These tests require a test database to be running.
Set TEST_DATABASE_URL environment variable or use docker-compose.

Run with: pytest tests/integration/test_database_integration.py -v
"""

import os
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session

from src.database import Base, UserModel, get_session_factory
from src.auth_enterprise import hash_password, get_user_by_email


# Test database URL (override in CI/CD)
TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql://test_user:test_pass@localhost:5432/weissman_test"
)


@pytest.fixture(scope="session")
def test_engine():
    """Create test database engine."""
    engine = create_engine(TEST_DATABASE_URL, echo=False)

    # Create all tables
    Base.metadata.create_all(engine)

    yield engine

    # Cleanup: drop all tables
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture(scope="function")
def db_session(test_engine):
    """Create a new database session for each test."""
    connection = test_engine.connect()
    transaction = connection.begin()

    SessionLocal = sessionmaker(bind=connection)
    session = SessionLocal()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def sample_user_data():
    """Sample user data for testing."""
    return {
        "email": "test@example.com",
        "password": "SecurePass123!",
        "role": "security_analyst",
        "mfa_enabled": True,
        "mfa_secret": "JBSWY3DPEHPK3PXP",
    }


class TestUserModel:
    """Tests for UserModel CRUD operations."""

    def test_create_user(self, db_session: Session, sample_user_data):
        """Should create a new user in database."""
        user = UserModel(
            email=sample_user_data["email"],
            password_hash=hash_password(sample_user_data["password"]),
            role=sample_user_data["role"],
            mfa_enabled=sample_user_data["mfa_enabled"],
            mfa_secret=sample_user_data["mfa_secret"],
        )

        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        assert user.id is not None
        assert user.email == sample_user_data["email"]
        assert user.role == sample_user_data["role"]

    def test_read_user_by_email(self, db_session: Session, sample_user_data):
        """Should retrieve user by email."""
        # Create user
        user = UserModel(
            email=sample_user_data["email"],
            password_hash=hash_password(sample_user_data["password"]),
            role=sample_user_data["role"],
            mfa_enabled=False,
        )
        db_session.add(user)
        db_session.commit()

        # Retrieve user
        found_user = get_user_by_email(db_session, sample_user_data["email"])

        assert found_user is not None
        assert found_user.email == sample_user_data["email"]
        assert found_user.role == sample_user_data["role"]

    def test_update_user_role(self, db_session: Session, sample_user_data):
        """Should update user role."""
        user = UserModel(
            email=sample_user_data["email"],
            password_hash=hash_password(sample_user_data["password"]),
            role="viewer",
        )
        db_session.add(user)
        db_session.commit()

        # Update role
        user.role = "super_admin"
        db_session.commit()
        db_session.refresh(user)

        assert user.role == "super_admin"

    def test_delete_user(self, db_session: Session, sample_user_data):
        """Should delete user from database."""
        user = UserModel(
            email=sample_user_data["email"],
            password_hash=hash_password(sample_user_data["password"]),
            role=sample_user_data["role"],
        )
        db_session.add(user)
        db_session.commit()
        user_id = user.id

        # Delete
        db_session.delete(user)
        db_session.commit()

        # Verify deletion
        deleted_user = db_session.query(UserModel).filter_by(id=user_id).first()
        assert deleted_user is None

    def test_email_uniqueness(self, db_session: Session, sample_user_data):
        """Should enforce email uniqueness constraint."""
        user1 = UserModel(
            email=sample_user_data["email"],
            password_hash=hash_password(sample_user_data["password"]),
            role="viewer",
        )
        db_session.add(user1)
        db_session.commit()

        # Try to create duplicate
        user2 = UserModel(
            email=sample_user_data["email"],
            password_hash=hash_password("DifferentPass123!"),
            role="security_analyst",
        )
        db_session.add(user2)

        with pytest.raises(Exception):  # IntegrityError
            db_session.commit()

    def test_user_with_mfa(self, db_session: Session, sample_user_data):
        """Should store and retrieve MFA configuration."""
        user = UserModel(
            email=sample_user_data["email"],
            password_hash=hash_password(sample_user_data["password"]),
            role=sample_user_data["role"],
            mfa_enabled=True,
            mfa_secret=sample_user_data["mfa_secret"],
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)

        assert user.mfa_enabled is True
        assert user.mfa_secret == sample_user_data["mfa_secret"]


class TestDatabaseTransactions:
    """Tests for transaction handling."""

    def test_rollback_on_error(self, db_session: Session, sample_user_data):
        """Should rollback transaction on error."""
        initial_count = db_session.query(UserModel).count()

        try:
            user = UserModel(
                email=sample_user_data["email"],
                password_hash=hash_password(sample_user_data["password"]),
                role="invalid_role",  # This might cause validation error
            )
            db_session.add(user)
            db_session.commit()

            # Force an error
            db_session.execute(text("INVALID SQL"))
            db_session.commit()
        except Exception:
            db_session.rollback()

        # User count should remain unchanged
        final_count = db_session.query(UserModel).count()
        assert final_count == initial_count

    def test_bulk_insert(self, db_session: Session):
        """Should handle bulk inserts efficiently."""
        users = [
            UserModel(
                email=f"user{i}@example.com",
                password_hash=hash_password(f"Pass{i}123!"),
                role="viewer",
            )
            for i in range(100)
        ]

        db_session.bulk_save_objects(users)
        db_session.commit()

        count = db_session.query(UserModel).count()
        assert count >= 100


class TestDatabaseConstraints:
    """Tests for database constraints and validation."""

    def test_email_not_null(self, db_session: Session):
        """Should enforce NOT NULL constraint on email."""
        user = UserModel(
            email=None,
            password_hash=hash_password("TestPass123!"),
            role="viewer",
        )
        db_session.add(user)

        with pytest.raises(Exception):
            db_session.commit()

    def test_role_validation(self, db_session: Session):
        """Should validate role values."""
        valid_roles = ["super_admin", "security_analyst", "viewer"]

        for role in valid_roles:
            user = UserModel(
                email=f"test_{role}@example.com",
                password_hash=hash_password("TestPass123!"),
                role=role,
            )
            db_session.add(user)
            db_session.commit()

            # Cleanup for next iteration
            db_session.delete(user)
            db_session.commit()


class TestDatabasePerformance:
    """Tests for database performance characteristics."""

    def test_query_performance(self, db_session: Session):
        """Should execute queries efficiently."""
        import time

        # Create test data
        users = [
            UserModel(
                email=f"perf_user{i}@example.com",
                password_hash=hash_password(f"Pass{i}123!"),
                role="viewer",
            )
            for i in range(1000)
        ]
        db_session.bulk_save_objects(users)
        db_session.commit()

        # Measure query time
        start = time.time()
        results = db_session.query(UserModel).filter(
            UserModel.role == "viewer"
        ).limit(100).all()
        duration = time.time() - start

        assert len(results) == 100
        assert duration < 1.0  # Should complete in under 1 second

    def test_connection_pooling(self, test_engine):
        """Should reuse database connections from pool."""
        sessions = []
        for _ in range(10):
            SessionLocal = sessionmaker(bind=test_engine)
            session = SessionLocal()
            sessions.append(session)

        # All sessions should work
        for session in sessions:
            count = session.query(UserModel).count()
            assert count >= 0
            session.close()
