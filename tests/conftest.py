from pathlib import Path

import os
import tempfile
import pytest
import base64

from patatt import DevsigHeader, PatattMessage

from typing import Generator, Dict

@pytest.fixture
def sample_email_bytes() -> bytes:
    """A simple email message in bytes format."""
    return b"""From: test@example.com
Subject: Test email
Message-ID: <12345@example.com>

This is a test email body.
"""

@pytest.fixture
def temp_data_dir() -> Generator[str, None, None]:
    """Create a temporary data directory structure for patatt."""
    with tempfile.TemporaryDirectory() as tmpdirname:
        # Create directory structure similar to patatt's data dir
        private_dir = Path(tmpdirname) / 'private'
        public_dir = Path(tmpdirname) / 'public'

        private_dir.mkdir()
        public_dir.mkdir()

        # Return path to the temp directory
        yield tmpdirname

@pytest.fixture
def devsig_header() -> DevsigHeader:
    """Create a basic DevsigHeader instance."""
    return DevsigHeader()

@pytest.fixture
def patatt_message(sample_email_bytes: bytes) -> PatattMessage:
    """Create a PatattMessage from a sample email."""
    return PatattMessage(sample_email_bytes)

@pytest.fixture
def sample_ed25519_key_pair() -> Dict[str, bytes]:
    """Generate a sample ed25519 key pair for testing."""
    try:
        from nacl.signing import SigningKey
    except ImportError:
        pytest.skip("PyNaCl not installed, skipping ed25519 tests")

    # Generate a key pair
    private_key = SigningKey.generate()
    public_key = private_key.verify_key

    # Return base64 encoded keys
    return {
        'private': base64.b64encode(bytes(private_key)),
        'public': base64.b64encode(public_key.encode())
    }