import pytest
import re
from io import BytesIO

from patatt import PatattMessage, ValidationError

from typing import Tuple

class TestPatattMessage:

    def test_initialization(self, sample_email_bytes: bytes) -> None:
        """Test initialization of PatattMessage with sample email."""
        message = PatattMessage(sample_email_bytes)

        assert len(message.headers) > 0
        assert len(message.body) > 0
        assert message.signed is False

    def test_load_from_bytes(self) -> None:
        """Test loading message from bytes."""
        email_bytes = b"""From: test@example.com
Subject: Test email

This is a test body.
"""
        message = PatattMessage(email_bytes)

        assert len(message.headers) == 2
        assert message.body == b"This is a test body.\n"

    def test_as_bytes(self, sample_email_bytes: bytes) -> None:
        """Test converting message back to bytes."""
        message = PatattMessage(sample_email_bytes)

        output = message.as_bytes()
        # The output should be the same as the input
        assert output == sample_email_bytes

    def test_as_string(self, sample_email_bytes: bytes) -> None:
        """Test converting message to string."""
        message = PatattMessage(sample_email_bytes)

        output = message.as_string()
        # The output should be a string representation of the input
        assert isinstance(output, str)
        assert output == sample_email_bytes.decode()

    def test_git_canonicalize(self, monkeypatch: pytest.MonkeyPatch, sample_email_bytes: bytes) -> None:
        """Test git canonicalization of message."""
        # Mock _get_git_mailinfo to avoid actual git command execution
        def mock_get_git_mailinfo(payload: bytes) -> Tuple[bytes, bytes, bytes]:
            # Return mock metadata, patch, and info
            metadata = b"Author: Test User\nEmail: test@example.com\nSubject: Test email\n"
            patch = b"This is a test body.\n"
            info = b"email: test@example.com\nauthor: Test User\nsubject: Test email\n"
            return metadata, patch, info

        monkeypatch.setattr(PatattMessage, "_get_git_mailinfo", mock_get_git_mailinfo)

        message = PatattMessage(sample_email_bytes)
        message.git_canonicalize()

        # Check that the message was canonicalized
        assert message.canon_body is not None
        assert message.canon_headers is not None
        assert message.canon_identity == "test@example.com"

    # @pytest.mark.skipif(True, reason="Requires actual signing setup")
    # def test_sign(self) -> None:
    #     """Test signing a message."""
    #     # This would require more complex setup and mocking
    #     pass
