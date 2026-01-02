import hashlib
import tempfile
from pathlib import Path

import pytest

from patatt import make_byhash_path, make_pkey_path, get_public_key


class TestMakeByhashPath:

    def test_basic_hash_computation(self) -> None:
        """Test that make_byhash_path computes the correct hash."""
        keytype = 'openssh'
        identity = 'user@example.com'
        selector = 'default'

        keypath = make_pkey_path(keytype, identity, selector)
        expected_hash = hashlib.sha256(str(keypath).encode('utf-8')).hexdigest()
        expected_prefix = expected_hash[:2]
        expected_remainder = expected_hash[2:]

        result = make_byhash_path(keytype, identity, selector)

        assert result == Path('by-hash', expected_prefix, expected_remainder)

    def test_path_format(self) -> None:
        """Test that the by-hash path has correct structure."""
        result = make_byhash_path('ed25519', 'mricon@kernel.org', '20210505')

        assert isinstance(result, Path)
        assert result.parts[0] == 'by-hash'
        assert len(result.parts[1]) == 2  # 2-char prefix
        assert len(result.parts[2]) == 62  # remaining 62 chars of sha256 hex

    def test_different_identities_produce_different_hashes(self) -> None:
        """Test that different identities produce different by-hash paths."""
        result1 = make_byhash_path('openssh', 'user1@example.com', 'default')
        result2 = make_byhash_path('openssh', 'user2@example.com', 'default')

        assert result1 != result2


class TestGetPublicKeyByHash:

    def test_filesystem_byhash_lookup(self) -> None:
        """Test that get_public_key finds a key via by-hash fallback."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a keypath that won't exist at the standard location
            keytype = 'ed25519'
            identity = 'test@example.com'
            selector = 'default'

            # Compute the by-hash path
            byhash_path = make_byhash_path(keytype, identity, selector)

            # Create the by-hash directory and file
            full_byhash_path = Path(tmpdir) / byhash_path
            full_byhash_path.parent.mkdir(parents=True, exist_ok=True)

            # Write a test key
            test_key = b'test-public-key-data'
            full_byhash_path.write_bytes(test_key)

            # Now try to get the key - should find it via by-hash fallback
            key_data, key_source = get_public_key(tmpdir, keytype, identity, selector)

            assert key_data == test_key
            assert 'by-hash' in key_source

    def test_standard_path_takes_precedence(self) -> None:
        """Test that standard path is preferred over by-hash path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            keytype = 'ed25519'
            identity = 'test@example.com'
            selector = 'default'

            keypath = make_pkey_path(keytype, identity, selector)
            byhash_path = make_byhash_path(keytype, identity, selector)

            # Create both standard and by-hash paths
            standard_full_path = Path(tmpdir) / keypath
            byhash_full_path = Path(tmpdir) / byhash_path

            standard_full_path.parent.mkdir(parents=True, exist_ok=True)
            byhash_full_path.parent.mkdir(parents=True, exist_ok=True)

            # Write different data to each
            standard_key = b'standard-key-data'
            byhash_key = b'byhash-key-data'
            standard_full_path.write_bytes(standard_key)
            byhash_full_path.write_bytes(byhash_key)

            # Should find standard path first
            key_data, key_source = get_public_key(tmpdir, keytype, identity, selector)

            assert key_data == standard_key
            assert 'by-hash' not in key_source

    def test_keyerror_when_neither_path_exists(self) -> None:
        """Test that KeyError is raised when neither path exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            keytype = 'ed25519'
            identity = 'nonexistent@example.com'
            selector = 'default'

            with pytest.raises(KeyError):
                get_public_key(tmpdir, keytype, identity, selector)
