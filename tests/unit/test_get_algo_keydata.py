import pytest

from typing import Any, Callable
from unittest.mock import patch, MagicMock

from patatt import (
    get_algo_keydata,
    NoKeyError,
    ConfigurationError,
    KEYCACHE,
    GitConfigType,
)


def _make_mock_get_config(
    usercfg: GitConfigType,
    gpgcfg: GitConfigType,
) -> Callable[..., GitConfigType]:
    """Return a mock get_config_from_git that dispatches on the regexp arg."""

    def _mock(regexp: str, **kwargs: object) -> GitConfigType:
        if regexp == r'user\..*':
            return dict(usercfg)
        if regexp == r'gpg\..*':
            # When called with section='ssh', return empty (irrelevant here)
            if kwargs.get('section'):
                return {}
            return dict(gpgcfg)
        return {}

    return _mock


class TestGetAlgoKeydataSSHSigningKey:
    """Tests for the user.signingkey + gpg.format detection in get_algo_keydata."""

    def setup_method(self) -> None:
        """Clear KEYCACHE before each test to avoid cross-test pollution."""
        KEYCACHE.clear()

    @patch('patatt.get_config_from_git')
    def test_ssh_format_uses_openssh(self, mock_gcfg: MagicMock) -> None:
        """When gpg.format=ssh, user.signingkey should get the openssh: prefix."""
        mock_gcfg.side_effect = _make_mock_get_config(
            usercfg={'email': 'test@example.com', 'signingkey': '/home/user/.ssh/id_ed25519.pub'},
            gpgcfg={'format': 'ssh'},
        )
        config: GitConfigType = {'identity': 'test@example.com'}
        algo, keydata = get_algo_keydata(config)

        assert algo == 'openssh'
        assert keydata == '/home/user/.ssh/id_ed25519.pub'
        assert config['signingkey'] == 'openssh:/home/user/.ssh/id_ed25519.pub'

    @patch('patatt.get_config_from_git')
    def test_gpg_format_uses_openpgp(self, mock_gcfg: MagicMock) -> None:
        """When gpg.format=gpg (explicit), user.signingkey should get the openpgp: prefix."""
        mock_gcfg.side_effect = _make_mock_get_config(
            usercfg={'email': 'test@example.com', 'signingkey': 'DEADBEEF'},
            gpgcfg={'format': 'gpg'},
        )
        config: GitConfigType = {'identity': 'test@example.com'}
        algo, keydata = get_algo_keydata(config)

        assert algo == 'openpgp'
        assert keydata == 'DEADBEEF'
        assert config['signingkey'] == 'openpgp:DEADBEEF'

    @patch('patatt.get_config_from_git')
    def test_no_gpg_format_defaults_to_openpgp(self, mock_gcfg: MagicMock) -> None:
        """When gpg.format is not set, default to openpgp."""
        mock_gcfg.side_effect = _make_mock_get_config(
            usercfg={'email': 'test@example.com', 'signingkey': 'ABCD1234'},
            gpgcfg={},  # no 'format' key at all
        )
        config: GitConfigType = {'identity': 'test@example.com'}
        algo, keydata = get_algo_keydata(config)

        assert algo == 'openpgp'
        assert keydata == 'ABCD1234'

    @patch('patatt.get_config_from_git')
    def test_no_signingkey_raises_nokeyerror(self, mock_gcfg: MagicMock) -> None:
        """When neither patatt.signingkey nor user.signingkey is set, raise NoKeyError."""
        mock_gcfg.side_effect = _make_mock_get_config(
            usercfg={'email': 'test@example.com'},
            gpgcfg={},
        )
        config: GitConfigType = {'identity': 'test@example.com'}

        with pytest.raises(NoKeyError, match='patatt.signingkey is not set'):
            get_algo_keydata(config)

    @patch('patatt.get_config_from_git')
    def test_patatt_signingkey_skips_user_signingkey(self, mock_gcfg: MagicMock) -> None:
        """When patatt.signingkey is already set, user.signingkey is not consulted."""
        mock_gcfg.side_effect = _make_mock_get_config(
            usercfg={'email': 'test@example.com', 'signingkey': 'SHOULD_NOT_BE_USED'},
            gpgcfg={'format': 'ssh'},
        )
        config: GitConfigType = {
            'identity': 'test@example.com',
            'signingkey': 'openpgp:MY_GPG_KEY',
        }
        algo, keydata = get_algo_keydata(config)

        assert algo == 'openpgp'
        assert keydata == 'MY_GPG_KEY'

    @patch('patatt.get_config_from_git')
    def test_identity_from_user_email(self, mock_gcfg: MagicMock) -> None:
        """When config has no identity, it should be set from user.email."""
        mock_gcfg.side_effect = _make_mock_get_config(
            usercfg={'email': 'auto@example.com', 'signingkey': 'SOMEKEY'},
            gpgcfg={'format': 'ssh'},
        )
        config: GitConfigType = {}
        algo, keydata = get_algo_keydata(config)

        assert config['identity'] == 'auto@example.com'
        assert algo == 'openssh'

    @patch('patatt.get_config_from_git')
    def test_keycache_hit_skips_lookup(self, mock_gcfg: MagicMock) -> None:
        """When identity is already in KEYCACHE, return cached result directly."""
        KEYCACHE['cached@example.com'] = ('openssh', '/cached/key')

        mock_gcfg.side_effect = _make_mock_get_config(
            usercfg={'email': 'cached@example.com'},
            gpgcfg={},
        )
        config: GitConfigType = {'identity': 'cached@example.com'}
        algo, keydata = get_algo_keydata(config)

        assert algo == 'openssh'
        assert keydata == '/cached/key'

    @patch('patatt.get_config_from_git')
    def test_unknown_gpg_format_defaults_to_openpgp(self, mock_gcfg: MagicMock) -> None:
        """An unrecognized gpg.format value should fall through to openpgp."""
        mock_gcfg.side_effect = _make_mock_get_config(
            usercfg={'email': 'test@example.com', 'signingkey': 'SOMEKEY'},
            gpgcfg={'format': 'x509'},  # not 'ssh', so should be openpgp
        )
        config: GitConfigType = {'identity': 'test@example.com'}
        algo, keydata = get_algo_keydata(config)

        assert algo == 'openpgp'
        assert keydata == 'SOMEKEY'
