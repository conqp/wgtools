"""Python bindings for WireGuard."""

from collections import namedtuple
from subprocess import check_output


__all__ = ['WG', 'Keypair', 'genkey', 'pubkey', 'keypair', 'genpsk']


WG = '/usr/bin/wg'


Keypair = namedtuple('Keypair', ('public', 'private'))


def _check_text_output(*args, input=None):  # pylint: disable=W0622
    """Runs a subprocess and returns its text output."""

    if isinstance(input, str):
        input = input.encode()

    return check_output(args, input=input, universal_newlines=True).strip()


def genkey(*, _wg=WG):
    """Generates a new private key."""

    return _check_text_output(_wg, 'genkey')


def pubkey(key, *, _wg=WG):
    """Generates a public key for the given private key."""

    return _check_text_output(_wg, 'pubkey', input=key)


def keypair(*, _wg=WG):
    """Generates a public-private key pair."""

    private = genkey(_wg=_wg)
    public = pubkey(private, _wg=_wg)
    return Keypair(public, private)


def genpsk(*, _wg=WG):
    """Generates a pre-shared key."""

    return _check_text_output(_wg, 'genpsk')
