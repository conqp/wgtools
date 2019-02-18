"""Python bindings for WireGuard."""

from collections import namedtuple
from subprocess import check_output


__all__ = ['WG', 'Keypair', 'genkey', 'pubkey', 'keypair', 'genpsk']


WG = '/usr/bin/wg'


Keypair = namedtuple('Keypair', ('public', 'private'))


def genkey(*, _wg=WG):
    """Generates a new private key."""

    return check_output((_wg, 'genkey'), universal_newlines=True).strip()


def pubkey(key, *, _wg=WG):
    """Generates a public key for the given private key."""

    return check_output(
        (_wg, 'pubkey'), input=key, universal_newlines=True).strip()


def keypair(*, _wg=WG):
    """Generates a public-private key pair."""

    private = genkey(_wg=_wg)
    public = pubkey(private, _wg=_wg)
    return Keypair(public, private)


def genpsk(*, _wg=WG):
    """Generates a pre-shared key."""

    return check_output((_wg, 'genpsk'), universal_newlines=True).strip()
