"""Python bindings for WireGuard."""

from subprocess import check_output
from typing import NamedTuple


__all__ = ['WG', 'Keypair', 'genkey', 'pubkey', 'keypair', 'genpsk']


WG = '/usr/bin/wg'


def genkey(*, _wg=WG):
    """Generates a new private key."""

    return check_output((_wg, 'genkey'), text=True).strip()


def pubkey(key, *, _wg=WG):
    """Generates a public key for the given private key."""

    return check_output((_wg, 'pubkey'), input=key, text=True).strip()


def keypair(*, _wg=WG):
    """Generates a public-private key pair."""

    private = genkey(_wg=_wg)
    public = pubkey(private, _wg=_wg)
    return Keypair(public, private)


def genpsk(*, _wg=WG):
    """Generates a pre-shared key."""

    return check_output((_wg, 'genpsk'), text=True).strip()


class Keypair(NamedTuple):
    """A public / private key pair."""

    public: str
    private: str
