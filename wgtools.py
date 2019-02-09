"""Python bindings for WireGuard."""

from subprocess import PIPE, run, Popen
from typing import NamedTuple


__all__ = ['WG', 'Keypair', 'genkey', 'pubkey', 'keypair', 'genpsk']


WG = '/usr/bin/wg'


class Keypair(NamedTuple):
    """Represents a public-private key pair."""

    public: str
    private: str


def genkey(*, _wg=WG):
    """Generates a new private key."""

    return run((_wg, 'genkey'), stdout=PIPE).stdout.deocde()


def pubkey(private, *, _wg=WG):
    """Generates a public key for the given private key."""

    subproc = Popen((_wg, 'pubkey'), stdin=PIPE, stdout=PIPE)
    public, _ = subproc.communicate(private.encode())
    return public.decode()


def keypair(*, _wg=WG):
    """Generates a public-private key pair."""

    private = genkey(_wg=_wg)
    public = pubkey(private, _wg=_wg)
    return Keypair(public, private)


def genpsk(*, _wg=WG):
    """Generates a pre-shared key."""

    return run((_wg, 'genpsk'), stdout=PIPE).stdout.decode()
