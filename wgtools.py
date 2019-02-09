"""Python bindings for WireGuard."""

from collections import namedtuple
from subprocess import PIPE, check_output, Popen


__all__ = ['WG', 'Keypair', 'genkey', 'pubkey', 'keypair', 'genpsk']


WG = '/usr/bin/wg'


Keypair = namedtuple('Keypair', ('public', 'private'))


def genkey(*, _wg=WG):
    """Generates a new private key."""

    return check_output((_wg, 'genkey')).decode().strip()


def pubkey(private, *, _wg=WG):
    """Generates a public key for the given private key."""

    subproc = Popen((_wg, 'pubkey'), stdin=PIPE, stdout=PIPE)
    public, _ = subproc.communicate(private.encode())
    return public.decode().strip()


def keypair(*, _wg=WG):
    """Generates a public-private key pair."""

    private = genkey(_wg=_wg)
    public = pubkey(private, _wg=_wg)
    return Keypair(public, private)


def genpsk(*, _wg=WG):
    """Generates a pre-shared key."""

    return check_output((_wg, 'genpsk')).decode().strip()
