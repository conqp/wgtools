"""Python bindings for WireGuard."""

from os import linesep
from subprocess import check_output
from typing import NamedTuple


__all__ = [
    'WG',
    'Keypair',
    'genkey',
    'pubkey',
    'keypair',
    'genpsk',
    'show'
]


WG = '/usr/bin/wg'


class Keypair(NamedTuple):
    """A public / private key pair."""

    public: str
    private: str


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


def _parse_interface(text):
    """Parses interface information from the given text."""

    interface = {'peers': {}}
    peer = None

    for line in text.split(linesep):
        key, value = line.strip().split(': ')

        if key == 'peer':
            interface['peers'][value] = peer = {}
            continue

        if peer is None:
            interface[key] = value
        else:
            peer[key] = value

    return interface


def _parse_interfaces(text):
    """parses interface information from
    the given text for multiple interfaces.
    """

    interfaces = {}
    interface = {}
    peer = None

    for line in text.split(linesep):
        key, value = line.strip().split(': ')

        if key == 'interface':
            interfaces[value] = interface = {'peers': {}}
            peer = None
            continue

        if key == 'peer':
            interface['peers'][value] = peer = {}
            continue

        if peer is None:
            interface[key] = value
        else:
            peer[key] = value

    return interfaces


def show(interface='all', *, _wg=WG):
    """Yields status information."""

    if interface == 'all':
        text = check_output((_wg, 'show', 'all'), text=True).strip()
        return _parse_interfaces(text)

    if interface == 'interfaces':
        text = check_output((_wg, 'show', 'interfaces'), text=True).strip()
        return text.split()

    text = check_output((_wg, 'show', interface), text=True).strip()
    return _parse_interface(text)
