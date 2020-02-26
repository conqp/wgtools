"""Python bindings for WireGuard."""

from ipaddress import ip_network
from os import linesep
from pathlib import Path
from subprocess import check_call, check_output
from typing import NamedTuple


__all__ = [
    'WG',
    'Keypair',
    'genkey',
    'pubkey',
    'keypair',
    'genpsk',
    'show',
    'set'
]


WG = Path('/usr/bin/wg')


class Keypair(NamedTuple):
    """A public / private key pair."""

    public: str
    private: str


def genkey(*, _wg: str = WG) -> str:
    """Generates a new private key."""

    return check_output((_wg, 'genkey'), text=True).strip()


def pubkey(key: str, *, _wg: str = WG) -> str:
    """Generates a public key for the given private key."""

    return check_output((_wg, 'pubkey'), input=key, text=True).strip()


def keypair(*, _wg: str = WG) -> Keypair:
    """Generates a public-private key pair."""

    private = genkey(_wg=_wg)
    public = pubkey(private, _wg=_wg)
    return Keypair(public, private)


def genpsk(*, _wg: str = WG) -> str:
    """Generates a pre-shared key."""

    return check_output((_wg, 'genpsk'), text=True).strip()


def _parse_value(key, value):
    """Parses key / value pairs for wg show."""

    if key == 'allowed ips':
        return [ip_network(ip.strip()) for ip in value.split(',')]

    if key == 'listening port':
        return int(value)

    if key == 'transfer':
        received, sent = value.split(',')
        received = received.replace('received', '')
        sent = sent.replace('sent', '')
        return {'received': received.strip(), 'sent': sent.strip()}

    if value == '(hidden)':
        return None

    return value


def _parse_interface(text: str, raw: bool = False) -> dict:
    """Parses interface information from the given text."""

    interface = {'peers': {}}
    peer = None

    for line in text.split(linesep):
        line = line.strip()

        if not line:
            continue

        key, value = line.split(': ')

        if not raw:
            value = _parse_value(key, value)

        if key == 'peer':
            interface['peers'][value] = peer = {}
            continue

        if peer is None:
            interface[key] = value
        else:
            peer[key] = value

    return interface


def _parse_interfaces(text: str, raw: bool = False) -> dict:
    """parses interface information from
    the given text for multiple interfaces.
    """

    interfaces = {}
    interface = {}
    peer = None

    for line in text.split(linesep):
        line = line.strip()

        if not line:
            continue

        key, value = line.split(': ')

        if not raw:
            value = _parse_value(key, value)

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


def show(interface: str = 'all', *, raw: bool = False, _wg: str = WG):
    """Yields status information."""

    if interface == 'all':
        text = check_output((_wg, 'show', 'all'), text=True).strip()
        return _parse_interfaces(text, raw=raw)

    if interface == 'interfaces':
        text = check_output((_wg, 'show', 'interfaces'), text=True).strip()
        return text.split()

    text = check_output((_wg, 'show', interface), text=True).strip()
    return _parse_interface(text, raw=raw)


# pylint: disable=W0622
def set(interface: str, listen_port: int = None, fwmark: str = None,
        private_key: Path = None, peers: dict = None, *, _wg: str = WG):
    """Sets interface configuration."""

    args = ['set', interface]

    if listen_port is not None:
        args.append('listen-port')
        args.append(str(listen_port))

    if fwmark is not None:
        args.append('fwmark')
        args.append(fwmark)

    if private_key is not None:
        args.append('private-key')
        args.append(private_key)

    if peers:
        for peer, settings in peers.items():
            args.append('peer')
            args.append(peer)

            if settings.get('remove'):
                args.append('remove')

            if psk := settings.get('preshared-key'):
                args.append('preshared-key')
                args.append(psk)

            if endpoint := settings.get('endpoint'):
                args.append('endpoint')
                args.append(str(endpoint))

            if persistent_keepalive := settings.get('persistent-keepalive'):
                args.append('persistent-keepalive')
                args.append(str(persistent_keepalive))

            if allowed_ips := settings.get('allowed-ips'):
                args.append('allowed-ips')
                args.append(','.join(str(ip) for ip in allowed_ips))

    return check_call((_wg, *args))
