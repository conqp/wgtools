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
    'set',
    'clear_peers'
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


def _parse_value(key: str, value: str, *, json_compatible: bool = False):
    """Parses key / value pairs for wg show."""

    if key == 'allowed ips':
        if json_compatible:
            return [ip.strip() for ip in value.split(',')]

        return [ip_network(ip.strip()) for ip in value.split(',')]

    if key == 'listening port':
        return int(value)

    if key == 'transfer':
        received, sent = value.split(',')
        return {
            'received': received.replace('received', '').strip(),
            'sent': sent.replace('sent', '').strip()
        }

    if value == '(hidden)':
        return None

    return value


def _parse_interface(text: str, raw: bool = False,
                     json_compatible: bool = False) -> dict:
    """Parses interface information from the given text."""

    interface = {'peers': {}}
    peer = None

    for line in text.split(linesep):
        line = line.strip()

        if not line:
            continue

        key, value = line.split(': ')

        if not raw:
            value = _parse_value(key, value, json_compatible=json_compatible)

        if key == 'peer':
            interface['peers'][value] = peer = {}
            continue

        if peer is None:
            interface[key] = value
        else:
            peer[key] = value

    return interface


def _parse_interfaces(text: str, raw: bool = False,
                      json_compatible: bool = False) -> dict:
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
            value = _parse_value(key, value, json_compatible=json_compatible)

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


def show(interface: str = 'all', *, raw: bool = False,
         json_compatible: bool = False, _wg: str = WG):
    """Yields status information."""

    if interface == 'all':
        text = check_output((_wg, 'show', 'all'), text=True).strip()
        return _parse_interfaces(
            text, raw=raw, json_compatible=json_compatible)

    if interface == 'interfaces':
        text = check_output((_wg, 'show', 'interfaces'), text=True).strip()
        return text.split()

    text = check_output((_wg, 'show', interface), text=True).strip()
    return _parse_interface(text, raw=raw, json_compatible=json_compatible)


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

            psk = settings.get('preshared-key')

            if psk:
                args.append('preshared-key')
                args.append(psk)

            endpoint = settings.get('endpoint')

            if endpoint:
                args.append('endpoint')
                args.append(str(endpoint))

            persistent_keepalive = settings.get('persistent-keepalive')

            if persistent_keepalive:
                args.append('persistent-keepalive')
                args.append(str(persistent_keepalive))

            allowed_ips = settings.get('allowed-ips')

            if allowed_ips:
                args.append('allowed-ips')
                args.append(','.join(str(ip) for ip in allowed_ips))

    return check_call((_wg, *args))


def clear_peers(interface: str):
    """Removes all peers from the selected interface or all interfaces."""

    if interface == 'interfaces':
        raise ValueError('Invalid interface name:', interface)

    if interface == 'all':
        for interface in show('interfaces'):    # pylint: disable=R1704
            clear_peers(interface)
    else:
        peers = show(interface)['peers'].keys()
        peers = {key: {'remove': True} for key in peers}

        if peers:
            set(interface, peers=peers)
