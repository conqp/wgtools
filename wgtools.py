"""Python bindings for WireGuard."""

from __future__ import annotations
from ipaddress import IPv4Network, IPv6Network, ip_network
from os import linesep
from pathlib import Path
from shutil import which
from subprocess import check_call, check_output
from typing import Iterable, Iterator, NamedTuple


__all__ = [
    "WG",
    "Keypair",
    "genkey",
    "pubkey",
    "keypair",
    "genpsk",
    "show",
    "set",
    "clear_peers",
]


WG = (which("wg"),)

IPNetworks = Iterator[str | IPv4Network | IPv6Network]
ParsedValue = list | int | dict | None | str


class Keypair(NamedTuple):
    """A public / private key pair."""

    public: str
    private: str

    @classmethod
    def from_private_key(cls, private: str, *, _wg: Iterable[str] = WG) -> Keypair:
        """Creates a keypair from a private key."""
        return cls(pubkey(private, _wg=_wg), private)

    @classmethod
    def generate(cls, *, _wg: Iterable[str] = WG) -> Keypair:
        """Generates a public / private key pair."""
        return cls.from_private_key(genkey(_wg=_wg), _wg=_wg)


def genkey(*, _wg: Iterable[str] = WG) -> str:
    """Generates a new private key."""

    return check_output([*_wg, "genkey"], text=True).strip()


def pubkey(key: str, *, _wg: Iterable[str] = WG) -> str:
    """Generates a public key for the given private key."""

    return check_output([*_wg, "pubkey"], input=key, text=True).strip()


def keypair(*, _wg: Iterable[str] = WG) -> Keypair:
    """Generates a public-private key pair."""

    return Keypair.generate(_wg=_wg)


def genpsk(*, _wg: Iterable[str] = WG) -> str:
    """Generates a pre-shared key."""

    return check_output([*_wg, "genpsk"], text=True).strip()


def _parse_ip_networks(value: str, *, json: bool = False) -> IPNetworks:
    """Returns a parsed IP networks from a string."""

    for network in map(str.strip, value.split(",")):
        if network == "(none)":
            continue

        if not json:
            network = ip_network(network)

        yield network


def parse_value(key: str, value: str, *, json: bool = False) -> ParsedValue:
    """Parses key / value pairs for wg show."""

    if key == "allowed ips":
        return list(_parse_ip_networks(value, json=json))

    if key == "listening port":
        return int(value)

    if key == "transfer":
        received, sent = value.split(",")
        return {
            "received": received.replace("received", "").strip(),
            "sent": sent.replace("sent", "").strip(),
        }

    if value == "(hidden)":
        return None

    return value


def parse_interface(text: str, *, raw: bool = False, json: bool = False) -> dict:
    """Parses interface information from the given text."""

    interface = {"peers": (peers := {})}
    peer = None

    for line in text.split(linesep):
        if not (line := line.strip()):
            continue

        key, value = line.split(": ")

        if not raw:
            value = parse_value(key, value, json=json)

        if key == "peer":
            peers[value] = peer = {}
            continue

        if peer is None:
            interface[key] = value
        else:
            peer[key] = value

    return interface


def parse_interfaces(text: str, *, raw: bool = False, json: bool = False) -> dict:
    """Parses interface information from
    the given text for multiple interfaces.
    """

    interfaces = {}
    interface = {}
    peer = None

    for line in text.split(linesep):
        if not (line := line.strip()):
            continue

        key, value = line.split(": ")

        if not raw:
            value = parse_value(key, value, json=json)

        if key == "interface":
            interfaces[value] = interface = {"peers": {}}
            peer = None
            continue

        if key == "peer":
            interface["peers"][value] = peer = {}
            continue

        if peer is None:
            interface[key] = value
        else:
            peer[key] = value

    return interfaces


def show(
    interface: str = "all",
    *,
    raw: bool = False,
    json: bool = False,
    _wg: Iterable[str] = WG,
) -> dict | list:
    """Returns status information of a WireGuard interface."""

    if interface == "all":
        text = check_output([*_wg, "show", "all"], text=True).strip()
        return parse_interfaces(text, raw=raw, json=json)

    if interface == "interfaces":
        text = check_output([*_wg, "show", "interfaces"], text=True).strip()
        return text.split()

    text = check_output([*_wg, "show", interface], text=True).strip()
    return parse_interface(text, raw=raw, json=json)


def peers_args(peers: dict[str, dict]) -> Iterator[str]:
    """Yields additional args for the peers."""

    for peer, settings in peers.items():
        yield "peer"
        yield peer

        if settings.get("remove"):
            yield "remove"

        if psk := settings.get("preshared-key"):
            yield "preshared-key"
            yield psk

        if endpoint := settings.get("endpoint"):
            yield "endpoint"
            yield str(endpoint)

        if persistent_keepalive := settings.get("persistent-keepalive"):
            yield "persistent-keepalive"
            yield str(persistent_keepalive)

        if allowed_ips := settings.get("allowed-ips"):
            yield "allowed-ips"
            yield ",".join(str(ip) for ip in allowed_ips)


def set(
    interface: str,
    *,
    listen_port: int | None = None,
    fwmark: str | None = None,
    private_key: Path | None = None,
    peers: dict[str, dict] | None = None,
    _wg: Iterable[str] = WG,
) -> int:
    """Sets interface configuration."""

    args = [*_wg, "set", interface]

    if listen_port is not None:
        args.append("listen-port")
        args.append(str(listen_port))

    if fwmark is not None:
        args.append("fwmark")
        args.append(fwmark)

    if private_key is not None:
        args.append("private-key")
        args.append(private_key)

    if peers:
        args.extend(peers_args(peers))

    return check_call(args)


def clear_all_peers(*, _wg: Iterable[str] = WG) -> None:
    """Clear all peers on all interfaces."""

    for interface in show("interfaces", _wg=_wg):
        clear_peers(interface, _wg=_wg)


def clear_peers(interface: str, *, _wg: Iterable[str] = WG) -> None:
    """Removes all peers from the selected interface or all interfaces."""

    if interface == "interfaces":
        raise ValueError("Invalid interface name:", interface)

    if interface == "all":
        return clear_all_peers(_wg=_wg)

    peers = {key: {"remove": True} for key in show(interface, _wg=_wg)["peers"].keys()}

    if peers:
        set(interface, peers=peers, _wg=_wg)
