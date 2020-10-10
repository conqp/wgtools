# wgtools
Python bindings for WireGuard's `wg` utility.

## Installation

    python3 setup.py install

## Usage
In the following, the most common use cases are briefly explained.  
For a full documentation, please refer to `help(wgtools.<function>)`.

### Generating a private key

    private_key = wgtools.genkey()

### Generating a public key

    public_key = wgtools.pubkey(private_key)

### Generating a keypair

    keypair = wgtools.keypair()

or

    public_key, private_key = wgtools.keypair()

The `keypair` object is a named tuple an can be unpacked

    public_key, private_key = keypair
    
or accessed by atributes

    public_key = keypair.public
    private_key = keypair.private

### Generating a pre-shared key (PSK)

    psk = wgtools.genpsk()
