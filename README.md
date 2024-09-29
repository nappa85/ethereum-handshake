# Ethereum P2P Handshake

Documentation about the RLP protocol can be found [here](https://github.com/ethereum/devp2p/blob/master/rlpx.md).

## Usage

```
Ethereum P2P Handshake

Usage: ethereum-handshake [OPTIONS] <ADDR> <REMOTE_PUBLIC_KEY>

Arguments:
  <ADDR>               Node address
  <REMOTE_PUBLIC_KEY>  Remote public Key

Options:
  -p, --private-key <PRIVATE_KEY>
          Optional private key for debugging purposes
  -e, --private-ephemeral-key <PRIVATE_EPHEMERAL_KEY>
          Optional private ephemeral key for debugging purposes
  -n, --nonce <NONCE>
          Optional nonce for debugging purposes
  -r, --random-secret-key <RANDOM_SECRET_KEY>
          Optional random secret key for debugging purposes
  -i, --iv <IV>
          Optional iv for debugging purposes
  -h, --help
          Print help
```

Mandatory parameters are remote addr and remote public key, e.g.

```bash
cargo run 52.59.248.41:30303 1cb2a31b7f39f069a29d719f01fd7fc711b85e07f416b64aa0e9e3ed55dc317d431c1361e76c33a2354ed11b183e9e4596443babf8f98fd80cc469c3b99a7264
```

Any other parameter is optional and can be used to gain a good level of reproducibility when testing against a node you
can control too.

## Bootnodes

Bootnodes list can be found [here](https://github.com/ethereum/go-ethereum/blob/master/params/bootnodes.go#L23),
an updated list of active servers can be found [here](https://ethernodes.org/nodes).

## Handshake conclusion

Citing documentation `cryptographic handshake is complete if MAC of first encrypted frame is valid on both sides`.

That means that handshake can be considered complete if the application doesn't return any error,
the error `Invalid Mac` followed by an hexadecimal value would precisely mean this check failed.

To see a successful handshake output, set the env var `RUST_LOG=info`, e.g.

```bash
RUST_LOG=info cargo run 52.59.248.41:30303 1cb2a31b7f39f069a29d719f01fd7fc711b85e07f416b64aa0e9e3ed55dc317d431c1361e76c33a2354ed11b183e9e4596443babf8f98fd80cc469c3b99a7264
```

## Acknowledgments

The base code is loosely based on [this repo](https://github.com/aonescu/p2p-node-handshake/). 
