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
cargo run 65.21.224.171:30303 00e6f58d28f907f0ffdce7666289107f7cdfacf55611feb8f208639e9deddee90408b5357d82fe3be328a323c4bd129b85b33cd7a494afbedd6a2e87ca8a56a1
```

Any other parameter is optional and can be used to gain a good level of reproducibility when testing against a node you
can control too.

## Handshake conclusion

Citing documentation `cryptographic handshake is complete if MAC of first encrypted frame is valid on both sides`.

That means that handshake can be considered complete if the application doesn't return any error,
the error `Invalid Mac` followed by an hexadecimal value would precisely mean this check failed.

## Acknowledgments

The base code is loosely based on [this repo](https://github.com/aonescu/p2p-node-handshake/). 
