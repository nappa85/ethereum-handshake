use std::borrow::Cow;

use rlp::{Decodable, DecoderError, Encodable};
use secp256k1::PublicKey;

/// Hello (0x00)
///
/// First packet sent over the connection, and sent once by both sides. No other messages may be sent until a Hello is received. Implementations must ignore any additional list elements in Hello because they may be used by a future version.
///
/// protocolVersion the version of the "p2p" capability, 5.
/// clientId Specifies the client software identity, as a human-readable string (e.g. "Ethereum(++)/1.0.0").
/// capabilities is the list of supported capabilities and their versions: [[cap1, capVersion1], [cap2, capVersion2], ...].
/// listenPort (legacy) specifies the port that the client is listening on (on the interface that the present connection traverses). If 0 it indicates the client is not listening. This field should be ignored.
/// nodeId is the secp256k1 public key corresponding to the node's private key.
#[derive(Debug)]
pub struct Body<'a> {
    protocol_version: u64,
    client_id: Cow<'a, str>,
    capabilities: Vec<Capability<'a>>,
    port: u16,
    node_id: PublicKey,
}

impl<'a> Body<'a> {
    pub fn new(node_id: PublicKey) -> Self {
        Self {
            protocol_version: super::PROTOCOL_VERSION,
            client_id: Cow::Borrowed("hello"),
            capabilities: vec![],
            port: 0,
            node_id,
        }
    }
}

impl<'a> Encodable for Body<'a> {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        let stream = s.begin_list(5);
        stream.append(&self.protocol_version);
        stream.append(&self.client_id.as_ref());
        stream.append_list(&self.capabilities);
        stream.append(&self.port);

        let node_id = &self.node_id.serialize_uncompressed()[1..65];
        stream.append(&node_id);
    }
}

impl<'a> Decodable for Body<'a> {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, DecoderError> {
        let protocol_version: u64 = dbg!(rlp.val_at(1))?;
        let client_id: String = dbg!(rlp.val_at(2))?;
        let capabilities: Vec<Capability> = dbg!(rlp.list_at(3))?;
        let port: u16 = dbg!(rlp.val_at(4))?;
        let node_id: Vec<u8> = dbg!(rlp.val_at(5))?;

        let mut s = [0_u8; 65];
        s[0] = 4;
        s[1..].copy_from_slice(&node_id);
        let node_id =
            PublicKey::from_slice(&s).map_err(|_| DecoderError::Custom("Invalid public key"))?;

        Ok(Self {
            protocol_version,
            client_id: Cow::Owned(client_id),
            capabilities,
            port,
            node_id,
        })
    }
}

#[derive(Debug)]
pub struct Capability<'a> {
    pub name: Cow<'a, str>,
    pub version: u64,
}

impl<'a> Encodable for Capability<'a> {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(2);
        s.append(&self.name.as_ref());
        s.append(&self.version);
    }
}

impl<'a> Decodable for Capability<'a> {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, DecoderError> {
        let name: String = rlp.val_at(0)?;
        let ver: u64 = rlp.val_at(1)?;

        Ok(Self {
            name: Cow::Owned(name),
            version: ver,
        })
    }
}
