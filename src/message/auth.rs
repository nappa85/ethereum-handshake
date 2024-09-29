use ethereum_types::H256;
use rlp::{Encodable, RlpStream};
use secp256k1::{Message, PublicKey, SecretKey, SECP256K1};

use crate::{message::PROTOCOL_VERSION, Error};

/// auth = auth-size || enc-auth-body
/// auth-size = size of enc-auth-body, encoded as a big-endian 16-bit integer
/// auth-vsn = 4
/// auth-body = [sig, initiator-pubk, initiator-nonce, auth-vsn, ...]
/// enc-auth-body = ecies.encrypt(recipient-pubk, auth-body || auth-padding, auth-size)
/// auth-padding = arbitrary data
pub struct Body<'a> {
    signature: [u8; 65],
    initiator_pubk: &'a PublicKey,
    initiator_nonce: &'a H256,
    auth_vsn: u64,
    arbitrary_data: &'a [u8],
}

impl<'a> Body<'a> {
    pub fn init(
        initiator_pubk: &'a PublicKey,
        shared_key: &H256,
        initiator_nonce: &'a H256,
        private_ephemeral_key: &SecretKey,
        arbitrary_data: &'a [u8],
    ) -> Result<Self, Error> {
        Ok(Self {
            signature: Self::signature(shared_key, initiator_nonce, private_ephemeral_key)?,
            initiator_pubk,
            initiator_nonce,
            auth_vsn: PROTOCOL_VERSION,
            arbitrary_data,
        })
    }

    fn signature(
        shared_key: &H256,
        nonce: &H256,
        private_ephemeral_key: &SecretKey,
    ) -> Result<[u8; 65], Error> {
        let msg = shared_key ^ nonce;
        let msg = Message::from_digest_slice(msg.as_bytes())?;

        let (rec_id, sig) = SECP256K1
            .sign_ecdsa_recoverable(&msg, private_ephemeral_key)
            .serialize_compact();

        let mut signature = [0; 65];
        signature[..64].copy_from_slice(&sig);
        signature[64] = rec_id.to_i32().to_le_bytes()[0];

        Ok(signature)
    }
}

impl<'a> Encodable for Body<'a> {
    fn rlp_append(&self, s: &mut RlpStream) {
        let full_pub_key = self.initiator_pubk.serialize_uncompressed();
        let public_key = &full_pub_key[1..];

        let stream = s.begin_list(4);
        stream.append(&&self.signature[..]);
        stream.append(&public_key);
        stream.append(&self.initiator_nonce.as_bytes());
        stream.append(&PROTOCOL_VERSION);
        stream.append(&self.arbitrary_data);
    }
}
