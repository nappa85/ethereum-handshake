use std::borrow::Cow;

use ethereum_types::H256;
use rlp::{Decodable, DecoderError, Rlp};
use secp256k1::PublicKey;

use crate::message::PROTOCOL_VERSION;

/// ack = ack-size || enc-ack-body
/// ack-size = size of enc-ack-body, encoded as a big-endian 16-bit integer
/// ack-vsn = 4
/// ack-body = [recipient-ephemeral-pubk, recipient-nonce, ack-vsn, ...]
/// enc-ack-body = ecies.encrypt(initiator-pubk, ack-body || ack-padding, ack-size)
/// ack-padding = arbitrary data
#[derive(Debug)]
pub struct Body<'a> {
    pub recipient_ephemeral_pubk: PublicKey,
    pub recipient_nonce: H256,
    ack_vsn: u64,
    arbitrary_data: Cow<'a, [u8]>,
}

impl<'a> Decodable for Body<'a> {
    fn decode(rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        let recipient_ephemeral_pubk_raw: Vec<_> = rlp.val_at(0)?;

        let mut buf = [4_u8; 65];
        buf[1..].copy_from_slice(&recipient_ephemeral_pubk_raw);
        let recipient_ephemeral_pubk =
            PublicKey::from_slice(&buf).map_err(|_| DecoderError::Custom("Invalid public key"))?;

        // recipient nonce
        let recipient_nonce_raw: Vec<_> = rlp.val_at(1)?;
        let recipient_nonce = H256::from_slice(&recipient_nonce_raw);

        // ack-vsn
        let ack_vsn: u64 = rlp.val_at(2)?;
        if ack_vsn != PROTOCOL_VERSION {
            // Ignoring any mismatches in auth-vsn and ack-vsn
        }

        let arbitrary_data: Vec<u8> = rlp.val_at(3)?;

        Ok(Self {
            recipient_ephemeral_pubk,
            recipient_nonce,
            ack_vsn,
            arbitrary_data: Cow::Owned(arbitrary_data),
        })
    }
}
