use aes::cipher::{KeyIvInit, StreamCipher};
use bytes::BytesMut;
use ethereum_types::{H128, H256};
use hmac::{Hmac, Mac};
use rlp::{Decodable, Encodable, Rlp};
use secp256k1::{ecdh, PublicKey, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};

use crate::Error;

pub type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;

pub struct Ecies {
    pub remote_public_key: PublicKey,
    pub private_key: SecretKey,
    pub private_ephemeral_key: SecretKey,
    pub public_key: PublicKey,
    pub shared_key: H256,
    pub nonce: H256,
}

impl Ecies {
    pub fn new(
        remote_public_key: PublicKey,
        private_key: SecretKey,
        private_ephemeral_key: SecretKey,
        nonce: H256,
    ) -> Self {
        let public_key = PublicKey::from_secret_key(SECP256K1, &private_key);

        let shared_key =
            H256::from_slice(&ecdh::shared_secret_point(&remote_public_key, &private_key)[..32]);

        Self {
            remote_public_key,
            private_key,
            private_ephemeral_key,
            public_key,
            shared_key,
            nonce,
        }
    }

    pub fn encrypt<T>(
        &self,
        data_in: &T,
        data_out: &mut BytesMut,
        random_secret_key: SecretKey,
        iv: H128,
    ) -> Result<usize, Error>
    where
        T: Encodable,
    {
        let shared_key = H256::from_slice(
            &ecdh::shared_secret_point(&self.remote_public_key, &random_secret_key)[..32],
        );

        let mut key = [0u8; 32];
        concat_kdf::derive_key_into::<Sha256>(shared_key.as_bytes(), &[], &mut key)
            .map_err(Error::DerivedKey)?;

        let encrypted_key = H128::from_slice(&key[..16]);
        let mac_key = H256::from(Sha256::digest(&key[16..]).as_ref());

        let mut encryptor = Aes128Ctr64BE::new(encrypted_key.as_ref().into(), iv.as_ref().into());

        let mut encrypted = data_in.rlp_bytes();
        let total_size: u16 =
            u16::try_from(65 + 16 + encrypted.len() + 32).map_err(|_| Error::PayloadTooBig)?;

        encryptor.apply_keystream(&mut encrypted);

        let tag = {
            let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key.as_ref())
                .map_err(|_| Error::Tag(mac_key))?;
            hmac.update(iv.as_bytes());
            hmac.update(&encrypted);
            hmac.update(&total_size.to_be_bytes());

            H256::from_slice(&hmac.finalize().into_bytes())
        };

        data_out.extend_from_slice(&total_size.to_be_bytes());
        data_out.extend_from_slice(
            &PublicKey::from_secret_key(SECP256K1, &random_secret_key).serialize_uncompressed(),
        );
        data_out.extend_from_slice(iv.as_bytes());
        data_out.extend_from_slice(&encrypted);
        data_out.extend_from_slice(tag.as_bytes());

        Ok(data_out.len())
    }

    pub fn decrypt<T>(&self, data_in: &mut [u8], read_bytes: &mut u16) -> Result<T, Error>
    where
        T: Decodable,
    {
        let (size, rest) = data_in.split_at_mut(2);
        let payload_size = u16::from_be_bytes([size[0], size[1]]);
        *read_bytes = payload_size + 2;

        let (pub_data, rest) = rest.split_at_mut(65);
        let remote_ephemeral_pub_key = PublicKey::from_slice(pub_data)?;

        let (iv, rest) = rest.split_at_mut(16); //
        let (encrypted_data, tag) = rest.split_at_mut(payload_size as usize - (65 + 16 + 32));

        let tag = H256::from_slice(&tag[..32]);
        let shared_key = H256::from_slice(
            &ecdh::shared_secret_point(&remote_ephemeral_pub_key, &self.private_key)[..32],
        );

        let mut key = [0_u8; 32];
        concat_kdf::derive_key_into::<Sha256>(shared_key.as_bytes(), &[], &mut key)
            .map_err(Error::DerivedKey)?;

        let encrypted_key = H128::from_slice(&key[..16]);
        let mac_key = H256::from(Sha256::digest(&key[16..32]).as_ref());

        let iv = H128::from_slice(iv);

        let remote_tag = {
            let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key.as_ref())
                .map_err(|_| Error::Tag(mac_key))?;
            hmac.update(iv.as_bytes());
            hmac.update(encrypted_data);
            hmac.update(&payload_size.to_be_bytes());

            H256::from_slice(&hmac.finalize().into_bytes())
        };

        if tag != remote_tag {
            return Err(Error::InvalidTag(remote_tag));
        }

        let mut decryptor = Aes128Ctr64BE::new(encrypted_key.as_ref().into(), iv.as_ref().into());
        decryptor.apply_keystream(encrypted_data);

        let rlp = Rlp::new(&encrypted_data);
        Ok(T::decode(&rlp)?)
    }
}
