use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher},
    Aes256,
};
use bytes::{Bytes, BytesMut};
use ethereum_types::{H128, H256};
use rlp::{Decodable, Encodable, Rlp};
use sha3::{Digest, Keccak256};

pub type Aes256Ctr64BE = ctr::Ctr64BE<Aes256>;

const ZERO_HEADER: &[u8; 3] = &[194, 128, 128];

/// Secrets generated following the exchange of handshake messages:
/// static-shared-secret = ecdh.agree(privkey, remote-pubk)
/// ephemeral-key = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
/// shared-secret = keccak256(ephemeral-key || keccak256(nonce || initiator-nonce))
/// aes-secret = keccak256(ephemeral-key || shared-secret)
/// mac-secret = keccak256(ephemeral-key || aes-secret)
pub struct Secrets {
    ephemeral_key: H256,
    shared_secret: H256,
    aes_secret: H256,
    mac_secret: H256,
    egress_mac: Keccak256,
    ingress_mac: Keccak256,
    ingress_aes: Aes256Ctr64BE,
    egress_aes: Aes256Ctr64BE,
}

impl Secrets {
    /// egress-mac = keccak256.init((mac-secret ^ recipient-nonce) || auth)
    /// ingress-mac = keccak256.init((mac-secret ^ initiator-nonce) || ack)
    ///
    /// egress-mac = keccak256.init((mac-secret ^ initiator-nonce) || ack)
    /// ingress-mac = keccak256.init((mac-secret ^ recipient-nonce) || auth)
    ///
    /// header-mac-seed = aes(mac-secret, keccak256.digest(egress-mac)[:16]) ^ header-ciphertext
    /// egress-mac = keccak256.update(egress-mac, header-mac-seed)
    /// header-mac = keccak256.digest(egress-mac)[:16]
    ///
    /// egress-mac = keccak256.update(egress-mac, frame-ciphertext)
    /// frame-mac-seed = aes(mac-secret, keccak256.digest(egress-mac)[:16]) ^ keccak256.digest(egress-mac)[:16]
    /// egress-mac = keccak256.update(egress-mac, frame-mac-seed)
    /// frame-mac = keccak256.digest(egress-mac)[:16]
    pub fn new(
        auth: Bytes,
        auth_response: Bytes,
        ack: &crate::message::ack::Body<'_>,
        ecies: &crate::ecies::Ecies,
    ) -> Self {
        // ephemeral-key
        let ephemeral_key = H256::from_slice(
            &secp256k1::ecdh::shared_secret_point(
                &ack.recipient_ephemeral_pubk,
                &ecies.private_ephemeral_key,
            )[..32],
        );

        // shared-secret
        let mut hasher = Keccak256::new();
        hasher.update(ack.recipient_nonce);
        hasher.update(ecies.nonce);
        let keccak_nonce = H256::from(hasher.finalize().as_ref());

        let mut hasher = Keccak256::new();
        hasher.update(ephemeral_key);
        hasher.update(keccak_nonce.as_ref());
        let shared_secret = H256::from(hasher.finalize().as_ref());

        // aes-secret
        let mut hasher = Keccak256::new();
        hasher.update(ephemeral_key.as_ref());
        hasher.update(shared_secret.as_ref());
        let aes_secret = H256::from(hasher.finalize().as_ref());

        // mac-secret
        let mut hasher = Keccak256::new();
        hasher.update(ephemeral_key.as_ref());
        hasher.update(aes_secret.as_ref());
        let mac_secret = H256::from(hasher.finalize().as_ref());

        // egress-mac
        let mut egress_mac = Keccak256::new();
        egress_mac.update((mac_secret ^ ack.recipient_nonce).as_bytes());
        egress_mac.update(auth);

        // ingress-mac
        let mut ingress_mac = Keccak256::new();
        ingress_mac.update((mac_secret ^ ecies.nonce).as_bytes());
        ingress_mac.update(auth_response);

        let iv = H128::default();
        let ingress_aes = Aes256Ctr64BE::new(aes_secret.as_ref().into(), iv.as_ref().into());
        let egress_aes = Aes256Ctr64BE::new(aes_secret.as_ref().into(), iv.as_ref().into());

        Self {
            ephemeral_key,
            shared_secret,
            aes_secret,
            mac_secret,
            egress_mac,
            ingress_mac,
            ingress_aes,
            egress_aes,
        }
    }

    /// frame = header-ciphertext || header-mac || frame-ciphertext || frame-mac
    /// header-ciphertext = aes(aes-secret, header)
    /// header = frame-size || header-data || header-padding
    /// header-data = [capability-id, context-id]
    /// capability-id = integer, always zero
    /// context-id = integer, always zero
    /// header-padding = zero-fill header to 16-byte boundary
    /// frame-ciphertext = aes(aes-secret, frame-data || frame-padding)
    /// frame-padding = zero-fill frame-data to 16-byte boundary
    pub fn write_frame<T>(&mut self, data: &T) -> BytesMut
    where
        T: Encodable,
    {
        let data = data.rlp_bytes();

        let mut header_buf = [0; 16];

        // copy last 3 bytes of data length big endian representation
        let bytes = data.len().to_be_bytes();
        header_buf[0..3].copy_from_slice(&bytes[(bytes.len() - 3)..]);

        header_buf[3..6].copy_from_slice(ZERO_HEADER);

        self.egress_aes.apply_keystream(&mut header_buf);
        update_header(&mut self.egress_mac, &self.mac_secret, &header_buf);

        let mac = digest(&self.egress_mac);

        let mut out = BytesMut::default();
        out.reserve(32);
        out.extend_from_slice(&header_buf);
        out.extend_from_slice(mac.as_bytes());

        let mut len = data.len();
        if len % 16 > 0 {
            len = (len / 16 + 1) * 16;
        }

        let old_len = out.len();
        out.resize(old_len + len, 0);

        let encrypted = &mut out[old_len..old_len + len];
        encrypted[..data.len()].copy_from_slice(&data);

        self.egress_aes.apply_keystream(encrypted);
        compute_frame(&mut self.egress_mac, &self.mac_secret, encrypted);
        let mac = digest(&self.egress_mac);

        out.extend_from_slice(mac.as_bytes());

        out
    }

    pub fn read_frame<T>(&mut self, buf: &mut [u8]) -> Result<T, crate::Error>
    where
        T: Decodable,
    {
        let (header_bytes, frame) = buf.split_at_mut(32);
        let (header, mac) = header_bytes.split_at_mut(16);
        let mac = H128::from_slice(mac);

        update_header(&mut self.ingress_mac, &self.mac_secret, header);
        if mac != digest(&self.ingress_mac) {
            return Err(crate::Error::Mac(mac));
        }

        self.ingress_aes.apply_keystream(header);

        let mut buf = [0; 8];
        buf[5..].copy_from_slice(&header[0..3]);
        let mut frame_size = u64::from_be_bytes(buf) + 16;
        let padding = frame_size % 16;
        if padding > 0 {
            frame_size += 16 - padding;
        }

        let (frame, _) = frame.split_at_mut(frame_size as usize);
        let (frame_data, frame_mac) = frame.split_at_mut(frame.len() - 16);
        let frame_mac = H128::from_slice(frame_mac);

        compute_frame(&mut self.ingress_mac, &self.mac_secret, frame_data);

        if frame_mac != digest(&self.ingress_mac) {
            return Err(crate::Error::Mac(frame_mac));
        }

        self.ingress_aes.apply_keystream(frame_data);

        let rlp = Rlp::new(frame_data);
        Ok(T::decode(&rlp)?)
    }
}

fn digest(hasher: &Keccak256) -> H128 {
    H128::from_slice(&hasher.clone().finalize()[..16])
}

fn update_header(hasher: &mut Keccak256, secret: &H256, header_cipher_text: &[u8]) {
    let mut header_mac_seed = digest(hasher).to_fixed_bytes();

    compute(hasher, secret, &mut header_mac_seed, header_cipher_text);
}

fn compute_frame(hasher: &mut Keccak256, secret: &H256, body_ciphertext: &[u8]) {
    hasher.update(body_ciphertext);

    let seed = digest(hasher);
    compute(hasher, secret, &mut seed.to_fixed_bytes(), seed.as_ref());
}

fn compute(hasher: &mut Keccak256, secret: &H256, seed: &mut [u8], cipher_text: &[u8]) {
    encrypt(secret, seed);

    for i in 0..cipher_text.len() {
        seed[i] ^= cipher_text[i];
    }

    hasher.update(seed);
}

fn encrypt(secret: &H256, data: &mut [u8]) {
    let cipher = aes::Aes256::new(secret.as_ref().into());
    cipher.encrypt_block(GenericArray::from_mut_slice(data));
}
