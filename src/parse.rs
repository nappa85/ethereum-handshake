use ethereum_types::{H128, H256};
use secp256k1::{PublicKey, SecretKey};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Invalid length")]
    InvalidLength,
    #[error("Invalid public key: {0}")]
    PublicKey(#[from] secp256k1::Error),
}

pub fn public_key(env: &str) -> Result<PublicKey, Error> {
    let data = hex::decode(env)?;
    if data.len() != 64 {
        return Err(Error::InvalidLength);
    }

    let mut buf = [4_u8; 65];
    buf[1..].copy_from_slice(&data);

    let public_key = PublicKey::from_slice(&buf)?;

    Ok(public_key)
}

pub fn secret_key(env: &str) -> Result<SecretKey, Error> {
    let data = hex::decode(env)?;
    if data.len() != 32 {
        return Err(Error::InvalidLength);
    }

    let public_key = SecretKey::from_slice(&data)?;

    Ok(public_key)
}

pub fn h256(env: &str) -> Result<H256, Error> {
    let data = hex::decode(env)?;
    if data.len() != 32 {
        return Err(Error::InvalidLength);
    }

    let mac = H256::from_slice(&data);

    Ok(mac)
}

pub fn h128(env: &str) -> Result<H128, Error> {
    let data = hex::decode(env)?;
    if data.len() != 16 {
        return Err(Error::InvalidLength);
    }

    let mac = H128::from_slice(&data);

    Ok(mac)
}
