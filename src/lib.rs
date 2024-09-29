use std::{borrow::Cow, io};

use bytes::{Bytes, BytesMut};
use ethereum_types::{H128, H256};
use secp256k1::{PublicKey, SecretKey};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

mod ecies;
mod message;
pub mod parse;
mod secrets;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid tag {0}")]
    InvalidTag(H256),
    #[error("Invalid public key: {0}")]
    PublicKey(#[from] secp256k1::Error),
    #[error("Invalid derived key: {0}")]
    DerivedKey(concat_kdf::Error),
    #[error("Invalid tag: {0}")]
    Tag(H256),
    #[error("Invalid Mac {0}")]
    Mac(H128),
    #[error("Payload too big")]
    PayloadTooBig,
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("TCP connection closed")]
    TcpConnectionClosed,
    #[error("Invalid auth response")]
    InvalidAuthResponse,
    #[error("No Hello/Disconnect message")]
    NoHello,
    #[error("Invalid decoded value: {0}")]
    Rlp(#[from] rlp::DecoderError),
}

pub async fn handshake(
    socket: &mut TcpStream,
    remote_public_key: PublicKey,
    private_key: SecretKey,
    private_ephemeral_key: SecretKey,
    nonce: H256,
    random_secret_key: SecretKey,
    iv: H128,
) -> Result<(), Error> {
    let ecies = ecies::Ecies::new(remote_public_key, private_key, private_ephemeral_key, nonce);

    let auth = message::auth::Body::init(
        &ecies.public_key,
        &ecies.shared_key,
        &ecies.nonce,
        &ecies.private_ephemeral_key,
        &[],
    )?;
    let mut auth_encrypted = BytesMut::default();
    ecies.encrypt(&auth, &mut auth_encrypted, random_secret_key, iv)?;
    let auth = Bytes::copy_from_slice(&auth_encrypted[..]);

    if socket.write(&auth_encrypted).await? == 0 {
        return Err(Error::TcpConnectionClosed);
    }

    let mut buf = [0; 1024];
    let resp = socket.read(&mut buf).await?;

    if resp == 0 {
        return Err(Error::InvalidAuthResponse);
    }

    // here we received both ack and hello/disconnect, now we need only the ack, but we need to copy the buffer before it's decrypted
    let mut auth_response = Bytes::copy_from_slice(&buf[..resp]);
    let mut bytes_used = 0;
    let ack = ecies.decrypt::<message::ack::Body>(&mut buf, &mut bytes_used)?;
    if bytes_used as usize == resp {
        return Err(Error::NoHello);
    }
    // shrink the buffer only to ack
    auth_response.truncate(bytes_used as usize);

    let mut secrets = secrets::Secrets::new(auth, auth_response, &ack, &ecies);

    let hello = message::Body::Hello(message::hello::Body::new(ecies.public_key));
    let hello_frame = secrets.write_frame(&hello);
    if socket.write(&hello_frame).await? == 0 {
        return Err(Error::TcpConnectionClosed);
    }

    let msg = secrets.read_frame::<message::Body>(&mut buf[bytes_used as usize..resp])?;
    println!("received {msg:?}");

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn msg() {
        let msg = super::message::Body::Hello(super::message::hello::Body::new(crate::parse::public_key("00e6f58d28f907f0ffdce7666289107f7cdfacf55611feb8f208639e9deddee90408b5357d82fe3be328a323c4bd129b85b33cd7a494afbedd6a2e87ca8a56a1").unwrap()));

        let msg = super::message::Body::Disconnect(super::message::disconnect::Body::new(
            super::message::disconnect::Reason::TooManyPeers,
        ));

        let rlp = rlp::Rlp::new(&[1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let _: super::message::disconnect::Body = dbg!(rlp.as_val()).unwrap();
    }
}
