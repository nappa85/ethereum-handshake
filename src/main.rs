use std::net::SocketAddr;

use clap::Parser;
use ethereum_handshake::{Error, TIMEOUT};
use ethereum_types::{H128, H256};
use secp256k1::{PublicKey, SecretKey};
use tokio::{net::TcpStream, time::timeout};

/// Ethereum P2P Handshake
#[derive(Parser, Debug)]
struct Args {
    /// Node address
    #[arg(required = true)]
    addr: SocketAddr,

    /// Remote public Key
    #[arg(required = true, value_parser = ethereum_handshake::parse::public_key)]
    remote_public_key: PublicKey,

    /// Optional private key for debugging purposes
    #[arg(short = 'p', long, value_parser = ethereum_handshake::parse::secret_key)]
    private_key: Option<SecretKey>,

    /// Optional private ephemeral key for debugging purposes
    #[arg(short = 'e', long, value_parser = ethereum_handshake::parse::secret_key)]
    private_ephemeral_key: Option<SecretKey>,

    /// Optional nonce for debugging purposes
    #[arg(short = 'n', long, value_parser = ethereum_handshake::parse::h256)]
    nonce: Option<H256>,

    /// Optional random secret key for debugging purposes
    #[arg(short = 'r', long, value_parser = ethereum_handshake::parse::secret_key)]
    random_secret_key: Option<SecretKey>,

    /// Optional iv for debugging purposes
    #[arg(short = 'i', long, value_parser = ethereum_handshake::parse::h128)]
    iv: Option<H128>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let mut socket = timeout(TIMEOUT, TcpStream::connect(args.addr))
        .await
        .map_err(|_| Error::ConnectionTimeout)??;
    let _secrets = ethereum_handshake::handshake(
        &mut socket,
        args.remote_public_key,
        args.private_key
            .unwrap_or_else(|| SecretKey::new(&mut secp256k1::rand::thread_rng())),
        args.private_ephemeral_key
            .unwrap_or_else(|| SecretKey::new(&mut secp256k1::rand::thread_rng())),
        args.nonce.unwrap_or_else(H256::random),
        args.random_secret_key
            .unwrap_or_else(|| SecretKey::new(&mut secp256k1::rand::thread_rng())),
        args.iv.unwrap_or_else(H128::random),
    )
    .await?;

    Ok(())
}
