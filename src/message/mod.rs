use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

pub mod ack;
pub mod auth;
pub mod disconnect;
pub mod hello;

pub const PROTOCOL_VERSION: u64 = 5;

#[derive(Debug)]
pub enum Body<'a> {
    Disconnect(disconnect::Body),
    Hello(hello::Body<'a>),
}

impl Encodable for Body<'_> {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            Body::Disconnect(d) => {
                s.append(&1_u8);
                d.rlp_append(s)
            }
            Body::Hello(h) => {
                s.append(&0_u8);
                h.rlp_append(s)
            }
        }
    }
}

impl Decodable for Body<'_> {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let msg_id: u8 = rlp.as_val()?;
        let rlp = Rlp::new(&rlp.as_raw()[1..]);
        match msg_id {
            0 => Ok(Body::Hello(hello::Body::decode(&rlp)?)),
            1 => Ok(Body::Disconnect(disconnect::Body::decode(&rlp)?)),
            _ => Err(DecoderError::Custom("Unknown message id")),
        }
    }
}
