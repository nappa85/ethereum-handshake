use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

pub mod ack;
pub mod auth;
pub mod disconnect;
pub mod hello;

pub const PROTOCOL_VERSION: u64 = 5;

#[derive(Debug, PartialEq)]
pub enum Body<'a> {
    Disconnect(disconnect::Body),
    Hello(hello::Body<'a>),
    Ping,
    Pong,
}

impl Encodable for Body<'_> {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            Body::Hello(h) => {
                s.append(&0_u8);
                h.rlp_append(s);
            }
            Body::Disconnect(d) => {
                s.append(&1_u8);
                d.rlp_append(s);
            }
            Body::Ping => {
                s.append(&2_u8);
            }
            Body::Pong => {
                s.append(&3_u8);
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
            2 => Ok(Body::Ping),
            3 => Ok(Body::Pong),
            _ => Err(DecoderError::Custom("Unknown message id")),
        }
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::PublicKey;

    use super::*;

    const HELLO: &[u8] = &[
        128, 248, 75, 5, 133, 104, 101, 108, 108, 111, 192, 128, 184, 64, 0, 230, 245, 141, 40,
        249, 7, 240, 255, 220, 231, 102, 98, 137, 16, 127, 124, 223, 172, 245, 86, 17, 254, 184,
        242, 8, 99, 158, 157, 237, 222, 233, 4, 8, 181, 53, 125, 130, 254, 59, 227, 40, 163, 35,
        196, 189, 18, 155, 133, 179, 60, 215, 164, 148, 175, 190, 221, 106, 46, 135, 202, 138, 86,
        161,
    ];

    #[test]
    fn msg() {
        let msg = Body::Hello(hello::Body::new(crate::parse::public_key("00e6f58d28f907f0ffdce7666289107f7cdfacf55611feb8f208639e9deddee90408b5357d82fe3be328a323c4bd129b85b33cd7a494afbedd6a2e87ca8a56a1").unwrap()));
        assert_eq!(rlp::encode(&msg).as_ref(), HELLO);
        let recv = rlp::decode::<Body>(HELLO).unwrap();
        assert_eq!(msg, recv);

        let msg = Body::Disconnect(disconnect::Body::new(disconnect::Reason::TooManyPeers));
        assert_eq!(rlp::encode(&msg).as_ref(), &[1, 4]);

        // test ignore padding
        let rlp = rlp::Rlp::new(&[1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let body: Body = rlp.as_val().unwrap();
        assert_eq!(body, msg);
    }
}
