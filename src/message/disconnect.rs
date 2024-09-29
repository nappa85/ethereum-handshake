use rlp::{Decodable, DecoderError, Encodable};

#[derive(Debug)]
pub struct Body {
    reason: Reason,
}

impl Body {
    pub fn new(reason: Reason) -> Self {
        Self { reason }
    }
}

impl Encodable for Body {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        //s.begin_list(1);
        s.append(&self.reason);
    }
}

impl Decodable for Body {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            reason: rlp.as_val()?,
        })
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(u64)]
pub enum Reason {
    DisconnectRequested = 0,
    TcpSubSystemError = 1,
    BreachOfProtocol = 2,
    UselessPeer = 3,
    TooManyPeers = 4,
    AlreadyConnected = 5,
    IncompatibleP2pProtocolVersion = 6,
    NullNodeIdentityReceived = 7,
    ClientQuitting = 8,
    UnexpectedIdentityInHandshake = 9,
    IdentityIsTheSameAsThisNode = 10,
    PingTimeout = 11,
    SomeOtherReasonSpecificToASubprotocol = 12,
}

impl Encodable for Reason {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.append(&(*self as u64));
    }
}

impl Decodable for Reason {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, DecoderError> {
        let temp = u64::decode(rlp)?;
        match temp {
            0 => Ok(Reason::DisconnectRequested),
            1 => Ok(Reason::TcpSubSystemError),
            2 => Ok(Reason::BreachOfProtocol),
            3 => Ok(Reason::UselessPeer),
            4 => Ok(Reason::TooManyPeers),
            5 => Ok(Reason::AlreadyConnected),
            6 => Ok(Reason::IncompatibleP2pProtocolVersion),
            7 => Ok(Reason::NullNodeIdentityReceived),
            8 => Ok(Reason::ClientQuitting),
            9 => Ok(Reason::UnexpectedIdentityInHandshake),
            10 => Ok(Reason::IdentityIsTheSameAsThisNode),
            11 => Ok(Reason::PingTimeout),
            12 => Ok(Reason::SomeOtherReasonSpecificToASubprotocol),
            _ => Err(DecoderError::Custom("invalid disconnect reason")),
        }
    }
}
