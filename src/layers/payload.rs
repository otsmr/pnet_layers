#![allow(unexpected_cfgs)]

use crate::{
    Layer, LayerImmutable, LayerMutable, Layers, create_default_immutable, create_modify,
    create_set_payload,
};
use pnet::packet::arp::MutableArpPacket;
use pnet_macros::packet;
use std::fmt::Display;

#[packet]
pub struct PayloadDummy {
    #[payload]
    pub payload: Vec<u8>,
}

/// Immutable representation of an arp packet
#[derive(Debug)]
pub struct Payload<'a> {
    /// buf
    pub buf: &'a [u8],
}

#[derive(Debug, Clone)]
/// Mutable representation of an arp packet
pub struct PayloadMut {
    /// buf
    pub buf: Vec<u8>,
}

impl<'a> LayerMutable<'a> for PayloadMut {
    type PacketMut = MutableArpPacket<'a>;
    fn new() -> Self {
        Self { buf: vec![0; 0] }
    }

    create_modify!();
    create_set_payload!();

    fn from_buf(buf: Vec<u8>) -> Option<Self> {
        Some(Self { buf })
    }

    fn build(self) -> Option<Vec<u8>> {
        Some(self.buf)
    }
}

impl<'a> LayerImmutable<'a> for Payload<'a> {
    type Packet = PayloadDummyPacket<'a>;
    type PacketMut = MutablePayloadDummyPacket<'a>;
    type LayerMutType = PayloadMut;

    create_default_immutable!();
    fn get_layer_from_buf(_buf: &'_ [u8], _layer: Layers) -> Option<Layer<'_>> {
        None
    }
}

impl Display for PayloadMut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Payload")?;
        Ok(())
    }
}
