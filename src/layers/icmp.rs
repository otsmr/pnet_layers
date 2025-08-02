use crate::{
    Layer, LayerImmutable, LayerMutable, Layers, create_default_immutable, create_modify,
    create_set_payload,
};
use pnet::packet::icmp::{IcmpPacket, MutableIcmpPacket, checksum};
use std::fmt::Display;

/// Immutable representation of an icmp packet
#[derive(Debug)]
pub struct Icmp<'a> {
    buf: &'a [u8],
}

#[derive(Debug, Clone)]
/// Mutable representation of an icmp packet
pub struct IcmpMut {
    buf: Vec<u8>,
}

impl<'a> LayerMutable<'a> for IcmpMut {
    type PacketMut = MutableIcmpPacket<'a>;
    fn new() -> Self {
        Self {
            buf: vec![0; IcmpPacket::minimum_packet_size()],
        }
    }
    create_modify!();
    create_set_payload!();

    fn from_buf(buf: Vec<u8>) -> Option<Self> {
        Some(Self { buf })
    }

    fn build(mut self) -> Option<Vec<u8>> {
        let mut chksum = None;
        if let Some(packet) = IcmpPacket::new(&self.buf) {
            chksum = Some(checksum(&packet));
        }
        if let Some(checksum) = chksum
            && let Some(mut pkt) = self.modify()
        {
            pkt.set_checksum(checksum);
            return Some(self.buf);
        }
        None
        // Some(self.buf)
    }
}

impl<'a> LayerImmutable<'a> for Icmp<'a> {
    type Packet = IcmpPacket<'a>;
    type PacketMut = MutableIcmpPacket<'a>;
    type LayerMutType = IcmpMut;

    create_default_immutable!();
    fn get_layer_from_buf(_buf: &'_ [u8], _layer: Layers) -> Option<Layer<'_>> {
        None
    }
}

impl Display for IcmpMut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(eth) = IcmpPacket::new(&self.buf) {
            write!(f, "Icmp (type: {:?})", eth.get_icmp_type())?;
        }
        Ok(())
    }
}
