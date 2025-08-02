use crate::{
    Layer, LayerImmutable, LayerMut, LayerMutable, Layers, Payload, PayloadMut, create_add_layer,
    create_default_immutable, create_get_layer, create_modify, create_set_payload,
    create_switch_layer,
};
use pnet::packet::Packet;
use pnet::packet::udp::{MutableUdpPacket, UdpPacket, ipv4_checksum, ipv6_checksum};
use std::fmt::{Debug, Display};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Immutable representation of an UPD packet
#[derive(Debug)]
pub struct Udp<'a> {
    buf: &'a [u8],
}

#[derive(Clone)]
/// Mutable representation of an UPD packet
pub struct UdpMut {
    buf: Vec<u8>,
    /// the upper layer
    pub upper_layer: Option<Box<LayerMut>>,
}

impl UdpMut {
    pub(super) fn build_from_ipv4(self, saddr: Ipv4Addr, daddr: Ipv4Addr) -> Option<Vec<u8>> {
        let mut udp_build = self.build()?;
        {
            let mut udp = MutableUdpPacket::new(&mut udp_build)?;
            udp.set_checksum(ipv4_checksum(&udp.to_immutable(), &saddr, &daddr));
        }

        Some(udp_build)
    }
    pub(super) fn build_from_ipv6(self, saddr: Ipv6Addr, daddr: Ipv6Addr) -> Option<Vec<u8>> {
        let mut udp_build = self.build()?;
        {
            let mut udp = MutableUdpPacket::new(&mut udp_build)?;
            udp.set_checksum(ipv6_checksum(&udp.to_immutable(), &saddr, &daddr));
        }
        Some(udp_build)
    }
}

impl<'a> LayerMutable<'a> for UdpMut {
    type PacketMut = MutableUdpPacket<'a>;
    fn new() -> Self {
        Self {
            buf: vec![0; UdpPacket::minimum_packet_size()],
            upper_layer: None,
        }
    }

    create_modify!();
    create_set_payload!();
    create_switch_layer!();
    create_add_layer!(Payload; { });
    create_get_layer!(Payload);

    fn from_buf(mut buf: Vec<u8>) -> Option<Self> {
        let udp = UdpPacket::new(&buf)?;

        let payload = udp.payload();
        let mut upper_layer = None;

        if !payload.is_empty() {
            upper_layer = Some(Box::new(LayerMut::Payload(PayloadMut::from_buf(
                payload.to_vec(),
            )?)));
        }

        buf.resize(buf.len() - payload.len(), 0);

        Some(Self { buf, upper_layer })
    }

    fn build(mut self) -> Option<Vec<u8>> {
        let payload = match self.upper_layer {
            Some(child) => match *child {
                LayerMut::Payload(a) => a.build()?,
                _ => return None,
            },
            None => vec![],
        };
        self.buf.extend_from_slice(&payload);

        if self.buf.len() > u16::MAX as usize {
            return None;
        }

        #[allow(clippy::cast_possible_truncation)]
        let len = self.buf.iter().len() as u16;
        {
            let mut udp = Self::PacketMut::new(self.buf.as_mut())?;
            udp.set_length(len);
        }
        Some(self.buf)
    }
}

impl<'a> LayerImmutable<'a> for Udp<'a> {
    type Packet = UdpPacket<'a>;
    type PacketMut = MutableUdpPacket<'a>;
    type LayerMutType = UdpMut;

    create_default_immutable!();

    fn get_layer_from_buf(buf: &'_ [u8], layer: Layers) -> Option<Layer<'_>> {
        let size = UdpPacket::minimum_packet_size();
        let buf = &buf[size..buf.len()];
        if matches!(layer, Layers::Payload) {
            Some(Layer::Payload(Payload::new(buf)))
        } else {
            Payload::get_layer_from_buf(buf, layer)
        }
    }
}

impl Display for UdpMut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(eth) = UdpPacket::new(&self.buf) {
            write!(
                f,
                "Udp (s: {}, d: {})",
                eth.get_source(),
                eth.get_destination()
            )?;
            if let Some(upper) = &self.upper_layer {
                write!(f, " > {upper}")?;
            }
        }
        Ok(())
    }
}

impl Debug for UdpMut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(eth) = UdpPacket::new(&self.buf) {
            write!(
                f,
                "Udp (s: {}, d: {})",
                eth.get_source(),
                eth.get_destination()
            )?;
            if let Some(upper) = &self.upper_layer {
                write!(f, " > {upper}")?;
            }
        }
        Ok(())
    }
}
