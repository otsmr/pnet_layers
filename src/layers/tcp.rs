use crate::{
    Layer, LayerImmutable, LayerMut, LayerMutable, Layers, Payload, PayloadMut, create_add_layer,
    create_default_immutable, create_get_layer, create_modify, create_set_payload,
    create_switch_layer,
};
use pnet::packet::Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket, ipv4_checksum, ipv6_checksum};
use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Immutable representation of an UPD packet
#[derive(Debug)]
pub struct Tcp<'a> {
    buf: &'a [u8],
}

#[derive(Debug, Clone)]
/// Mutable representation of an UPD packet
pub struct TcpMut {
    buf: Vec<u8>,
    upper_layer: Option<Box<LayerMut>>,
}

impl TcpMut {
    pub(super) fn build_from_ipv4(self, saddr: Ipv4Addr, daddr: Ipv4Addr) -> Option<Vec<u8>> {
        let mut tcp_build = self.build()?;
        {
            let mut tcp = MutableTcpPacket::new(&mut tcp_build)?;
            tcp.set_checksum(ipv4_checksum(&tcp.to_immutable(), &saddr, &daddr));
        }

        Some(tcp_build)
    }
    pub(super) fn build_from_ipv6(self, saddr: Ipv6Addr, daddr: Ipv6Addr) -> Option<Vec<u8>> {
        let mut udp_build = self.build()?;
        {
            let mut udp = MutableTcpPacket::new(&mut udp_build)?;
            udp.set_checksum(ipv6_checksum(&udp.to_immutable(), &saddr, &daddr));
        }
        Some(udp_build)
    }
}

impl<'a> LayerMutable<'a> for TcpMut {
    type PacketMut = MutableTcpPacket<'a>;
    fn new() -> Self {
        Self {
            buf: vec![0; 20],
            upper_layer: None,
        }
    }

    create_modify!();
    create_set_payload!();
    create_switch_layer!();
    create_add_layer!(Payload; {});
    create_get_layer!(Payload);

    fn from_buf(mut buf: Vec<u8>) -> Option<Self> {
        let tcp = TcpPacket::new(&buf)?;

        let payload = tcp.payload();
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
                LayerMut::Payload(arp) => arp.build()?,
                _ => return None,
            },
            None => vec![],
        };
        self.buf.extend_from_slice(&payload);

        let data_offset = 20 / 4;
        if data_offset > u8::MAX as usize {
            return None;
        }

        #[allow(clippy::cast_possible_truncation)]
        let data_offset = data_offset as u8;
        {
            let mut tcp = Self::PacketMut::new(self.buf.as_mut())?;
            tcp.set_data_offset(data_offset);
        }
        Some(self.buf)
    }
}

impl<'a> LayerImmutable<'a> for Tcp<'a> {
    type Packet = TcpPacket<'a>;
    type PacketMut = MutableTcpPacket<'a>;
    type LayerMutType = TcpMut;

    create_default_immutable!();

    fn get_layer_from_buf(buf: &'_ [u8], layer: Layers) -> Option<Layer<'_>> {
        let tcp_size = TcpPacket::minimum_packet_size();
        let buf = &buf[tcp_size..buf.len()];
        if matches!(layer, Layers::Payload) {
            Some(Layer::Payload(Payload::new(buf)))
        } else {
            Payload::get_layer_from_buf(buf, layer)
        }
    }
}

impl Display for TcpMut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(eth) = TcpPacket::new(&self.buf) {
            write!(
                f,
                "Tcp (s: {}, d: {})",
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

//
#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_tcp_layer() {
        let packet = hex::decode("b3ece804018999b993a5ee1d50100200de6400000000").expect("failed");
        {
            let mut tcp = TcpMut::from_buf(packet.clone()).expect("");
            assert_eq!(
                &packet,
                tcp.clone().build().expect("could not build").as_slice()
            );
            let pnet = tcp.modify().expect("Could not modify tcp packet");
            assert_eq!(pnet.get_destination(), 59396);
            assert_eq!(pnet.get_source(), 46060);
        }
    }
}
