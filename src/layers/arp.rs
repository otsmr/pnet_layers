use crate::{
    Layer, LayerImmutable, LayerMutable, Layers, create_default_immutable, create_modify,
    create_set_payload,
};
use pnet::packet::arp::{ArpPacket, MutableArpPacket};
use std::fmt::Display;

/// Immutable representation of an arp packet
#[derive(Debug)]
pub struct Arp<'a> {
    buf: &'a [u8],
}

#[derive(Debug, Clone)]
/// Mutable representation of an arp packet
pub struct ArpMut {
    buf: Vec<u8>,
}

impl<'a> LayerMutable<'a> for ArpMut {
    type PacketMut = MutableArpPacket<'a>;
    fn new() -> Self {
        Self {
            buf: vec![0; ArpPacket::minimum_packet_size()],
        }
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

impl<'a> LayerImmutable<'a> for Arp<'a> {
    type Packet = ArpPacket<'a>;
    type PacketMut = MutableArpPacket<'a>;
    type LayerMutType = ArpMut;

    create_default_immutable!();
    fn get_layer_from_buf(_buf: &'_ [u8], _layer: Layers) -> Option<Layer<'_>> {
        None
    }
}

impl Display for ArpMut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(eth) = ArpPacket::new(&self.buf) {
            write!(
                f,
                "Arp (target: {}, src: {})",
                eth.get_target_hw_addr(),
                eth.get_sender_hw_addr()
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use pnet::util::MacAddr;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_arp_layer() {
        let mac = MacAddr::from_str("3c:ce:33:33:33:33").expect("could not get mac");
        let expected = [
            0u8, 0, 0, 0, 0, 0, 0, 0, 60, 206, 51, 51, 51, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0,
        ];
        {
            // test mutable and build
            let mut arp = ArpMut::new();
            let mut pnet = arp.modify().expect("Could not modify arp packet");
            pnet.set_sender_hw_addr(mac);
            assert_eq!(&expected, arp.build().expect("could not build").as_slice());
        }

        let arp = Arp::new(&expected);
        {
            // convert to pnet
            let pnet = arp.as_pnet().expect("could not generate pnet");
            assert_eq!(mac, pnet.get_sender_hw_addr());
        }
        {
            // convert imutable to mutable and build
            let mut arp = arp.as_mut().expect("could not generate pnet");
            {
                let mut pnet = arp.modify().expect("Could not modify arp packet");
                pnet.set_sender_hw_addr(MacAddr::zero());
            }
            assert_eq!(
                &[0u8; 28],
                arp.clone().build().expect("could not build").as_slice()
            );
            {
                let mut pnet = arp.modify().expect("Could not modify arp packet");
                pnet.set_sender_hw_addr(mac);
            }
            assert_eq!(&expected, arp.build().expect("could not build").as_slice());
        }

        assert!(arp.get_layer(Layers::Udp).is_none());
    }
}
