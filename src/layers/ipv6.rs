use crate::{
    Layer, LayerImmutable, LayerMut, LayerMutable, Layers, Tcp, TcpMut, Udp, UdpMut,
    create_add_layer, create_default_immutable, create_from_buf, create_get_layer, create_modify,
    create_set_payload, create_switch_layer,
};
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use std::fmt::{Debug, Display};

/// Immutable representation of an Ipv6 packet
#[derive(Debug)]
pub struct Ipv6<'a> {
    buf: &'a [u8],
}

#[derive(Clone)]
/// Mutable representation of an Ipv6 packet
pub struct Ipv6Mut {
    buf: Vec<u8>,
    upper_layer: Option<Box<LayerMut>>,
}

impl<'a> LayerMutable<'a> for Ipv6Mut {
    type PacketMut = MutableIpv6Packet<'a>;
    fn new() -> Self {
        Self {
            buf: vec![0; Ipv6Packet::minimum_packet_size()],
            upper_layer: None,
        }
    }

    create_modify!();
    create_set_payload!();
    create_switch_layer!();
    create_add_layer!(Udp, Tcp; {});
    create_get_layer!(Udp, Tcp);
    create_from_buf!(
        Ipv6Packet,
        get_next_header,
        IpNextHeaderProtocols,
        Udp => UdpMut,
        Tcp => TcpMut
    );

    fn build(mut self) -> Option<Vec<u8>> {
        let mut upper_layer = None;

        #[allow(clippy::collapsible_if)]
        if self.upper_layer.is_some() {
            #[allow(clippy::unwrap_used)]
            if matches!(**self.upper_layer.as_ref().unwrap(), LayerMut::Udp(_)) {
                upper_layer = Some(IpNextHeaderProtocols::Udp);
            }
            #[allow(clippy::unwrap_used)]
            if matches!(**self.upper_layer.as_ref().unwrap(), LayerMut::Tcp(_)) {
                upper_layer = Some(IpNextHeaderProtocols::Tcp);
            }
        }

        let saddr;
        let daddr;

        {
            let mut ipv6 = self.modify()?;

            saddr = ipv6.get_source();
            daddr = ipv6.get_destination();

            if ipv6.get_version() == 0 {
                ipv6.set_version(6);
            }
            // if ipv4.get_identification() == 0 {
            //     let ident: u16 = rand::rng().random_range(0..u16::MAX);
            //     ipv4.set_identification(ident);
            // }
            // if ipv4.get_header_length() == 0 {
            //     ipv4.set_header_length(5);
            // }
            // if ipv4.get_ttl() == 0 {
            //     ipv4.set_ttl(MAGIC_IPV4_TTL);
            // }
            if let Some(upper) = upper_layer {
                ipv6.set_next_header(upper);
            }
        }

        let payload = match self.upper_layer.clone() {
            Some(child) => match *child {
                LayerMut::Udp(udp) => udp.build_from_ipv6(saddr, daddr)?,
                LayerMut::Tcp(tcp) => tcp.build_from_ipv6(saddr, daddr)?,
                // LayerMut::Tcp(tcp) => vlan.build(),
                _ => panic!("child not possible"),
            },
            None => vec![],
        };

        self.buf.extend_from_slice(&payload);

        if self.buf.len() > u16::MAX as usize {
            return None;
        }

        #[allow(clippy::cast_possible_truncation)]
        let len = self.buf.len() as u16 - Ipv6Packet::minimum_packet_size() as u16;
        assert_eq!(Ipv6Packet::minimum_packet_size(), 40);

        {
            let mut ipv6 = self.modify()?;
            ipv6.set_payload_length(len);
            // ipv6.set_checksum(pnet::packet::ipv4::checksum(&ipv6.to_immutable()));
        }

        Some(self.buf)
    }
}

// Usage of the macro

impl<'a> LayerImmutable<'a> for Ipv6<'a> {
    type Packet = Ipv6Packet<'a>;
    type PacketMut = MutableIpv6Packet<'a>;
    type LayerMutType = Ipv6Mut;

    create_default_immutable!();

    fn get_layer_from_buf(buf: &'_ [u8], layer: Layers) -> Option<Layer<'_>> {
        let ipv4 = Ipv6Packet::new(buf)?;
        let ipv4_size = Ipv6Packet::minimum_packet_size();
        let buf = &buf[ipv4_size..buf.len()];
        Some(match ipv4.get_next_header() {
            IpNextHeaderProtocols::Udp => {
                if matches!(layer, Layers::Udp) {
                    Layer::Udp(Udp::new(buf))
                } else {
                    Udp::get_layer_from_buf(buf, layer)?
                }
            }
            IpNextHeaderProtocols::Tcp => {
                if matches!(layer, Layers::Tcp) {
                    Layer::Tcp(Tcp::new(buf))
                } else {
                    Tcp::get_layer_from_buf(buf, layer)?
                }
            }
            _ => {
                log::debug!(
                    "Ipv6 next level protocol missing: {}",
                    ipv4.get_next_header(),
                );
                return None;
            }
        })
    }
}

impl Display for Ipv6Mut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(eth) = Ipv6Packet::new(&self.buf) {
            write!(
                f,
                "Ipv6 (s: {}, d: {})",
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

impl Debug for Ipv6Mut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(eth) = Ipv6Packet::new(&self.buf) {
            write!(
                f,
                "Ipv6 (s: {}, d: {})",
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
