use crate::magics::MAGIC_IPV4_TTL;
use crate::{
    Icmp, IcmpMut, Layer, LayerImmutable, LayerMut, LayerMutable, Layers, Tcp, TcpMut, Udp, UdpMut,
    create_add_layer, create_default_immutable, create_from_buf, create_get_layer, create_modify,
    create_set_payload, create_switch_layer,
};
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use rand::Rng;
use std::fmt::{Debug, Display};

/// Immutable representation of an Ipv4 packet
#[derive(Debug)]
pub struct Ipv4<'a> {
    buf: &'a [u8],
}

#[derive(Clone)]
/// Mutable representation of an Ipv4 packet
pub struct Ipv4Mut {
    /// the packet as bytes
    pub buf: Vec<u8>,
    /// the upper layer
    pub upper_layer: Option<Box<LayerMut>>,
}

impl<'a> LayerMutable<'a> for Ipv4Mut {
    type PacketMut = MutableIpv4Packet<'a>;
    fn new() -> Self {
        Self {
            buf: vec![0; Ipv4Packet::minimum_packet_size()],
            upper_layer: None,
        }
    }

    create_modify!();
    create_set_payload!();
    create_switch_layer!();
    create_add_layer!(Udp, Tcp, Icmp; {});
    create_get_layer!(Udp, Tcp, Icmp);
    create_from_buf!(
        Ipv4Packet,
        get_next_level_protocol,
        IpNextHeaderProtocols,
        Udp => UdpMut,
        Icmp => IcmpMut,
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
            #[allow(clippy::unwrap_used)]
            if matches!(**self.upper_layer.as_ref().unwrap(), LayerMut::Icmp(_)) {
                upper_layer = Some(IpNextHeaderProtocols::Icmp);
            }
        }

        let saddr;
        let daddr;

        {
            let mut ipv4 = self.modify()?;

            saddr = ipv4.get_source();
            daddr = ipv4.get_destination();

            if ipv4.get_version() == 0 {
                ipv4.set_version(4);
            }
            if ipv4.get_identification() == 0 {
                let ident: u16 = rand::rng().random_range(0..u16::MAX);
                ipv4.set_identification(ident);
            }
            if ipv4.get_header_length() == 0 {
                ipv4.set_header_length(5);
            }
            if ipv4.get_ttl() == 0 {
                ipv4.set_ttl(MAGIC_IPV4_TTL);
            }
            if let Some(upper) = upper_layer {
                ipv4.set_next_level_protocol(upper);
            }
        }

        let payload = match self.upper_layer.clone() {
            Some(child) => match *child {
                LayerMut::Udp(udp) => udp.build_from_ipv4(saddr, daddr)?,
                LayerMut::Tcp(tcp) => tcp.build_from_ipv4(saddr, daddr)?,
                LayerMut::Icmp(pkt) => pkt.build()?,
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
        let len = self.buf.len() as u16;

        {
            let mut ipv4 = self.modify()?;
            ipv4.set_total_length(len);
            ipv4.set_checksum(pnet::packet::ipv4::checksum(&ipv4.to_immutable()));
        }

        Some(self.buf)
    }
}

// Usage of the macro

impl<'a> LayerImmutable<'a> for Ipv4<'a> {
    type Packet = Ipv4Packet<'a>;
    type PacketMut = MutableIpv4Packet<'a>;
    type LayerMutType = Ipv4Mut;

    create_default_immutable!();

    fn get_layer_from_buf(buf: &'_ [u8], layer: Layers) -> Option<Layer<'_>> {
        let ipv4 = Ipv4Packet::new(buf)?;
        let ipv4_size = Ipv4Packet::minimum_packet_size();
        let buf = &buf[ipv4_size..buf.len()];
        Some(match ipv4.get_next_level_protocol() {
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
            IpNextHeaderProtocols::Icmp => {
                if matches!(layer, Layers::Icmp) {
                    Layer::Icmp(Icmp::new(buf))
                } else {
                    Icmp::get_layer_from_buf(buf, layer)?
                }
            }
            _ => {
                log::debug!(
                    "Ipv4 next level protocol missing: {}",
                    ipv4.get_next_level_protocol(),
                );
                return None;
            }
        })
    }
}

impl Display for Ipv4Mut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(eth) = Ipv4Packet::new(&self.buf) {
            write!(
                f,
                "Ipv4 (s: {}, d: {})",
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

impl Debug for Ipv4Mut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(eth) = Ipv4Packet::new(&self.buf) {
            write!(
                f,
                "Ipv4 (s: {}, d: {})",
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
