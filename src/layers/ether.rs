use crate::layers::{Arp, ArpMut, Ipv4, Ipv4Mut, Ipv6, Ipv6Mut, LayerImmutable, Vlan, VlanMut};
use crate::{
    Layer, LayerMut, LayerMutable, Layers, create_default_immutable, create_set_payload,
    create_switch_layer,
};
use crate::{create_add_layer, create_from_buf, create_get_layer, create_modify};
use pnet::packet::Packet;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use std::fmt::{Debug, Display};

/// Immutable representation of an Ethernet packet
#[derive(Debug)]
pub struct Ether<'a> {
    buf: &'a [u8],
}

#[derive(Clone)]
/// Mutable representation of an Ethernet packet
pub struct EtherMut {
    buf: Vec<u8>,
    /// The upper layer of the ethernet
    pub upper_layer: Option<Box<LayerMut>>,
}

impl<'a> LayerMutable<'a> for EtherMut {
    type PacketMut = MutableEthernetPacket<'a>;

    fn new() -> Self {
        Self {
            buf: vec![0; EthernetPacket::minimum_packet_size()],
            upper_layer: None,
        }
    }

    create_modify!();
    create_set_payload!();
    create_switch_layer!();
    create_add_layer!(Vlan, Ipv4, Ipv6, Arp; { Ipv4 => Vlan, Arp => Vlan, Ipv6 => Vlan});
    create_get_layer!(Vlan, Ipv4, Ipv6, Arp);
    create_from_buf!(
        EthernetPacket,
        get_ethertype,
        EtherTypes,
        Vlan => VlanMut,
        Ipv4 => Ipv4Mut,
        Ipv6 => Ipv6Mut,
        Arp => ArpMut
    );

    fn build(mut self) -> Option<Vec<u8>> {
        if self.upper_layer.is_some() {
            #[allow(clippy::unwrap_used)]
            if matches!(**self.upper_layer.as_ref().unwrap(), LayerMut::Ipv4(_)) {
                self.modify().unwrap().set_ethertype(EtherTypes::Ipv4);
            }
            #[allow(clippy::unwrap_used)]
            if matches!(**self.upper_layer.as_ref().unwrap(), LayerMut::Ipv6(_)) {
                self.modify().unwrap().set_ethertype(EtherTypes::Ipv6);
            }
            #[allow(clippy::unwrap_used)]
            if matches!(**self.upper_layer.as_ref().unwrap(), LayerMut::Vlan(_)) {
                self.modify().unwrap().set_ethertype(EtherTypes::Vlan);
            }
            #[allow(clippy::unwrap_used)]
            if matches!(**self.upper_layer.as_ref().unwrap(), LayerMut::Arp(_)) {
                self.modify().unwrap().set_ethertype(EtherTypes::Arp);
            }
        }
        let payload = match self.upper_layer {
            Some(child) => match *child {
                LayerMut::Ipv4(ipv4) => ipv4.build()?,
                LayerMut::Ipv6(ipv6) => ipv6.build()?,
                LayerMut::Vlan(vlan) => vlan.build()?,
                LayerMut::Arp(arp) => arp.build()?,
                _ => panic!("child not possible"),
            },
            None => vec![],
        };
        self.buf.extend_from_slice(&payload);
        Some(self.buf)
    }
}

impl<'a> LayerImmutable<'a> for Ether<'a> {
    type Packet = EthernetPacket<'a>;
    type PacketMut = MutableEthernetPacket<'a>;
    type LayerMutType = EtherMut;

    create_default_immutable!();

    fn get_layer_from_buf(buf: &'_ [u8], layer: Layers) -> Option<Layer<'_>> {
        let eth = EthernetPacket::new(buf)?;
        let eth_size = EthernetPacket::minimum_packet_size();
        let buf = &buf[eth_size..buf.len()];
        get_layer_with_ether_type(eth.get_ethertype(), buf, layer)
    }
}

pub(super) fn get_layer_with_ether_type(
    ether_type: EtherType,
    buf: &'_ [u8],
    layer: Layers,
) -> Option<Layer<'_>> {
    Some(match ether_type {
        EtherTypes::Ipv4 => {
            if matches!(layer, Layers::Vlan) {
                return None;
            }
            if matches!(layer, Layers::Ipv4) {
                Layer::Ipv4(Ipv4::new(buf))
            } else {
                Ipv4::get_layer_from_buf(buf, layer)?
            }
        }
        EtherTypes::Ipv6 => {
            if matches!(layer, Layers::Vlan) {
                return None;
            }
            if matches!(layer, Layers::Ipv6) {
                Layer::Ipv6(Ipv6::new(buf))
            } else {
                Ipv6::get_layer_from_buf(buf, layer)?
            }
        }
        EtherTypes::Vlan => {
            if matches!(layer, Layers::Vlan) {
                Layer::Vlan(Vlan::new(buf))
            } else {
                Vlan::get_layer_from_buf(buf, layer)?
            }
        }
        EtherTypes::Arp => {
            if matches!(layer, Layers::Arp) {
                Layer::Arp(Arp::new(buf))
            } else {
                return None;
                // Vlan::get_layer_from_buf(buf, layer)?
            }
        }
        EtherTypes::Ptp => {
            // log::debug!("Ignoring PTP");
            return None;
            // if matches!(layer, Layers::Ptp) {
            //     Layer::Ptp(buf.to_vec())
            // } else {
            //     log::debug!("Ptp is ignored");
            //     return None;
            //     // Vlan::get_layer_from_buf(buf, layer)?
            // }
        }
        _ => {
            if format!("{ether_type}") == "unknown" {
                log::debug!("Unknown EtherType: {ether_type}");
            } else {
                log::warn!("Unknown EtherType: {ether_type}");
            }
            return None;
        }
    })
}

impl Display for EtherMut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(eth) = EthernetPacket::new(&self.buf) {
            write!(
                f,
                "Ether (s: {}, d: {})",
                eth.get_source(),
                eth.get_destination(),
            )?;
            if let Some(upper) = &self.upper_layer {
                write!(f, " > {upper}")?;
            }
        }
        Ok(())
    }
}

impl Debug for EtherMut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(eth) = EthernetPacket::new(&self.buf) {
            let mut ethertype = format!("{}", eth.get_ethertype());
            if ethertype == "unknown" {
                ethertype = format!("{:04x}", eth.get_ethertype().0);
            }
            write!(
                f,
                "Ether (s: {}, d: {}, {ethertype})",
                eth.get_source(),
                eth.get_destination(),
            )?;
            if let Some(upper) = &self.upper_layer {
                write!(f, " > {upper:?}")?;
            }
        }
        Ok(())
    }
}
