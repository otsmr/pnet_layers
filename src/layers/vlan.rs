use crate::layers::ether::get_layer_with_ether_type;
use crate::{
    ArpMut, Ipv4Mut, Ipv6Mut, Layer, LayerImmutable, LayerMut, LayerMutable, Layers,
    create_add_layer, create_default_immutable, create_from_buf, create_get_layer, create_modify,
    create_set_payload,
};
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::vlan::{MutableVlanPacket, VlanPacket};
use std::fmt::{Debug, Display};

/// Immutable representation of an VLAN packet
#[derive(Debug)]
pub struct Vlan<'a> {
    buf: &'a [u8],
}

#[derive(Clone)]
/// Mutable representation of an VLAN packet
pub struct VlanMut {
    buf: Vec<u8>,
    /// The upper layer of the vlan
    pub upper_layer: Option<Box<LayerMut>>,
}

impl<'a> LayerMutable<'a> for VlanMut {
    type PacketMut = MutableVlanPacket<'a>;
    fn new() -> Self {
        Self {
            buf: vec![0; VlanPacket::minimum_packet_size()],
            upper_layer: None,
        }
    }

    fn switch_src_dst(&mut self) {
        if let Some(upper_layer) = self.upper_layer.as_mut() {
            upper_layer.switch_src_dst();
        }
    }

    create_modify!();
    create_set_payload!();
    create_add_layer!(Vlan, Ipv6, Ipv4, Arp; { Ipv6 => Vlan, Ipv4 => Vlan, Arp => Vlan});
    create_get_layer!(Vlan, Ipv4, Ipv6, Arp);
    create_from_buf!(
        VlanPacket,
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
                self.modify()?.set_ethertype(EtherTypes::Ipv4);
            }
            #[allow(clippy::unwrap_used)]
            if matches!(**self.upper_layer.as_ref().unwrap(), LayerMut::Ipv6(_)) {
                self.modify()?.set_ethertype(EtherTypes::Ipv6);
            }
            #[allow(clippy::unwrap_used)]
            if matches!(**self.upper_layer.as_ref().unwrap(), LayerMut::Vlan(_)) {
                self.modify()?.set_ethertype(EtherTypes::Vlan);
            }
            #[allow(clippy::unwrap_used)]
            if matches!(**self.upper_layer.as_ref().unwrap(), LayerMut::Arp(_)) {
                self.modify()?.set_ethertype(EtherTypes::Arp);
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

impl<'a> LayerImmutable<'a> for Vlan<'a> {
    type Packet = VlanPacket<'a>;
    type PacketMut = MutableVlanPacket<'a>;
    type LayerMutType = VlanMut;

    create_default_immutable!();

    fn get_layer_from_buf(buf: &'_ [u8], layer: Layers) -> Option<Layer<'_>> {
        let eth = VlanPacket::new(buf)?;
        let eth_size = VlanPacket::minimum_packet_size();
        let buf = &buf[eth_size..buf.len()];
        get_layer_with_ether_type(eth.get_ethertype(), buf, layer)
    }
}

impl Display for VlanMut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(eth) = VlanPacket::new(&self.buf) {
            write!(f, "Vlan (id: {})", eth.get_vlan_identifier())?;
            if let Some(upper) = &self.upper_layer {
                write!(f, " > {upper}")?;
            }
        }
        Ok(())
    }
}

impl Debug for VlanMut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(eth) = VlanPacket::new(&self.buf) {
            write!(
                f,
                "id: {}, prio: {:?}, drop: {}",
                eth.get_vlan_identifier(),
                eth.get_priority_code_point(),
                eth.get_drop_eligible_indicator()
            )?;
            if let Some(upper) = &self.upper_layer {
                write!(f, " > {upper:?}")?;
            }
        }
        Ok(())
    }
}
