use crate::{ArpMut, EtherMut, LayerMut, LayerMutable, VlanMut, helper::tcp::TcpPacket};
use pnet::{
    packet::arp::{ArpHardwareTypes, ArpOperations},
    util::MacAddr,
};
use std::net::Ipv4Addr;

/// A helper struct to define the different parameters to craft a ARP packet including the Ethernet and VLAN layers
pub struct ArpPacket {
    eth_src: MacAddr,
    eth_dst: MacAddr,
    vlan_id: Option<u16>,
    ipv4_src: Ipv4Addr,
    ipv4_dst: Ipv4Addr,
}

impl ArpPacket {
    /// craft a `ArpPacket` from a `TcpPacket`
    #[must_use]
    pub fn from_tcp(target: &TcpPacket) -> ArpPacket {
        ArpPacket {
            eth_src: target.eth_src,
            eth_dst: target.eth_dst,
            vlan_id: target.vlan_id,
            ipv4_dst: target.ipv4_dst,
            ipv4_src: target.ipv4_src,
        }
    }
    /// craft an Arp Replay packet
    #[must_use]
    pub fn reply(&self) -> Option<EtherMut> {
        let mut ether = EtherMut::new();
        {
            let mut eth = ether.modify()?;
            eth.set_source(self.eth_src);
            eth.set_destination(self.eth_dst);
        }

        if let Some(vlan_id) = self.vlan_id {
            let mut vlan = VlanMut::new();
            {
                let mut pkt = vlan.modify()?;
                pkt.set_vlan_identifier(vlan_id);
            }
            ether.add(LayerMut::Vlan(vlan));
        }

        let mut arp = ArpMut::new();
        {
            let mut pkt = arp.modify()?;
            pkt.set_protocol_type(pnet::packet::ethernet::EtherTypes::Ipv4);
            pkt.set_hardware_type(ArpHardwareTypes::Ethernet);
            pkt.set_hw_addr_len(6);
            pkt.set_proto_addr_len(4);
            pkt.set_operation(ArpOperations::Reply);
            pkt.set_sender_hw_addr(self.eth_src);
            pkt.set_sender_proto_addr(self.ipv4_src);
            pkt.set_target_proto_addr(self.ipv4_dst);
            pkt.set_target_hw_addr(self.eth_dst);
        }
        ether.add(LayerMut::Arp(arp));
        Some(ether)
    }
}
