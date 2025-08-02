use crate::{
    EtherMut, Ipv4Mut, LayerMut, LayerMutable, Layers, TcpMut, VlanMut, helper::arp::ArpPacket,
};
use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// A helper struct to define the different parameters to craft a TCP packet including the Ethernet, VLAN and IPv4 layers
pub struct TcpPacket {
    /// Ethernet source address
    pub eth_src: MacAddr,
    /// Ethernet destination address
    pub eth_dst: MacAddr,
    /// If set, the VLAN id
    pub vlan_id: Option<u16>,
    /// IPv4 source address
    pub ipv4_src: Ipv4Addr,
    /// IPv4 destination address
    pub ipv4_dst: Ipv4Addr,
    /// TCP destination port
    pub dport: u16,
    /// TCP source port
    pub sport: u16,
}

impl TcpPacket {
    /// creates a basic TCP packet setting all the parameters
    /// but without any TCP flags set
    #[must_use]
    pub fn basic(&self) -> Option<EtherMut> {
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

        let mut ipv4 = Ipv4Mut::new();
        {
            let mut pkt = ipv4.modify()?;
            pkt.set_source(self.ipv4_src);
            pkt.set_destination(self.ipv4_dst);
        }

        ether.add(LayerMut::Ipv4(ipv4));

        let mut tcp = TcpMut::new();
        {
            let mut pkt = tcp.modify()?;
            pkt.set_destination(self.dport);
            pkt.set_source(self.sport);
        }

        ether.add(LayerMut::Tcp(tcp));
        Some(ether)
    }

    /// Crafts an TCP Syn packet
    #[must_use]
    pub fn syn(&self, seq: u32) -> Option<EtherMut> {
        let mut ether = self.basic()?;
        if let Some(LayerMut::Tcp(tcp)) = ether.get_layer(&Layers::Tcp) {
            let mut pkt = tcp.modify()?;
            pkt.set_flags(pnet::packet::tcp::TcpFlags::SYN);
            pkt.set_window(515);
            pkt.set_acknowledgement(0);
            pkt.set_sequence(seq);
        }
        Some(ether)
    }

    /// Create an ARP packet so the target of the SYN can find the sender
    #[must_use]
    pub fn arp(&self) -> Option<EtherMut> {
        ArpPacket::from_tcp(self).reply()
    }
}
