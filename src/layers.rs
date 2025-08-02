pub(crate) mod arp;
pub(crate) mod ether;
pub(crate) mod icmp;
pub(crate) mod ipv4;
pub(crate) mod ipv6;
pub(crate) mod payload;
pub(crate) mod tcp;
pub(crate) mod udp;
pub(crate) mod vlan;

use std::fmt::Display;

use crate::layers;
use crate::layers::arp::{Arp, ArpMut};
use crate::layers::ether::{Ether, EtherMut};
use crate::layers::icmp::{Icmp, IcmpMut};
use crate::layers::ipv4::{Ipv4, Ipv4Mut};
use crate::layers::ipv6::{Ipv6, Ipv6Mut};
use crate::layers::payload::{Payload, PayloadMut};
use crate::layers::tcp::{Tcp, TcpMut};
use crate::layers::udp::{Udp, UdpMut};
use crate::layers::vlan::{Vlan, VlanMut};

layers!(
    Ether => EtherMut,
    Vlan => VlanMut,
    Arp => ArpMut,
    Ipv4 => Ipv4Mut,
    Ipv6 => Ipv6Mut,
    Icmp => IcmpMut,
    Udp => UdpMut,
    Tcp => TcpMut,
    Payload => PayloadMut
);

/// Implements functions for immutable layer representation
pub trait LayerImmutable<'a> {
    /// Immutable packet type of the pnet lib
    type Packet;
    /// Mutable packet type of the pnet lib
    type PacketMut;
    ///  Packet specific`LayerMut` type used to convert the immutable to a mutable packet
    type LayerMutType;
    /// Creates a new immutable representation of the packet
    fn new(buf: &'a [u8]) -> Self;
    /// Returns a mutable packet to modification this will cause a copy of payload
    fn as_mut(&self) -> Option<Self::LayerMutType>;
    /// Retunrs a immutable reference to the raw packet
    fn get_buf(&self) -> &[u8];
    /// returns immutable pnet representation
    fn as_pnet(&self) -> Option<Self::Packet>;
    /// returns mutable pnet representation this will cause a copy of payload
    fn as_mut_pnet(&self) -> Option<Self::PacketMut>;
    /// Searches in the self buffer for the layer provided and if exists returns it
    fn get_layer(&'a self, layer: Layers) -> Option<Layer<'a>>;
    /// Searches in the buffer for the layer provided and if exists returns it
    fn get_layer_from_buf(buf: &'_ [u8], layer: Layers) -> Option<Layer<'_>>;
}

/// Implements functions for packet manipulation
pub trait LayerMutable<'a>: Sized {
    /// Mutable packet type of the pnet lib
    type PacketMut;

    /// Creates a new mut layer instance
    fn new() -> Self;

    /// Creates a new mut layer instance base on the provided buffer
    fn from_buf(buf: Vec<u8>) -> Option<Self>;

    /// Returns a mutable reference to the requested layer
    fn get_layer(&'a mut self, _layer: &Layers) -> Option<&'a mut LayerMut> {
        None
    }

    /// This returns the a mutable reference to the pnet type to modify properties of the packet.
    /// If you want to modify the payload YOU must use `set_payload` from the `LayerMutable` trait
    fn modify(&'a mut self) -> Option<Self::PacketMut>;

    /// Modifies the payload of the packet
    fn set_payload(&'a mut self, payload: &[u8]);

    /// Add upper layer as payload. Returns false if it fails e.g layer is not allowed as payload
    /// If already a upper layer is defined this will be propagated to this upper layer
    fn add(&mut self, _layer: LayerMut) -> bool {
        false
    }

    /// If the layer contains a src and a dest this will be switch and propagated to the last
    /// layer. When called on an Eth/Ipv4/Udp this will switch the mac, ipv and the port numbers
    fn switch_src_dst(&mut self) {}

    /// This returns the builded packet as bytes ready to send on the wire.
    /// The following will be modified:
    ///     - Required packet structure information will be set to there default value if not
    ///     already set
    ///     - Payload types will be set
    ///     - Checksum will be calculated
    fn build(self) -> Option<Vec<u8>>;
}
