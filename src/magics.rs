//! Magic consists of different const values which
//! will be set if the value is not defined. These values allows to identify the packet when it
//! was send by `pnet_layers`.

/// Magic value for the TTL value int the IPv4 packet. Added by `pnet_layers` to make the packet identifiable.
pub const MAGIC_IPV4_TTL: u8 = 170;

/// Magic value for the vlan prio. Added by `pnet_layers` to make the packet identifiable.
pub const MAGIC_VLAN_PRIO: u8 = 6;
