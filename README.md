# pnet_layers

A scapy like wrapper around the [pnet](https://crates.io/crates/pnet) crate to easily parse, craft or manipulate network packets.

```rs
use pnet::util::MacAddr;
use pnet_layers::*;
use std::str::FromStr;

let mut ether = EtherMut::new();

if let Some(mut eth) = ether.modify() {
    eth.set_source(MacAddr::from_str("3c:ce:33:33:33:33").unwrap());
    eth.set_destination(MacAddr::broadcast());
}

ether.add(LayerMut::Vlan(VlanMut::new()));
ether.add(LayerMut::Ipv4(Ipv4Mut::new()));
ether.add(LayerMut::Udp(UdpMut::new()));
ether.add(LayerMut::Payload(PayloadMut::from_buf(vec![10; 10]).unwrap()));

for vlan_id in [1u16, 2, 3, 4] {
    let mut ether = ether.clone();
    if let Some(LayerMut::Vlan(vlan)) = ether.get_layer(&Layers::Vlan) {
        vlan.modify().unwrap().set_vlan_identifier(vlan_id);
    }

    println!("{ether}");
    // Ether (s: 3c:ce:33:33:33:33, d: 3c:ce:33:33:33:33) > Vlan (id: 1) > Ipv4 (s: 0.0.0.0, d: 0.0.0.0) > Udp (s: 0, d: 0) > [10, 10, 10, 10, 10, 10, 10, 10, 10, 10]
    // Ether (s: 3c:ce:33:33:33:33, d: 3c:ce:33:33:33:33) > Vlan (id: 2) > Ipv4 (s: 0.0.0.0, d: 0.0.0.0) > Udp (s: 0, d: 0) > [10, 10, 10, 10, 10, 10, 10, 10, 10, 10]
    // Ether (s: 3c:ce:33:33:33:33, d: 3c:ce:33:33:33:33) > Vlan (id: 3) > Ipv4 (s: 0.0.0.0, d: 0.0.0.0) > Udp (s: 0, d: 0) > [10, 10, 10, 10, 10, 10, 10, 10, 10, 10]
    // Ether (s: 3c:ce:33:33:33:33, d: 3c:ce:33:33:33:33) > Vlan (id: 4) > Ipv4 (s: 0.0.0.0, d: 0.0.0.0) > Udp (s: 0, d: 0) > [10, 10, 10, 10, 10, 10, 10, 10, 10, 10]

    // Using the .build() function all required params will be set including:
    // - EtherType
    // - Ipv4 size, checksum
    // - UDP size, checksum
    
    // Also some magic fields will be set. For example the IPv4 TTL
    // value will be set to `MAGIC_IPV4_TTL`.
    // This makes is possible to identify the packet later, like
    // when doing an firewall test. See all magic bytes in the
    // `magics.rs` file

    if let Some(bytes) = ether.build() {
        // bytes now be send
        // let _ = tx.send_to(&bytes, None);

        // EtherMut can also be created from a buffer...
        if let Some(mut send) = EtherMut::from_buf(bytes) {
            println!("{send}");
            // Ether (s: 3c:ce:33:33:33:33, d: 3c:ce:33:33:33:33) > Vlan (id: 1) > Ipv4 (s: 0.0.0.0, d: 0.0.0.0) > Udp (s: 0, d: 0) > [10, 10, 10, 10, 10, 10, 10, 10, 10, 10]
            // ...

        }
    }

}
```