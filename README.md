# pnet_layers

`pnet_layers` is a scapy like wrapper around the [pnet](https://crates.io/crates/pnet) crate to easily parse, craft or manipulate network packets.

For this `pnet_layers` defines two `traits` which can be implemented for `structs` that are deriving `#[packet]` defined by the `pnet` library. The first `trait` is the `LayerImmutable` implementing functions without cloning the underlining buffer. And the `LayerMutable` that allows to modify the packet or to craft new onces as shown below.  

## Crafting a packet

To craft, for example, a UDP packet including all layers down to Ethernet the `EtherMut` can be used.

```rs
// Create a new Ethernet Packet
let mut ether = EtherMut::new();

// Modify the packet. The `modify` function returns the pnet defined mutable packet to modify the different field.
if let Some(mut eth) = ether.modify() {
    eth.set_source(MacAddr::from_str("3c:ce:33:33:33:33").unwrap());
    eth.set_destination(MacAddr::broadcast());
}

// Using the `add` function new layers can be added.
ether.add(LayerMut::Vlan(VlanMut::new()));
ether.add(LayerMut::Ipv4(Ipv4Mut::new()));
ether.add(LayerMut::Udp(UdpMut::new()));
ether.add(LayerMut::Payload(PayloadMut::from_buf(vec![10; 10]).unwrap()));

println!("{ether}");
// Ether (s: 3c:ce:33:33:33:33, d: ff:ff:ff:ff:ff:ff:ff) > Vlan (id: 1) > Ipv4 (s: 0.0.0.0, d: 0.0.0.0) > Udp (s: 0, d: 0) > [10, 10, 10, 10, 10, 10, 10, 10, 10, 10]

// Using the .build() function all required params will be set including:
// - EtherType
// - Ipv4 size, checksum
// - UDP size, checksum

// Also some magic fields will be set. For example the IPv4 TTL value will be set to `MAGIC_IPV4_TTL`.
// This makes is possible to identify the packet later, for example, in a Wireshark trace. 
// See all magic bytes in the `magics.rs` file

if let Some(bytes) = ether.build() {
    // bytes in format of Vec<u8> which can be send to the network
    // let _ = tx.send_to(&bytes, None);
}
```

## Parsing and manipulating

Packet can also be parsed from a `u8` array and then modified.

```rs
/// Parsing the packet from a buffer in this case an Ethernet packet.
if let Some(mut ether) = EtherMut::from_buf(bytes) {

    // Add an VLAN tag
    ether.add(LayerMut::Vlan(VlanMut::new()));

    // Searching for the PAYLOAD and modifying it
    if let Some(LayerMut::Payload(vlan)) = ether.get_layer(&Layers::Payload) {
        vlan.set_payload(vec![11; 10]);
    }

    // Building the manipulated packet. This will also recalculate all the different checksums.
    // The magic values are only changed if the value was `0`. So when the TTL value is already set, this will not be changed to the magic value.
    if let Some(bytes) = ether.build() {
        // let _ = tx.send_to(&bytes, None);
    }
}
```

## Creating a new layer

Currently only a few layers are defined in [src/layers](src/layers/). If you want to add a new layer, please crate a new file in the `layers` folder with the protocol name. And implement the two traits. Most functions can be implemented by macros defined in `macros.rs`. 

# License
This project is licensed under the [Apache-2.0](./LICENSE) license