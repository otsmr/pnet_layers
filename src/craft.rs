use crate::{Ipv4Mut, LayerMut, LayerMutable, VlanMut};
use pnet::packet::vlan::ClassOfService;
use std::collections::HashMap;

impl LayerMut {
    /// Parses the packet from a string
    /// ```rs
    /// let pkt = LayerMut::parse("Vlan(id: 10) / IPv4(src: 10.10.10.10, dst: 1.1.1.1)");
    /// ```
    #[must_use]
    pub fn parse(input: &str) -> Option<LayerMut> {
        // Create a mutable vector to hold the layers
        let mut packet: Option<LayerMut> = None;

        let layers = input.split('/');

        for layer in layers {
            // Match the Vlan layer
            if let Some(pkt) = parse_vlan(layer) {
                let pkt = LayerMut::Vlan(pkt);
                if let Some(packet) = &mut packet {
                    packet.add(pkt);
                } else {
                    packet = Some(pkt);
                }
            }
            // Match the IPv4 layer
            else if let Some(pkt) = parse_ipv4(layer) {
                let pkt = LayerMut::Ipv4(pkt);
                if let Some(packet) = &mut packet {
                    packet.add(pkt);
                } else {
                    packet = Some(pkt);
                }
            }
        }

        packet
    }
}

pub fn parse_options(options: &str) -> HashMap<&str, &str> {
    let parts: Vec<&str> = options.split(',').collect();
    let mut ordered_parts = HashMap::new();
    for part in parts {
        if let Some((key, value)) = part.split_once(':') {
            ordered_parts.insert(key.trim(), value.trim());
        }
    }
    ordered_parts
}

// Helper function to parse Vlan layer
pub fn parse_vlan(layer: &str) -> Option<VlanMut> {
    if let Some(options) = layer
        .strip_prefix("Vlan(")
        .and_then(|s| s.strip_suffix(")"))
    {
        let parts = parse_options(options);
        let mut vlan = VlanMut::new();
        if let Some(mut vlan) = vlan.modify() {
            if let Some(value) = parts.get("id")
                && let Ok(parsed) = value.parse()
            {
                println!("parsed vlan id");
                vlan.set_vlan_identifier(parsed);
            }
            if let Some(value) = parts.get("prio")
                && let Ok(parsed) = value.parse()
            {
                vlan.set_priority_code_point(ClassOfService::new(parsed));
            }
        }
        return Some(vlan);
    }
    None
}

// Helper function to parse IPv4 layer
pub fn parse_ipv4(layer: &str) -> Option<Ipv4Mut> {
    if let Some(options) = layer
        .strip_prefix("IPv4(")
        .and_then(|s| s.strip_suffix(")"))
    {
        let parts = parse_options(options);
        let mut vlan = Ipv4Mut::new();
        if let Some(mut vlan) = vlan.modify() {
            if let Some(value) = parts.get("src")
                && let Ok(parsed) = value.parse()
            {
                vlan.set_source(parsed);
            }
            if let Some(value) = parts.get("dst")
                && let Ok(parsed) = value.parse()
            {
                vlan.set_destination(parsed);
            }
        }
        return Some(vlan);
    }
    None
}
