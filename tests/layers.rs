use pnet::util::MacAddr;
use pnet_layers::{EtherMut, Ipv4Mut, LayerMut, LayerMutable, Layers, TcpMut, VlanMut};
use std::net::Ipv4Addr;
use std::str::FromStr;

#[test]
fn test_layer_build() {
    let eth_dst = MacAddr::from_str("33:33:33:33:33:33").unwrap();
    let eth_src = MacAddr::from_str("44:44:44:44:44:44").unwrap();
    let vlan_id = 1;
    let ipv4_src = Ipv4Addr::from_str("11.11.11.11").unwrap();
    let ipv4_dst = Ipv4Addr::from_str("169.254.17.10").unwrap();
    let sport = 1000;
    let dport = 13400;

    // Testing adding layers
    let mut ether = EtherMut::new();
    {
        let mut eth = ether.modify().unwrap();
        eth.set_source(eth_src);
        eth.set_destination(eth_dst);
    }

    let mut vlan = VlanMut::new();
    {
        let mut pkt = vlan.modify().unwrap();
        pkt.set_vlan_identifier(vlan_id);
    }

    let mut ipv4 = Ipv4Mut::new();
    {
        let mut pkt = ipv4.modify().unwrap();
        pkt.set_source(ipv4_src);
        pkt.set_destination(ipv4_dst);
        pkt.set_identification(10); // make the testing static
    }

    let mut tcp = TcpMut::new();
    {
        let mut pkt = tcp.modify().unwrap();
        pkt.set_destination(dport);
        // pkt.set_destination(3496);
        pkt.set_source(sport);
        pkt.set_flags(pnet::packet::tcp::TcpFlags::SYN);
        pkt.set_window(515);
        // pkt.set_data_offset(20);
        pkt.set_acknowledgement(0);
    }

    let mut ether_tcp = ether.clone();
    assert!(ether_tcp.add(LayerMut::Vlan(vlan.clone())));
    assert!(ether_tcp.add(LayerMut::Ipv4(ipv4.clone())));
    assert!(ether_tcp.add(LayerMut::Tcp(tcp.clone())));

    {
        // adding VLAN after Ipv4 -> Should be replaced so that ether > vlan > ipv4 > tcp
        let mut ether_tcp_vlan = ether.clone();
        assert!(ether_tcp_vlan.add(LayerMut::Ipv4(ipv4.clone())));
        assert!(ether_tcp_vlan.add(LayerMut::Vlan(vlan.clone())));
        assert!(ether_tcp_vlan.add(LayerMut::Tcp(tcp.clone())));

        assert_eq!(format!("{ether_tcp:?}"), format!("{ether_tcp_vlan:?}"));
        assert_eq!(
            ether_tcp.clone().build().unwrap(),
            ether_tcp_vlan.build().unwrap()
        );
    }

    {
        let mut ether_tcp_vlan = ether.clone();
        // there is no IPv4 layer can not add Tcp
        assert!(!ether_tcp_vlan.add(LayerMut::Tcp(tcp)));
    }

    {
        let pnet = ether_tcp.modify().unwrap();
        assert_eq!(pnet.get_source(), eth_src);
    }

    {
        if let LayerMut::Vlan(pkt) = ether_tcp.get_layer(&Layers::Vlan).unwrap() {
            let pnet = pkt.modify().unwrap();
            assert_eq!(pnet.get_vlan_identifier(), vlan_id);
        } else {
            panic!("Could not get vlan");
        }
    }

    {
        if let LayerMut::Ipv4(pkt) = ether_tcp.get_layer(&Layers::Ipv4).unwrap() {
            let pnet = pkt.modify().unwrap();
            assert_eq!(pnet.get_source(), ipv4_src);
        } else {
            panic!("Could not get ipv4");
        }
    }

    {
        if let LayerMut::Tcp(pkt) = ether_tcp.get_layer(&Layers::Tcp).unwrap() {
            let pnet = pkt.modify().unwrap();
            assert_eq!(pnet.get_source(), sport);
        } else {
            panic!("Could not get tcp");
        }
    }
}
