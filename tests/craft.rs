use pnet_layers::{LayerMut, LayerMutable};

#[test]
fn test_craft() {
    let crafted = LayerMut::parse("Vlan(id: 10)").unwrap();
    assert!(matches!(crafted, LayerMut::Vlan(_)));
    if let LayerMut::Vlan(mut vlan) = crafted
        && let Some(vlan) = vlan.modify()
    {
        assert_eq!(vlan.get_vlan_identifier(), 10);
    }
}
