use pnet_layers::EtherMut;
use pnet_layers::LayerMutable;

#[test]
fn test_layer_build() {
    let bytes = hex::decode("2222222222221111111111118100800a080045000028487640004006dbe10101010102020202b3ec9076015297b1dda5d28c5010020009c300000000").unwrap();

    println!("{}", bytes.len());

    let ether = EtherMut::from_buf(bytes).unwrap();

    let builded = ether.build().unwrap();

    let bytes = hex::decode("2222222222221111111111118100800a080045000028487640004006dbe10101010102020202b3ec9076015297b1dda5d28c5010020009c30000").unwrap();
    assert_eq!(builded.len(), bytes.len());
}
