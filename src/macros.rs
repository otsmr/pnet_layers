/// create `get_layer` function
#[macro_export]
macro_rules! create_get_layer {
    ($($layer:ident),*) => {
        fn get_layer(&'a mut self, layer: &Layers) -> Option<&'a mut LayerMut> {
            match (layer, self.upper_layer.as_mut()?.as_mut()) {
                $(
                    (&Layers::$layer, LayerMut::$layer(_)) => {
                        return Some(self.upper_layer.as_mut()?.as_mut());
                    }
                )*
                _ => (),
            }
            match self.upper_layer.as_mut()?.as_mut() {
                $(
                    LayerMut::$layer(a) => a.get_layer(layer),
                )*
                _ => None,
            }
        }
    };
}

/// create `add_layer` function
#[macro_export]
macro_rules! create_add_layer {
    ($($layer:ident),*; { $($upper_layer:ident => $lower_layer:ident),* }) => {
    // ($layer:ident, $($replace_layer:ident => $with_layer:ident),*) => {


        #[allow(unused_mut)]
        fn add(&mut self, mut layer: LayerMut) -> bool {
            #[allow(unused)]
            if let Some(upper) = &mut self.upper_layer {
                $(
                    if matches!(**upper, LayerMut::$upper_layer(_)) && matches!(layer, LayerMut::$lower_layer(_)) {
                        // If upper layer is $replace_layer and the layer to add is $layer, replace it
                        layer.add(*upper.to_owned());
                        self.upper_layer.replace(Box::new(layer));
                        return true;
                    }
                )*

                return upper.add(layer);
            }

            // Check if the layer matches any of the allowed types
            if $(
                matches!(layer, LayerMut::$layer(_)) ||
            )* false {
                self.upper_layer.replace(Box::new(layer));
                true
            } else {
                false
            }
        }
    };
}

/// create `create_modify` function
#[macro_export]
macro_rules! create_modify {
    () => {
        fn modify(&'a mut self) -> Option<Self::PacketMut> {
            Self::PacketMut::new(self.buf.as_mut())
        }
    };
}

/// create `create_set_payload` function
#[macro_export]
macro_rules! create_set_payload {
    () => {
        fn set_payload(&'a mut self, payload: &[u8]) {
            let header_size = Self::PacketMut::minimum_packet_size();
            let len = self.buf.len() - header_size;
            if payload.len() > len {
                let increase = payload.len() - len;
                println!("increased packet by: {increase}");
                self.buf.resize((self.buf.len() + increase), 0);
            } else {
                let increase = len - payload.len();
                println!("decreased packet by: {increase}");
                self.buf.resize((self.buf.len() - increase), 0);
            }
            for i in header_size..self.buf.len() {
                self.buf[i] = payload[i - header_size];
            }
        }
    };
}

/// creates all default immutable functions
#[macro_export]
macro_rules! create_default_immutable {
    () => {
        fn new(buf: &'a [u8]) -> Self {
            Self { buf }
        }

        fn get_buf(&self) -> &[u8] {
            &self.buf
        }

        fn as_mut(&self) -> Option<Self::LayerMutType> {
            Self::LayerMutType::from_buf(self.buf.to_vec())
        }

        fn as_pnet(&self) -> Option<Self::Packet> {
            Self::Packet::new(self.buf)
        }

        fn as_mut_pnet(&self) -> Option<Self::PacketMut> {
            Self::PacketMut::owned(self.buf.to_vec())
        }

        fn get_layer(&'_ self, layer: Layers) -> Option<Layer<'_>> {
            Self::get_layer_from_buf(self.buf, layer)
        }
    };
}

#[macro_export]
/// creates `from_buf` function
macro_rules! create_from_buf {
    ($pnet_packet:ident, $get_next_level_protocol:ident, $next_level_proto:ident, $($proto:ident => $mut_proto:ident),*) => {
        fn from_buf(mut buf: Vec<u8>) -> Option<Self> {
            let mut pkt = $pnet_packet::new(&buf)?;

            let header_len = $pnet_packet::minimum_packet_size();


            let mut payload = pkt.payload();
            let ethernet_padding = buf.len() - header_len - payload.len();

            if ethernet_padding > 0 {
                buf.resize(buf.len() - ethernet_padding, 0);
                pkt = $pnet_packet::new(&buf)?;
                payload = pkt.payload();
            }

            let upper_layer = match pkt.$get_next_level_protocol() {
                $(
                    $next_level_proto::$proto => {
                        log::debug!("Next level is {}", pkt.$get_next_level_protocol());
                        Some(Box::new(LayerMut::$proto($mut_proto::from_buf(payload.to_vec())?)))
                    }
                )*
                _ => {
                    log::debug!("Next level not supported {}", pkt.$get_next_level_protocol());
                    None
                }
            };

            buf.resize(buf.len() - payload.len(), 0);

            Some(Self { buf, upper_layer })
        }
    };
}

#[macro_export]
/// creates `switch_src_dst` function
macro_rules! create_switch_layer {
    () => {
        fn switch_src_dst(&mut self) {
            if let Some(mut pkt) = self.modify() {
                let src = pkt.get_source();
                pkt.set_source(pkt.get_destination());
                pkt.set_destination(src);
            }
            if let Some(upper_layer) = self.upper_layer.as_mut() {
                upper_layer.switch_src_dst();
            }
        }
    };
}

#[macro_export]
/// Implements basics for the different layers
macro_rules! layers {
    ($($proto:ident => $mut_proto:ident),*) => {


        #[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
        /// Supported layer types to make them identifiable
        pub enum Layers {
            $(
                /// Layer type for the $proto layer, indicating its presence.
                $proto,
            )*
        }
        /// Immutable layer based representation of a network package
        /// This can be used for zero-copy inspection of received packets
        #[derive(Debug)]
        pub enum Layer<'a> {
            $(
                ///  $proto layer representation, containing $proto-specific data.
                $proto($proto<'a>),
            )*
        }

        #[derive(Debug, Clone)]
        /// Mutable layer based representation of a network package.
        /// This can be used for manipulating a packet or adding more layers
        pub enum LayerMut {
            $(
                /// Layer type for the $variant layer, indicating its presence.
                $proto($mut_proto),
            )*
        }


        impl LayerMut {
            pub(crate) fn add(&mut self, layer: LayerMut) -> bool {
                match self {
                    $(Self::$proto(a) => a.add(layer)),*
                }
            }
            fn switch_src_dst(&mut self) {
                match self {
                    $(Self::$proto(a) => a.switch_src_dst()),*
                }
            }
        }

        impl Display for LayerMut {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(Self::$proto(a) => write!(f, "{}", a)?),*
                }
                Ok(())
            }
        }

    };
}

#[macro_export]
/// Shortcut for getting a layer
/// `if let Some(vlan) = get_layer!(Vlan, ether) {}`
macro_rules! get_layer {
    ($layer_type:ident, $var:ident) => {
        if let Some(LayerMut::$layer_type(pkt)) = $var.get_layer(&Layers::$layer_type) {
            Some(pkt)
        } else {
            None
        }
    };
}
