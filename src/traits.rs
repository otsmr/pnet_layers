/// A function that create a string representation of the underlining packet
pub trait PacketShow {
    /// Returns a string representation of the packet
    fn show(&self) -> String;
}
