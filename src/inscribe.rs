pub const INSCRIBE_LENGTH: usize = 64;
pub type InscribeBuffer = [u8; INSCRIBE_LENGTH];

pub trait Inscribe {
    fn get_mark(&self) -> &'static str;
    fn get_inscription(&self, buf: &mut InscribeBuffer);
}

