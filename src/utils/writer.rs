use object::{bytes_of, Endian, Pod};

/// A value which gets encoded differently based on the endian setting.
pub trait EndianValue {
    fn encode<E: Endian>(&self, e: E) -> Vec<u8>;
}

impl EndianValue for u32 {
    fn encode<E: Endian>(&self, e: E) -> Vec<u8> {
        e.write_u32_bytes(*self).to_vec()
    }
}

/// Write data to a target
pub trait Writer: Sized {
    fn write_bytes(&mut self, b: &[u8]);

    fn write_pod<P: Pod>(&mut self, value: &P) {
        self.write_bytes(bytes_of(value));
    }

    fn write_encoded<E: Endian, V: EndianValue>(&mut self, endian: E, value: V) {
        self.write_bytes(&value.encode(endian));
    }
}

/// Implementation based on an in-memory buffer
impl Writer for Vec<u8> {
    fn write_bytes(&mut self, b: &[u8]) {
        self.extend_from_slice(b)
    }
}
