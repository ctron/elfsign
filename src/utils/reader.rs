use std::io::{self, Cursor, Read};

/// Helper to read data from a source
pub trait Reader {
    fn read_slice_into(&mut self, buffer: &mut [u8]) -> Result<(), io::Error>;

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], io::Error> {
        let mut buffer = [0u8; N];
        self.read_slice_into(&mut buffer)?;
        Ok(buffer)
    }

    fn read_map<const N: usize, F, T>(&mut self, f: F) -> Result<T, io::Error>
    where
        F: FnOnce([u8; N]) -> T,
    {
        Ok(f(self.read_array()?))
    }

    fn read_vec(&mut self, len: usize) -> Result<Vec<u8>, io::Error> {
        let mut buffer = vec![0u8; len];
        self.read_slice_into(&mut buffer)?;
        Ok(buffer)
    }
}

/// Read data from a curser, like a buffer.
impl<T> Reader for Cursor<T>
where
    T: AsRef<[u8]>,
{
    fn read_slice_into(&mut self, buffer: &mut [u8]) -> Result<(), io::Error> {
        Read::read_exact(self, buffer)?;
        Ok(())
    }
}
