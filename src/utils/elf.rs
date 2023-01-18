use anyhow::bail;
use std::{fs, path::Path};

pub fn process_elf<P, T, F32, F64>(file: P, f32: F32, f64: F64) -> anyhow::Result<T>
where
    P: AsRef<Path>,
    F32: FnOnce(&[u8]) -> anyhow::Result<T>,
    F64: FnOnce(&[u8]) -> anyhow::Result<T>,
{
    let in_data = fs::read(file)?;
    let in_data = &*in_data;

    let kind = match object::FileKind::parse(in_data) {
        Ok(file) => file,
        Err(err) => {
            bail!("Failed to parse file: {}", err);
        }
    };
    Ok(match kind {
        object::FileKind::Elf32 => f32(in_data)?,
        object::FileKind::Elf64 => f64(in_data)?,
        _ => {
            bail!("Not an ELF file");
        }
    })
}
