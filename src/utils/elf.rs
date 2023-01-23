use anyhow::bail;
use std::{fs, future::Future, path::Path, pin::Pin};

//pub type F<T, R: Future<Output = anyhow::Result<T>>> = dyn FnOnce(&[u8]) -> R;
//pub type F<T, R> = FnOnce(&[u8]) -> R;
pub type Fut<'f, T> = Pin<Box<dyn Future<Output = anyhow::Result<T>> + 'f>>;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Elf32,
    Elf64,
}

pub async fn process_elf<P, T, F>(file: P, f: F) -> anyhow::Result<T>
where
    P: AsRef<Path>,
    for<'d> F: FnOnce(Kind, &'d [u8]) -> Fut<'d, T>,
{
    let in_data = fs::read(file)?;

    let kind = match object::FileKind::parse(in_data.as_slice()) {
        Ok(file) => file,
        Err(err) => {
            bail!("Failed to parse file: {}", err);
        }
    };
    Ok(match kind {
        object::FileKind::Elf32 => f(Kind::Elf32, in_data.as_slice()).await?,
        object::FileKind::Elf64 => f(Kind::Elf64, in_data.as_slice()).await?,
        _ => {
            bail!("Not an ELF file");
        }
    })
}
