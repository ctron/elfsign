use crate::{
    signature::{
        digest::digest, Signature, SignatureNoteType, ELF_NOTE_SIGNATURE_V1_NAMESPACE,
        SIGNATURE_V1_SECTION,
    },
    utils::ElfType,
};
use anyhow::{anyhow, bail};
use digest::Digest;
use ecdsa::VerifyingKey;
use object::{
    elf,
    read::elf::{ElfFile, FileHeader, SectionHeader},
    Endianness,
};
use p256::NistP256;
use p384::NistP384;
use sha2::{Sha256, Sha384};
use signature::{DigestVerifier, SignatureEncoding};
use std::ffi::OsString;
use std::fs;

#[derive(Clone, Debug)]
pub struct Options {
    pub input: OsString,
}

pub(crate) async fn run(options: Options) -> anyhow::Result<()> {
    let in_data = fs::read(&options.input)?;
    let in_data = &*in_data;

    let kind = match object::FileKind::parse(in_data) {
        Ok(file) => file,
        Err(err) => {
            bail!("Failed to parse file: {}", err);
        }
    };
    match kind {
        object::FileKind::Elf32 => verify_file::<elf::FileHeader32<Endianness>>(in_data)?,
        object::FileKind::Elf64 => verify_file::<elf::FileHeader64<Endianness>>(in_data)?,
        _ => {
            bail!("Not an ELF file");
        }
    };

    Ok(())
}

fn verify_file<Elf: ElfType>(data: &[u8]) -> anyhow::Result<()> {
    let file = Elf::File::parse(data)?;
    let signatures = extract_signatures::<Elf>(&file, data)?;

    let file = ElfFile::parse(data)?;
    let signatures = verify_signatures::<Elf>(&file, signatures)?;

    if signatures.is_empty() {
        bail!("No valid signature found");
    }

    Ok(())
}

/// Filter out signatures which don't match the actual digest, or where the signature was not
/// signed by the provided certificate.
fn verify_signatures<Elf: ElfType>(
    file: &ElfFile<Elf::File>,
    signatures: Vec<Signature>,
) -> anyhow::Result<Vec<Signature>> {
    let mut result = Vec::new();

    for signature in signatures {
        match signature.r#type {
            SignatureNoteType::SignatureEcdsa256Sha256 => {
                let mut d = Sha256::new();
                digest(&mut d, file)?;
                let public_key = VerifyingKey::<NistP256>::from_sec1_bytes(&signature.public_key)?;
                if verify_signature::<_, ecdsa::Signature<_>, _>(&public_key, d, &signature)? {
                    result.push(signature);
                }
            }
            SignatureNoteType::SignatureEcdsaP384Sha384 => {
                let mut d = Sha384::new();
                digest(&mut d, file)?;
                let public_key = VerifyingKey::<NistP384>::from_sec1_bytes(&signature.public_key)?;
                if verify_signature::<_, ecdsa::Signature<_>, _>(&public_key, d, &signature)? {
                    result.push(signature);
                }
            }
        }
        // TODO: verify certificate (maybe outside here, apply policies)
    }

    Ok(result)
}

fn verify_signature<V, S, D>(verifier: &V, digest: D, signature: &Signature) -> anyhow::Result<bool>
where
    V: DigestVerifier<D, S>,
    S: SignatureEncoding,
    D: Digest,
{
    let signature = match S::try_from(&signature.signature) {
        Ok(signature) => signature,
        Err(_) => {
            log::warn!("Failed parse signature");
            return Ok(false);
        }
    };

    Ok(match verifier.verify_digest(digest, &signature) {
        Ok(()) => {
            log::info!("Valid signature found");
            true
        }
        Err(err) => {
            log::warn!("Failed to verify signature: {err}");
            false
        }
    })
}

fn extract_signatures<Elf: ElfType>(
    file: &Elf::File,
    data: &[u8],
) -> anyhow::Result<Vec<Signature>> {
    let endian = file.endian()?;

    let sections = file.sections(endian, data)?;
    let mut signatures = Vec::new();
    for section in sections.iter() {
        if sections.section_name(endian, section)? == SIGNATURE_V1_SECTION.as_bytes() {
            signatures.extend(parse_signature_section::<Elf>(file, data, section)?);
        }
    }

    Ok(signatures)
}

fn parse_signature_section<Elf: ElfType>(
    file: &Elf::File,
    data: &[u8],
    section: &<Elf::File as FileHeader>::SectionHeader,
) -> anyhow::Result<Vec<Signature>> {
    let endian = file.endian()?;
    let mut notes = section
        .notes(endian, data)?
        .ok_or_else(|| anyhow!("Signature section doesn't contain notes"))?;

    let mut result = vec![];

    while let Some(note) = notes.next()? {
        if note.name() != ELF_NOTE_SIGNATURE_V1_NAMESPACE.as_bytes() {
            log::warn!(
                "Unknown namespace: {}",
                String::from_utf8_lossy(note.name())
            );
            continue;
        }

        let r#type = match SignatureNoteType::try_from(note.n_type(endian)) {
            Ok(t) => t,
            Err(()) => {
                log::warn!("Unknown signature type: {}", note.n_type(endian));
                continue;
            }
        };

        result.push(Signature::parse(r#type, note.desc())?);
    }

    Ok(result)
}
