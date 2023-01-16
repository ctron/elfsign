use crate::{
    signature::{
        digest::digest, Signature, SignatureNoteType, ELF_NOTE_SIGNATURE_V1_NAMESPACE,
        SIGNATURE_V1_SECTION,
    },
    utils::ElfType,
};
use anyhow::{anyhow, bail};
use ecdsa::elliptic_curve::pkcs8::DecodePublicKey;
use ecdsa::VerifyingKey;
use ed25519_dalek_fiat::PublicKey;
use object::{
    elf,
    read::elf::{ElfFile, FileHeader, SectionHeader},
    Endianness,
};
use p256::NistP256;
use sha2::{Sha256, Sha512};
use signature::Verifier;
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
                let digest = digest::<Sha256, _>(file)?;
                let public_key =
                    VerifyingKey::<NistP256>::from_public_key_der(&signature.public_key)?;
                if verify_signature(&public_key, &digest, &signature) {
                    result.push(signature);
                }
            }
            SignatureNoteType::SignatureEd2551Sha512 => {
                let digest = digest::<Sha512, _>(file)?;
                let public_key = PublicKey::from_bytes(&signature.public_key)?;
                log::info!("Digest: {}", base16::encode_lower(&digest));
                log::info!(
                    "Public Key: {}",
                    base16::encode_lower(&signature.public_key)
                );
                if verify_signature(&public_key, &digest, &signature) {
                    result.push(signature);
                }
            }
        }
        // TODO: calc digest
        // TODO: verify signature
        // TODO: verify certificate (maybe outside here, apply policies)
    }

    Ok(result)
}

fn verify_signature<V, S>(verifier: &V, digest: &[u8], signature: &Signature) -> bool
where
    V: Verifier<S>,
    S: signature::Signature,
{
    let signature = match S::from_bytes(&signature.signature) {
        Ok(signature) => signature,
        Err(err) => {
            log::warn!("Failed parse signature: {err}");
            return false;
        }
    };

    match verifier.verify(digest, &signature) {
        Ok(()) => {
            log::info!("Valid signature found");
            true
        }
        Err(err) => {
            log::warn!("Failed to verify signature: {err}");
            false
        }
    }
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
