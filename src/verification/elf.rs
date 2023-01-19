use crate::{
    signature::{
        digest::digest, Signature, SignatureNoteType, ELF_NOTE_SIGNATURE_V1_NAMESPACE,
        SIGNATURE_V1_SECTION,
    },
    utils::ElfType,
};
use anyhow::{anyhow, bail};
use digest::{Digest, FixedOutput, Update};
use ecdsa::{
    elliptic_curve::{
        generic_array::ArrayLength,
        ops::Reduce,
        sec1::{self, FromEncodedPoint, ToEncodedPoint},
        AffinePoint, FieldSize, ProjectiveArithmetic, Scalar,
    },
    hazmat::VerifyPrimitive,
    PrimeCurve, SignatureSize, VerifyingKey,
};
use log::log_enabled;
use object::read::elf::{ElfFile, FileHeader, SectionHeader};
use p256::NistP256;
use p384::NistP384;
use sha2::{Sha256, Sha384};
use signature::{DigestVerifier, SignatureEncoding};
use std::ops::Deref;

/// Filter out signatures which don't match the actual digest, or where the signature was not
/// signed by the provided certificate.
///
/// **NOTE:**: This function does not verify any certificate or enforces any other rules.
pub fn verify_signatures<'c, Elf: ElfType>(
    file: &ElfFile<Elf::File>,
    signatures: Vec<Signature>,
) -> anyhow::Result<Vec<Signature>> {
    let mut result = Vec::new();

    for (i, signature) in signatures.into_iter().enumerate() {
        match signature.r#type {
            SignatureNoteType::SignatureEcdsaP256Sha256 => {
                verify_ecsa_entry::<Elf, Sha256, NistP256>(i, file, signature, &mut result)?;
            }
            SignatureNoteType::SignatureEcdsaP384Sha384 => {
                verify_ecsa_entry::<Elf, Sha384, NistP384>(i, file, signature, &mut result)?;
            }
        }
    }

    Ok(result)
}

fn verify_ecsa_entry<Elf, D, C>(
    i: usize,
    file: &ElfFile<Elf::File>,
    signature: Signature,
    result: &mut Vec<Signature>,
) -> anyhow::Result<()>
where
    Elf: ElfType,
    D: Digest + Update + FixedOutput<OutputSize = FieldSize<C>>,
    C: PrimeCurve + ProjectiveArithmetic,

    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldSize<C>: sec1::ModulusSize,
    Scalar<C>: Reduce<C::UInt>,
{
    let mut d = D::new();
    digest(&mut d, file)?;

    let verifier = VerifyingKey::<C>::from_sec1_bytes(&signature.public_key)?;
    match verify_signature::<_, ecdsa::Signature<C>, _>(&verifier, d, &signature) {
        Ok(()) => {
            result.push(signature);
        }
        Err(err) => {
            log::warn!("Failed to validate signature #{i}: {err}")
        }
    }

    Ok(())
}

/// Verify a signature entry.
///
/// This will ensure that:
/// * The signature could be parsed
/// * The signature validates against the embedded public key plus the evaluated file digest
/// * The embedded public key matches the public key of the first certificate in the bundle list
fn verify_signature<V, S, D>(
    verifier: &V,
    digest: D,
    signature_entry: &Signature,
) -> anyhow::Result<()>
where
    V: DigestVerifier<D, S>,
    S: SignatureEncoding,
    D: Digest,
{
    // parse the signature

    let signature = match S::try_from(&signature_entry.signature) {
        Ok(signature) => signature,
        Err(_) => {
            bail!("failed to parse signature");
        }
    };

    // verify by digest

    match verifier.verify_digest(digest, &signature) {
        Ok(()) => {
            log::info!("Valid signature found");
            // continue
        }
        Err(err) => {
            bail!("failed to verify signature: {err}");
        }
    }

    // ensure that the public key is equal to the public key from the certificate

    match signature_entry.certificate_bundle.first() {
        Some(cert) => {
            let (_, cert) = x509_parser::parse_x509_certificate(cert)?;
            if log_enabled!(log::Level::Debug) {
                log::debug!(
                    "public keys - entry: {}, certificate: {}",
                    base16::encode_lower(&signature_entry.public_key),
                    base16::encode_lower(&cert.subject_pki.subject_public_key)
                );
            }
            if signature_entry.public_key.deref() != cert.subject_pki.subject_public_key.as_ref() {
                bail!(
                    "public key mismatch - entry: {}, certificate: {}",
                    base16::encode_lower(&signature_entry.public_key),
                    base16::encode_lower(&cert.subject_pki.subject_public_key)
                );
            }
        }
        None => {
            bail!("No certificate");
        }
    }

    // done

    Ok(())
}

/// Extract signatures stored in an elf binary.
pub fn extract_signatures<Elf: ElfType>(
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

        result.push(Signature::parse(endian, r#type, note.desc())?);
    }

    Ok(result)
}
