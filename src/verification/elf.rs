use crate::{
    data::{Configuration, ExtractedSignature, Signature},
    signature::{
        digest::digest, DerSignatureEncoding, SignatureNoteType, ELF_NOTE_SIGNATURE_V1_NAMESPACE,
        SIGNATURE_V1_SECTION,
    },
    utils::ElfType,
};
use ::der::Decode;
use anyhow::{anyhow, bail};
use digest::{Digest, FixedOutput, Update};
use ecdsa::{
    der,
    elliptic_curve::{
        generic_array::ArrayLength,
        ops::Reduce,
        pkcs8::{AssociatedOid, DecodePublicKey},
        sec1::{self, FromEncodedPoint, ToEncodedPoint},
        AffinePoint, FieldSize, PointCompression, ProjectiveArithmetic, Scalar,
    },
    hazmat::VerifyPrimitive,
    PrimeCurve, SignatureSize, VerifyingKey,
};
use log::log_enabled;
use object::read::elf::{ElfFile, FileHeader, SectionHeader};
use p256::NistP256;
use p384::NistP384;
use sha2::{Sha256, Sha384};
use signature::DigestVerifier;
use std::ops::Add;

/// Filter out signatures which don't match the actual digest, or where the signature was not
/// signed by the provided certificate.
///
/// **NOTE:**: This function does not verify any certificate or enforces any other rules.
pub fn verify_signatures<Elf: ElfType>(
    file: &ElfFile<Elf::File>,
    signatures: Vec<Signature>,
) -> anyhow::Result<Vec<ExtractedSignature>> {
    let mut result = Vec::new();

    for (i, signature) in signatures.into_iter().enumerate() {
        match signature.r#type {
            Configuration::EcdsaP256Sha256 => {
                verify_ecsa_entry::<Elf, Sha256, NistP256>(i, file, signature, &mut result)?;
            }
            Configuration::EcdsaP384Sha384 => {
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
    result: &mut Vec<ExtractedSignature>,
) -> anyhow::Result<()>
where
    Elf: ElfType,
    D: Digest + Update + FixedOutput<OutputSize = FieldSize<C>> + Clone,
    C: PrimeCurve + AssociatedOid + ProjectiveArithmetic + PointCompression,

    SignatureSize<C>: ArrayLength<u8>,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C> + VerifyPrimitive<C>,
    FieldSize<C>: sec1::ModulusSize,
    Scalar<C>: Reduce<C::UInt>,

    der::MaxSize<C>: ArrayLength<u8>,
    <FieldSize<C> as Add>::Output: Add<der::MaxOverhead> + ArrayLength<u8>,
{
    let mut d = D::new();
    digest(&mut d, file)?;

    let verifier = VerifyingKey::<C>::from_public_key_der(signature.public_key.as_bytes())?;
    match verify_signature::<_, ecdsa::Signature<C>, _>(&verifier, d, signature) {
        Ok(signature) => {
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
    signature_entry: Signature,
) -> anyhow::Result<ExtractedSignature>
where
    V: DigestVerifier<D, S>,
    S: DerSignatureEncoding,
    D: Digest + Clone,
{
    // parse the signature

    let signature = match S::try_from_der(signature_entry.signature.as_bytes()) {
        Ok(signature) => signature,
        Err(_) => {
            bail!("failed to parse signature");
        }
    };

    // record digest for later

    let digest_value = digest.clone().finalize().to_vec();

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
            let (_, cert) = x509_parser::parse_x509_certificate(cert.as_bytes())?;
            if log_enabled!(log::Level::Debug) {
                log::debug!(
                    "public keys - entry: {}, certificate: {}",
                    base16::encode_lower(&signature_entry.public_key),
                    base16::encode_lower(&cert.subject_pki.subject_public_key)
                );
            }
            if signature_entry.public_key.as_bytes() != cert.subject_pki.raw {
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

    Ok(ExtractedSignature {
        signature: signature_entry,
        digest: digest_value,
    })
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

        match SignatureNoteType::try_from(note.n_type(endian)) {
            Ok(SignatureNoteType::Asn1Signature) => {
                result.push(Signature::from_der(note.desc())?);
            }
            Err(()) => {
                log::warn!("Unknown signature type: {}", note.n_type(endian));
                continue;
            }
        }
    }

    Ok(result)
}
