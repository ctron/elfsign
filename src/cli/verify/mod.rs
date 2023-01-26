use crate::{
    data::{self, ExtractedSignature, RekorBundle},
    utils::{
        elf::{process_elf, Kind},
        ElfType,
    },
    verification::{
        elf::{extract_signatures, verify_signatures},
        enforce::{
            CertificateBundle, CertificateChainEnforcer, CertificateEnforcer, StandardEnforcer,
        },
        seedwing::SeedwingEnforcer,
        validator::EnforceCertificateChain,
    },
};
use anyhow::{anyhow, bail, Context};
use ecdsa::VerifyingKey;
use object::{elf, read::elf::ElfFile, Endianness};
use p256::NistP256;
use serde_json::Value;
use sigstore::rekor::{
    self,
    apis::configuration::Configuration,
    models::{hashedrekord::Hash, Hashedrekord},
};
use std::{ffi::OsString, ops::Deref};
use x509_parser::{
    der_parser::{oid, Oid},
    parse_x509_certificate,
    prelude::ParsedExtension,
    time::ASN1Time,
};

const OID_SAN: Oid = oid!(2.5.29 .17);

#[derive(Clone, Debug)]
pub struct Options {
    pub input: OsString,
}

#[derive(Debug)]
struct ValidationResult<'a> {
    signature: &'a ExtractedSignature,
    certificate_bundle: &'a CertificateBundle<'a>,
    result: anyhow::Result<()>,
}

pub(crate) async fn run(options: Options) -> anyhow::Result<()> {
    // retrieve signatures from the elf file, and ensure the file signature matches the
    // embedded public key and the evaluated digest.
    let signatures = process_elf(options.input, |kind, file| {
        Box::pin(async move {
            match kind {
                Kind::Elf32 => signatures_from_file::<elf::FileHeader32<Endianness>>(file),
                Kind::Elf64 => signatures_from_file::<elf::FileHeader64<Endianness>>(file),
            }
        })
    })
    .await?;

    // These signatures are ok, the digest of the file was signed with the public key. But,
    // we still don't know anything about the certificates beyond the fact that the public key
    // of the first certificate matches the public key of the signature.
    log::info!("Valid signatures: {signatures:#?}");

    // parse into X509Certificates
    let signatures = parse_x509(&signatures)?;

    // next, we set up some enforcers, which will validate certificates from the certificate bundles
    // individually.

    let enforcers: &[&dyn CertificateEnforcer] = &[
        // enforce some basic properties:
        // * the leaf must be valid for code signing
        // * the root must be a CA certificate
        // * a self-signed certificate (not standard root) must enforce both leaf & root rules
        &StandardEnforcer,
    ];

    let chain_enforcers: &[&dyn CertificateChainEnforcer] = &[
        &EnforceCertificateChain(&enforcers),
        &SeedwingEnforcer::new().await?,
    ];

    // verify certificates, the certificates are ensured to:
    // * form a chain (subject signed by issuer)
    // * plus all checks from the provided enforcers
    let mut certificates = verify_certificates(&signatures, &chain_enforcers).await;

    // verify rekor
    verify_rekors(&mut certificates).await;

    // dump
    log::trace!("Validation result: {certificates:#?}");
    if log::log_enabled!(log::Level::Info) {
        for ValidationResult {
            signature,
            certificate_bundle,
            result,
        } in &certificates
        {
            match result {
                Ok(()) => {
                    log::info!(
                        "Signature - OK, signature: {} - public key: {}",
                        base16::encode_lower(&signature.signature.signature),
                        base16::encode_lower(&signature.public_key)
                    );
                    log::info!("Certificates (#{}):", certificate_bundle.len());
                    for (i, cert) in certificate_bundle.iter().enumerate() {
                        log::info!("  {i: >3}: Subject: {}", cert.subject);
                        log::info!("       Issuer: {}", cert.issuer);
                        log::info!("       Serial: {}", cert.raw_serial_as_string());
                        if let Ok(Some(ParsedExtension::SubjectAlternativeName(san))) = cert
                            .get_extension_unique(&OID_SAN)
                            .map(|v| v.map(|v| v.parsed_extension()))
                        {
                            log::info!("       SAN:");
                            for s in &san.general_names {
                                log::info!("          {}", s);
                            }
                        }
                    }
                }
                Err(err) => {
                    log::info!(
                        "Signature - failed({}), digest: {} - public key: {}",
                        err,
                        base16::encode_lower(&signature.signature.signature),
                        base16::encode_lower(&signature.public_key)
                    );
                }
            }
        }
    }

    // check if there are some remaining
    let has_some = certificates
        .into_iter()
        .filter_map(|r| r.result.ok())
        .next()
        .is_some();

    // FIXME: think about a check where all stored signatures must be valid

    if !has_some {
        bail!("No valid signatures found");
    }

    Ok(())
}

/// verify the rekor section for each signature entry
async fn verify_rekors(input: &mut [ValidationResult<'_>]) {
    for ValidationResult {
        signature, result, ..
    } in input
    {
        if result.is_err() {
            continue;
        }
        if let Some(rekor) = &signature.rekor {
            *result = verify_rekor(signature, rekor).await;
        } else {
            *result = Err(anyhow!("missing rekor information"));
            // TODO: find another way to validate without Rekor (maybe RFC 3161?)
        }
    }
}

/// Verify the rekor bundle used in the signature
///
/// This will:
///
/// * look up the rekor log entry
/// * lookup the public key of the rekor instance
/// * verify that the log entry is valid (see [`crate::verification::rekor::verify_entry`])
/// * ensure that the certificate of the log entry matches the certificate of the signature
/// * ensure that the certificate of the signature was valid at the time of the log entry
///
/// This ensures:
///
/// * that the signature was signed at a time the certificate was valid
///
async fn verify_rekor(signature: &ExtractedSignature, rekor: &RekorBundle) -> anyhow::Result<()> {
    let cfg = Configuration::new();

    // TODO: allow using an offline bundle
    let log_id = &rekor.entry_id;
    let log = rekor::apis::entries_api::get_log_entry_by_uuid(&cfg, log_id)
        .await
        .context("fetch rekor log entry")?;
    if &log.uuid != log_id {
        bail!("ID of retrieved log entry does not match ID of requested log entry");
    }

    // fetch public key

    // TODO: allow other means of providing the key
    let public_key = rekor::apis::pubkey_api::get_public_key(&cfg, None).await?;
    log::info!("Public key (PEM):\n{public_key}");
    // TODO: probe the key type and then parse the correct type
    let public_key: VerifyingKey<NistP256> = public_key.parse()?;
    log::info!("Public key: {public_key:?}");

    // validate entry

    let verified =
        crate::verification::rekor::verify_entry::<_, ecdsa::Signature<_>>(&log, &public_key)?;

    // decode record data

    let body: Hashedrekord = serde_json::from_slice(&verified.body)?;
    log::info!("Body: {body:?}");

    // validate certificate (binary == log entry)

    let certificate_from_log = pem::parse(body.spec.signature.public_key.decode()?)?.contents;
    let certificate_from_binary = signature
        .certificate_bundle
        .first()
        .ok_or_else(|| anyhow!("missing leaf certificate"))?;

    if certificate_from_log != certificate_from_binary.as_bytes() {
        bail!(
            "certificate mismatch: certificate of binary does not match certificate of log entry"
        );
    }

    // parse the certificate

    let certificate_from_binary = parse_x509_certificate(certificate_from_binary.as_bytes())?.1;

    // ensure that the certificate was valid at the point when the log entry was created

    if !certificate_from_binary
        .validity
        .is_valid_at(ASN1Time::new(verified.timestamp))
    {
        bail!("signing certificate was not valid when the log entry was created");
    }

    /*
     * => from now on we know that the certificate found in the signature was presented to Rekor
     * at the time of the log entry. But we still don't have a correlation between the log entry
     * and the ELF file
     */

    // evaluate digest

    let (hash_algorithm, hash_value) = extract_hash(&body.spec.data.hash)?;
    log::debug!("Hash: {hash_algorithm} / {hash_value:?}");
    match (signature.r#type, hash_algorithm.deref()) {
        (data::Configuration::EcdsaP256Sha256, "sha256") => {}
        _ => {
            bail!(
                r#"Unsupported hash configuration - actual: {}, supported: ["sha256s"]"#,
                signature.r#type
            );
        }
    }

    if signature.digest != hash_value {
        bail!(
            "Digest mismatch - signature: {}, logEntry: {}",
            base16::encode_lower(&signature.digest),
            base16::encode_lower(&hash_value)
        );
    }

    // done

    Ok(())
}

/// Extract the algorithm and hash value from the "hash" section.
///
/// TODO: remove this once a new version of sigstore-rs is releases, which makes those fields
/// public.
fn extract_hash(hash: &Hash) -> anyhow::Result<(String, Vec<u8>)> {
    let json = serde_json::to_value(hash)?;
    match (
        json.get("algorithm").and_then(Value::as_str),
        json.get("value")
            .and_then(Value::as_str)
            .map(base16::decode),
    ) {
        (Some(algorithm), Some(Ok(value))) => Ok((algorithm.to_string(), value)),
        _ => {
            bail!("Unable to decode 'Hash' structure")
        }
    }
}

/// parse all signatures into an array of signature plus certificate bundle
fn parse_x509(
    signatures: &[ExtractedSignature],
) -> anyhow::Result<Vec<(&ExtractedSignature, CertificateBundle)>> {
    let mut result = Vec::with_capacity(signatures.len());
    for signature in signatures {
        result.push((
            signature,
            CertificateBundle::try_from(signature.certificate_bundle.as_slice())?,
        ));
    }

    Ok(result)
}

/// extract signatures from an elf binary
fn signatures_from_file<Elf: ElfType>(data: &[u8]) -> anyhow::Result<Vec<ExtractedSignature>> {
    let file = ElfFile::parse(data)?;
    let signatures = extract_signatures::<Elf>(file.raw_header(), data)?;

    log::info!("Signatures found: {signatures:#?}");
    // we have signatures now, but no idea if they are "good"

    verify_signatures::<Elf>(&file, signatures)
}

async fn verify_certificates<'c, E>(
    signatures: &'c [(&'c ExtractedSignature, CertificateBundle<'c>)],
    enforcer: &E,
) -> Vec<ValidationResult<'c>>
where
    E: CertificateChainEnforcer,
{
    let mut results = Vec::with_capacity(signatures.len());

    for (signature, certificate_bundle) in signatures {
        let result = match enforcer.enforce(certificate_bundle).await {
            Ok(()) => Ok(()),
            Err(err) => Err(anyhow!(err)),
        };
        results.push(ValidationResult {
            signature,
            certificate_bundle,
            result,
        });
    }

    results
}
