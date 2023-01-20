use crate::verification::enforce::{CertificateBundle, CertificateChainEnforcer};
use crate::verification::seedwing::SeedwingEnforcer;
use crate::verification::validator::EnforceCertificateChain;
use crate::{
    signature::Signature,
    utils::{elf::process_elf, ElfType},
    verification::{
        elf::{extract_signatures, verify_signatures},
        enforce::{CertificateEnforcer, StandardEnforcer},
    },
};
use anyhow::{anyhow, bail};
use object::{elf, read::elf::ElfFile, Endianness};
use std::ffi::OsString;
use x509_parser::der_parser::{oid, Oid};
use x509_parser::prelude::ParsedExtension;

const OID_SAN: Oid = oid!(2.5.29 .17);

#[derive(Clone, Debug)]
pub struct Options {
    pub input: OsString,
}

pub(crate) async fn run(options: Options) -> anyhow::Result<()> {
    // retrieve signatures from the elf file, and ensure the file signature matches the
    // embedded public key and the evaluated digest.
    let signatures = process_elf(
        options.input,
        signatures_from_file::<elf::FileHeader32<Endianness>>,
        signatures_from_file::<elf::FileHeader64<Endianness>>,
    )?;

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
    let certificates = verify_certificates(&signatures, &chain_enforcers).await;
    log::debug!("Validation result: {certificates:#?}");
    if log::log_enabled!(log::Level::Info) {
        for (signature, result) in &certificates {
            match result {
                Ok(bundle) => {
                    log::info!(
                        "Signature - OK, digest: {} - public key: {}",
                        base16::encode_lower(&signature.signature),
                        base16::encode_lower(&signature.public_key)
                    );
                    log::info!("Certificates (#{}):", bundle.len());
                    for (i, cert) in bundle.iter().enumerate() {
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
                        base16::encode_lower(&signature.signature),
                        base16::encode_lower(&signature.public_key)
                    );
                }
            }
        }
    }

    // check if there are some remaining
    let has_some = certificates
        .into_iter()
        .filter_map(|r| r.1.ok())
        .next()
        .is_some();

    // FIXME: think about a check where all stores signatures must be valid

    if !has_some {
        bail!("No valid signatures found");
    }

    Ok(())
}

/// parse all signatures into an array of signature plus certificate bundle
fn parse_x509(signatures: &[Signature]) -> anyhow::Result<Vec<(&Signature, CertificateBundle)>> {
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
fn signatures_from_file<'c, Elf: ElfType>(data: &[u8]) -> anyhow::Result<Vec<Signature>> {
    let file = ElfFile::parse(data)?;
    let signatures = extract_signatures::<Elf>(file.raw_header(), data)?;

    log::info!("Signatures found: {signatures:#?}");
    // we have signatures now, but no idea if they are "good"

    verify_signatures::<Elf>(&file, signatures)
}

async fn verify_certificates<'c, E>(
    signatures: &'c [(&'c Signature, CertificateBundle<'c>)],
    enforcer: &E,
) -> Vec<(&'c Signature, anyhow::Result<&'c CertificateBundle<'c>>)>
where
    E: CertificateChainEnforcer,
{
    let mut results = Vec::with_capacity(signatures.len());

    for (signature, bundle) in signatures.into_iter() {
        let result = match enforcer.enforce(bundle).await {
            Ok(()) => Ok(bundle),
            Err(err) => Err(anyhow!(err)),
        };
        results.push((*signature, result));
    }

    results
}
