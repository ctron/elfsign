//! Data structures

use crate::signature::{SignatureNoteType, ELF_NOTE_SIGNATURE_V1_NAMESPACE};
use crate::utils::notes::{Note, NoteWriter};
use crate::utils::ElfType;
use base64::display::Base64Display;
use der::{asn1::OctetString, Encode, Sequence};
use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};

mod config;
mod rekor;

pub use config::*;
pub use rekor::*;

/// A signature, stored as a note section entry
///
/// ## Encoding
///
/// ```
/// Signature :: = SEQUENCE {
///   type ENUMERATED { /* see Configuration enum */ }
///   publicKey OCTET STRING
///   signature OCTET STRING
///   certificateBundle SEQUENCE OF BIT STRING
/// }
/// ```
///
/// TODO: I think we could do better. Use CHOICE, instead of ENUMERATED, and use the actual ASN.1 types for the fields.
///
#[derive(Clone, PartialEq, Eq, Sequence)]
pub struct Signature {
    pub r#type: Configuration,
    /// DER/ASN.1 encoded public key
    pub public_key: OctetString,
    /// DER/ASN.1 encoded signature
    pub signature: OctetString,

    /// DER encoded certificate bundle, root last.
    // FIXME: this contains duplicate information, like the algorithms, or the public key. Is that a problem?
    pub certificate_bundle: Vec<OctetString>,

    /// A rekor bundle, can be used to verify through rekor
    pub rekor: Option<RekorBundle>,
}

pub struct DebugCertificateBundle<'d>(pub &'d [&'d [u8]]);

impl<'d> Debug for DebugCertificateBundle<'d> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_list();
        for c in self.0 {
            d.entry(&DebugCertificate(c));
        }
        d.finish()
    }
}

pub struct DebugCertificate<'d>(pub &'d [u8]);

impl<'d> Debug for DebugCertificate<'d> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Base64Display::new(self.0, &base64::engine::general_purpose::STANDARD).fmt(f)
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signature")
            .field("type", &self.r#type)
            .field("public_key", &base16::encode_lower(&self.public_key))
            .field("signature", &base16::encode_lower(&self.signature))
            .field(
                "certificate_bundle",
                &DebugCertificateBundle(
                    &self
                        .certificate_bundle
                        .iter()
                        .map(|s| s.as_bytes())
                        .collect::<Vec<_>>()
                        .as_slice(),
                ),
            )
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct Signatures {
    pub signatures: Vec<Signature>,
}

impl Signatures {
    /// render the signature data section as a notes section.
    pub fn render_as_notes<E: ElfType>(&self, endian: E::Endian) -> anyhow::Result<Vec<u8>> {
        let mut result = Vec::new();
        let mut writer = NoteWriter::<_, E>::new(&mut result, endian);

        let mut notes = Vec::with_capacity(self.signatures.len());

        for signature in &self.signatures {
            notes.push(Note {
                namespace: ELF_NOTE_SIGNATURE_V1_NAMESPACE,
                descriptor: Cow::Owned(signature.to_vec()?),
                r#type: SignatureNoteType::Asn1Signature,
            });
        }

        writer.write_notes(&notes);

        Ok(result)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use der::{Decode, Encode};

    fn setup() {
        env_logger::init();
    }

    #[test]
    fn test_encode() {
        setup();

        let sig = Signature {
            r#type: Default::default(),
            public_key: OctetString::new(vec![1, 2, 3]).unwrap(),
            signature: OctetString::new(vec![4, 5, 6]).unwrap(),
            certificate_bundle: vec![
                OctetString::new(vec![1, 1, 1]).unwrap(),
                OctetString::new(vec![2, 2, 2]).unwrap(),
            ],
            rekor: Some(RekorBundle {
                entry_id: "123".to_string(),
            }),
        };
        let encoded = sig.to_vec().unwrap();
        log::info!("Encoded: {}", Base64Display::new(&encoded, &STANDARD));
        let decoded = Signature::from_der(&encoded).unwrap();
        assert_eq!(sig, decoded);
    }
}
