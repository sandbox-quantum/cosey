#![no_std]
//! # cosey
//!
//! Data types and serde for public COSE_Keys
//!
//! https://tools.ietf.org/html/rfc8152#section-7
//!
//! A COSE Key structure is built on a CBOR map object.  The set of
//! common parameters that can appear in a COSE Key can be found in the
//! IANA "COSE Key Common Parameters" registry (Section 16.5).
//!
//! https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
//!
//! Additional parameters defined for specific key types can be found in
//! the IANA "COSE Key Type Parameters" registry (Section 16.6).
//!
//! https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
//!
//!
//! Key Type 1 (OKP)
//! -1: crv
//! -2: x (x-coordinate)
//! -4: d (private key)
//!
//! Key Type 2 (EC2)
//! -1: crv
//! -2: x (x-coordinate)
//! -3: y (y-coordinate)
//! -4: d (private key)
//!
//! Key Type 4 (Symmetric)
//! -1: k (key value)
//!
//! Key Type 6 (PQC)
//! -1: pk (public key value)

/*
   COSE_Key = {
       1 => tstr / int,          ; kty
       ? 2 => bstr,              ; kid
       ? 3 => tstr / int,        ; alg
       ? 4 => [+ (tstr / int) ], ; key_ops
       ? 5 => bstr,              ; Base IV
       * label => values
   }
*/

use core::fmt::{self, Formatter};
pub use heapless_bytes::Bytes;
#[cfg(feature = "backend-dilithium")]
use pqcrypto_dilithium::ffi;
use serde::{
    de::{Error as _, Expected, MapAccess, Unexpected},
    Deserialize, Serialize,
};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[repr(i8)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize_repr, Deserialize_repr)]
enum Label {
    Kty = 1,
    Alg = 3,
    CrvOrPk = -1,
    X = -2,
    Y = -3,
}

struct TryFromIntError;

impl TryFrom<i8> for Label {
    type Error = TryFromIntError;

    fn try_from(label: i8) -> Result<Self, Self::Error> {
        Ok(match label {
            1 => Self::Kty,
            3 => Self::Alg,
            -1 => Self::CrvOrPk,
            -2 => Self::X,
            -3 => Self::Y,
            _ => {
                return Err(TryFromIntError);
            }
        })
    }
}

#[repr(i8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize_repr, Deserialize_repr)]
enum Kty {
    Okp = 1,
    Ec2 = 2,
    Symmetric = 4,
    #[cfg(feature = "backend-dilithium")]
    Pqc = 7,
}

impl Expected for Kty {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", *self as i8)
    }
}

#[repr(i8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize_repr, Deserialize_repr)]
enum Alg {
    Es256 = -7, // ECDSA with SHA-256
    EdDsa = -8,
    Totp = -9, // Unassigned, we use it for TOTP

    #[cfg(feature = "backend-dilithium2")]
    Dilithium2 = -87,
    #[cfg(feature = "backend-dilithium3")]
    Dilithium3 = -88,
    #[cfg(feature = "backend-dilithium5")]
    Dilithium5 = -89,

    // MAC
    // Hs256 = 5,
    // Hs512 = 7,

    // AEAD
    // A128Gcm = 1,
    // A256Gcm = 3,
    // lots of AES-CCM, why??
    // ChaCha20Poly1305 = 24,

    // Key Agreement
    EcdhEsHkdf256 = -25, // ES = ephemeral-static
}

impl Expected for Alg {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", *self as i8)
    }
}

#[repr(i8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize_repr, Deserialize_repr)]
enum Crv {
    None = 0,
    P256 = 1,
    // P384 = 2,
    // P512 = 3,
    X25519 = 4,
    // X448 = 5,
    Ed25519 = 6,
    // Ed448 = 7,
}

impl Expected for Crv {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", *self as i8)
    }
}

// `Deserialize` can't be derived on untagged enum,
// would need to "sniff" for correct (Kty, Alg, Crv) triple
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum PublicKey {
    P256Key(P256PublicKey),
    EcdhEsHkdf256Key(EcdhEsHkdf256PublicKey),
    Ed25519Key(Ed25519PublicKey),
    TotpKey(TotpPublicKey),
    #[cfg(feature = "backend-dilithium2")]
    Dilithium2(Dilithium2PublicKey),
    #[cfg(feature = "backend-dilithium3")]
    Dilithium3(Dilithium3PublicKey),
    #[cfg(feature = "backend-dilithium5")]
    Dilithium5(Dilithium5PublicKey),
}

impl From<P256PublicKey> for PublicKey {
    fn from(key: P256PublicKey) -> Self {
        PublicKey::P256Key(key)
    }
}

impl From<EcdhEsHkdf256PublicKey> for PublicKey {
    fn from(key: EcdhEsHkdf256PublicKey) -> Self {
        PublicKey::EcdhEsHkdf256Key(key)
    }
}

impl From<Ed25519PublicKey> for PublicKey {
    fn from(key: Ed25519PublicKey) -> Self {
        PublicKey::Ed25519Key(key)
    }
}

impl From<TotpPublicKey> for PublicKey {
    fn from(key: TotpPublicKey) -> Self {
        PublicKey::TotpKey(key)
    }
}

#[cfg(feature = "backend-dilithium2")]
impl From<Dilithium2PublicKey> for PublicKey {
    fn from(key: Dilithium2PublicKey) -> Self {
        PublicKey::Dilithium2(key)
    }
}

#[cfg(feature = "backend-dilithium3")]
impl From<Dilithium3PublicKey> for PublicKey {
    fn from(key: Dilithium3PublicKey) -> Self {
        PublicKey::Dilithium3(key)
    }
}
#[cfg(feature = "backend-dilithium5")]
impl From<Dilithium5PublicKey> for PublicKey {
    fn from(key: Dilithium5PublicKey) -> Self {
        PublicKey::Dilithium5(key)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum CrvOrPk {
    Ec(Crv),
    #[cfg(feature = "backend-dilithium2")]
    Dilithium2(Bytes<{ ffi::PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES }>),
    #[cfg(feature = "backend-dilithium3")]
    Dilithium3(Bytes<{ ffi::PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES }>),
    #[cfg(feature = "backend-dilithium5")]
    Dilithium5(Bytes<{ ffi::PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES }>)
}

#[derive(Clone, Debug, Default)]
struct RawPublicKey {
    kty: Option<Kty>,
    alg: Option<Alg>,
    crv_or_pk: Option<CrvOrPk>,
    x: Option<Bytes<32>>,
    y: Option<Bytes<32>>,
}

impl<'de> Deserialize<'de> for RawPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct IndexedVisitor;
        impl<'de> serde::de::Visitor<'de> for IndexedVisitor {
            type Value = RawPublicKey;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("RawPublicKey")
            }

            fn visit_map<V>(self, mut map: V) -> Result<RawPublicKey, V::Error>
            where
                V: MapAccess<'de>,
            {
                #[derive(PartialEq)]
                enum Key {
                    Label(Label),
                    Unknown(i8),
                    None,
                }

                fn next_key<'a, V: MapAccess<'a>>(map: &mut V) -> Result<Key, V::Error> {
                    let key: Option<i8> = map.next_key()?;
                    let key = match key {
                        Some(key) => match Label::try_from(key) {
                            Ok(label) => Key::Label(label),
                            Err(_) => Key::Unknown(key),
                        },
                        None => Key::None,
                    };
                    Ok(key)
                }

                let mut public_key = RawPublicKey::default();

                // As we cannot deserialize arbitrary values with cbor-smol, we do not support
                // unknown keys before a known key.  If there are unknown keys, they must be at the
                // end.

                // only deserialize in canonical order

                let mut key = next_key(&mut map)?;

                if key == Key::Label(Label::Kty) {
                    public_key.kty = Some(map.next_value()?);
                    key = next_key(&mut map)?;
                }

                if key == Key::Label(Label::Alg) {
                    public_key.alg = Some(map.next_value()?);
                    key = next_key(&mut map)?;
                }

                if key == Key::Label(Label::CrvOrPk) {
                    public_key.crv_or_pk = Some(map.next_value()?);
                    key = next_key(&mut map)?;
                }

                if key == Key::Label(Label::X) {
                    public_key.x = Some(map.next_value()?);
                    key = next_key(&mut map)?;
                }

                if key == Key::Label(Label::Y) {
                    public_key.y = Some(map.next_value()?);
                    key = next_key(&mut map)?;
                }

                // if there is another key, it should be an unknown one
                if matches!(key, Key::Label(_)) {
                    Err(serde::de::Error::custom(
                        "public key data in wrong order or with duplicates",
                    ))
                } else {
                    Ok(public_key)
                }
            }
        }
        deserializer.deserialize_map(IndexedVisitor {})
    }
}

impl Serialize for RawPublicKey {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_set = [
            self.kty.is_some(),
            self.alg.is_some(),
            self.crv_or_pk.is_some(),
            self.x.is_some(),
            self.y.is_some(),
        ];
        let fields = is_set.into_iter().map(usize::from).sum();
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(fields))?;

        //  1: kty
        if let Some(kty) = &self.kty {
            map.serialize_entry(&(Label::Kty as i8), &(*kty as i8))?;
        }
        //  3: alg
        if let Some(alg) = &self.alg {
            map.serialize_entry(&(Label::Alg as i8), &(*alg as i8))?;
        }
        // -1: crv or public key
        if let Some(crv_or_pk) = &self.crv_or_pk {
            match crv_or_pk {
                CrvOrPk::Ec(crv) => map.serialize_entry(&(Label::CrvOrPk as i8), &(*crv as i8))?,
                #[cfg(feature = "backend-dilithium2")]
                CrvOrPk::Dilithium2(pk) => map.serialize_entry(&(Label::CrvOrPk as i8), pk)?,
                #[cfg(feature = "backend-dilithium3")]
                CrvOrPk::Dilithium3(pk) => map.serialize_entry(&(Label::CrvOrPk as i8), pk)?,
                #[cfg(feature = "backend-dilithium5")]
                CrvOrPk::Dilithium5(pk) => map.serialize_entry(&(Label::CrvOrPk as i8), pk)?,
            }
        }
        // -2: x
        if let Some(x) = &self.x {
            map.serialize_entry(&(Label::X as i8), x)?;
        }
        // -3: y
        if let Some(y) = &self.y {
            map.serialize_entry(&(Label::Y as i8), y)?;
        }

        map.end()
    }
}

trait PublicKeyConstants {
    const KTY: Kty;
    const ALG: Alg;
    const CRV: Crv;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(into = "RawPublicKey")]
pub struct P256PublicKey {
    pub x: Bytes<32>,
    pub y: Bytes<32>,
}

impl PublicKeyConstants for P256PublicKey {
    const KTY: Kty = Kty::Ec2;
    const ALG: Alg = Alg::Es256;
    const CRV: Crv = Crv::P256;
}

impl From<P256PublicKey> for RawPublicKey {
    fn from(key: P256PublicKey) -> Self {
        Self {
            kty: Some(P256PublicKey::KTY),
            alg: Some(P256PublicKey::ALG),
            crv_or_pk: Some(CrvOrPk::Ec(P256PublicKey::CRV)),
            x: Some(key.x),
            y: Some(key.y),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(into = "RawPublicKey")]
pub struct EcdhEsHkdf256PublicKey {
    pub x: Bytes<32>,
    pub y: Bytes<32>,
}

impl PublicKeyConstants for EcdhEsHkdf256PublicKey {
    const KTY: Kty = Kty::Ec2;
    const ALG: Alg = Alg::EcdhEsHkdf256;
    const CRV: Crv = Crv::P256;
}

impl From<EcdhEsHkdf256PublicKey> for RawPublicKey {
    fn from(key: EcdhEsHkdf256PublicKey) -> Self {
        Self {
            kty: Some(EcdhEsHkdf256PublicKey::KTY),
            alg: Some(EcdhEsHkdf256PublicKey::ALG),
            crv_or_pk: Some(CrvOrPk::Ec(EcdhEsHkdf256PublicKey::CRV)),
            x: Some(key.x),
            y: Some(key.y),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(into = "RawPublicKey")]
pub struct Ed25519PublicKey {
    pub x: Bytes<32>,
}

impl PublicKeyConstants for Ed25519PublicKey {
    const KTY: Kty = Kty::Okp;
    const ALG: Alg = Alg::EdDsa;
    const CRV: Crv = Crv::Ed25519;
}

impl From<Ed25519PublicKey> for RawPublicKey {
    fn from(key: Ed25519PublicKey) -> Self {
        Self {
            kty: Some(Ed25519PublicKey::KTY),
            alg: Some(Ed25519PublicKey::ALG),
            crv_or_pk: Some(CrvOrPk::Ec(Ed25519PublicKey::CRV)),
            x: Some(key.x),
            y: None,
        }
    }
}

#[cfg(feature = "backend-dilithium2")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(into = "RawPublicKey")]
pub struct Dilithium2PublicKey {
    pub pk: Bytes<{ ffi::PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES }>,
}

#[cfg(feature = "backend-dilithium2")]
impl PublicKeyConstants for Dilithium2PublicKey {
    const KTY: Kty = Kty::Pqc;
    const ALG: Alg = Alg::Dilithium2;
    const CRV: Crv = Crv::None;
}

#[cfg(feature = "backend-dilithium2")]
impl From<Dilithium2PublicKey> for RawPublicKey {
    fn from(key: Dilithium2PublicKey) -> Self {
        Self {
            kty: Some(Dilithium2PublicKey::KTY),
            alg: Some(Dilithium2PublicKey::ALG),
            crv_or_pk: Some(CrvOrPk::Dilithium2(key.pk)),
            x: None,
            y: None,
        }
    }
}

#[cfg(feature = "backend-dilithium3")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(into = "RawPublicKey")]
pub struct Dilithium3PublicKey {
    pub pk: Bytes<{ ffi::PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES }>,
}

#[cfg(feature = "backend-dilithium3")]
impl PublicKeyConstants for Dilithium3PublicKey {
    const KTY: Kty = Kty::Pqc;
    const ALG: Alg = Alg::Dilithium3;
    const CRV: Crv = Crv::None;
}

#[cfg(feature = "backend-dilithium3")]
impl From<Dilithium3PublicKey> for RawPublicKey {
    fn from(key: Dilithium3PublicKey) -> Self {
        Self {
            kty: Some(Dilithium3PublicKey::KTY),
            alg: Some(Dilithium3PublicKey::ALG),
            crv_or_pk: Some(CrvOrPk::Dilithium3(key.pk)),
            x: None,
            y: None,
        }
    }
}

#[cfg(feature = "backend-dilithium5")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(into = "RawPublicKey")]
pub struct Dilithium5PublicKey {
    pub pk: Bytes<{ ffi::PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES }>,
}

#[cfg(feature = "backend-dilithium5")]
impl PublicKeyConstants for Dilithium5PublicKey {
    const KTY: Kty = Kty::Pqc;
    const ALG: Alg = Alg::Dilithium5;
    const CRV: Crv = Crv::None;
}

#[cfg(feature = "backend-dilithium5")]
impl From<Dilithium5PublicKey> for RawPublicKey {
    fn from(key: Dilithium5PublicKey) -> Self {
        Self {
            kty: Some(Dilithium5PublicKey::KTY),
            alg: Some(Dilithium5PublicKey::ALG),
            crv_or_pk: Some(CrvOrPk::Dilithium5(key.pk)),
            x: None,
            y: None,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(into = "RawPublicKey")]
pub struct TotpPublicKey {}

impl PublicKeyConstants for TotpPublicKey {
    const KTY: Kty = Kty::Symmetric;
    const ALG: Alg = Alg::Totp;
    const CRV: Crv = Crv::None;
}

impl From<TotpPublicKey> for RawPublicKey {
    fn from(_key: TotpPublicKey) -> Self {
        Self {
            kty: Some(TotpPublicKey::KTY),
            alg: Some(TotpPublicKey::ALG),
            crv_or_pk: None,
            x: None,
            y: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct X25519PublicKey {
    pub pub_key: Bytes<32>,
}

fn check_key_constants<K: PublicKeyConstants, E: serde::de::Error>(
    kty: Option<Kty>,
    alg: Option<Alg>,
    crv_or_pk: &Option<CrvOrPk>,
) -> Result<(), E> {
    let kty = kty.ok_or_else(|| E::missing_field("kty"))?;
    if kty != K::KTY {
        return Err(E::invalid_value(Unexpected::Signed(kty as _), &K::KTY));
    }
    if let Some(alg) = alg {
        if alg != K::ALG {
            return Err(E::invalid_value(Unexpected::Signed(alg as _), &K::ALG));
        }
    }
    if K::CRV != Crv::None {
        let crv_or_pk = crv_or_pk.as_ref().ok_or_else(|| E::missing_field("crv_or_pk"))?;
        match crv_or_pk {
            CrvOrPk::Ec(crv) => {
                if *crv != K::CRV {
                    return Err(E::invalid_value(Unexpected::Signed(*crv as _), &K::CRV));
                }
            },
            #[cfg(feature = "backend-dilithium2")]
            CrvOrPk::Dilithium2(pk) => return Err(E::invalid_type(Unexpected::Bytes(&pk as _), &K::CRV)),
            #[cfg(feature = "backend-dilithium3")]
            CrvOrPk::Dilithium3(pk) => return Err(E::invalid_type(Unexpected::Bytes(&pk as _), &K::CRV)),
            #[cfg(feature = "backend-dilithium5")]
            CrvOrPk::Dilithium5(pk) => return Err(E::invalid_type(Unexpected::Bytes(&pk as _), &K::CRV)),
        }
    }
    Ok(())
}

impl<'de> serde::Deserialize<'de> for P256PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let RawPublicKey {
            kty,
            alg,
            crv_or_pk,
            x,
            y,
        } = RawPublicKey::deserialize(deserializer)?;
        check_key_constants::<P256PublicKey, D::Error>(kty, alg, &crv_or_pk)?;
        let x = x.ok_or_else(|| D::Error::missing_field("x"))?;
        let y = y.ok_or_else(|| D::Error::missing_field("y"))?;
        Ok(Self { x, y })
    }
}

impl<'de> serde::Deserialize<'de> for EcdhEsHkdf256PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let RawPublicKey {
            kty,
            alg,
            crv_or_pk,
            x,
            y,
        } = RawPublicKey::deserialize(deserializer)?;
        check_key_constants::<EcdhEsHkdf256PublicKey, D::Error>(kty, alg, &crv_or_pk)?;
        let x = x.ok_or_else(|| D::Error::missing_field("x"))?;
        let y = y.ok_or_else(|| D::Error::missing_field("y"))?;
        Ok(Self { x, y })
    }
}

impl<'de> serde::Deserialize<'de> for Ed25519PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let RawPublicKey {
            kty, alg, crv_or_pk, x, ..
        } = RawPublicKey::deserialize(deserializer)?;
        check_key_constants::<Ed25519PublicKey, D::Error>(kty, alg, &crv_or_pk)?;
        let x = x.ok_or_else(|| D::Error::missing_field("x"))?;
        Ok(Self { x })
    }
}

#[cfg(feature = "backend-dilithium2")]
impl<'de> serde::Deserialize<'de> for Dilithium2PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let RawPublicKey {
            kty, alg, crv_or_pk, ..
        } = RawPublicKey::deserialize(deserializer)?;
        check_key_constants::<Dilithium2PublicKey, D::Error>(kty, alg, &crv_or_pk)?;
        let pk = crv_or_pk.ok_or_else(|| D::Error::missing_field("pk"))?;
        match pk {
            CrvOrPk::Dilithium2(pk) => Ok(Self { pk }),
            #[cfg(feature = "backend-dilithium3")]
            CrvOrPk::Dilithium3(pk) => Err(D::Error::invalid_length(pk.len(), &"expected 1312")),
            #[cfg(feature = "backend-dilithium5")]
            CrvOrPk::Dilithium5(pk) => Err(D::Error::invalid_length(pk.len(), &"expected 1312")),
            CrvOrPk::Ec(crv) => return Err(D::Error::invalid_type(Unexpected::Signed(crv as _), &"expected Bytes")),
        }
    }
}

#[cfg(feature = "backend-dilithium3")]
impl<'de> serde::Deserialize<'de> for Dilithium3PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let RawPublicKey {
            kty, alg, crv_or_pk, ..
        } = RawPublicKey::deserialize(deserializer)?;
        check_key_constants::<Dilithium3PublicKey, D::Error>(kty, alg, &crv_or_pk)?;
        let pk = crv_or_pk.ok_or_else(|| D::Error::missing_field("pk"))?;
        match pk {
            CrvOrPk::Dilithium3(pk) => Ok(Self { pk }),
            #[cfg(feature = "backend-dilithium2")]
            CrvOrPk::Dilithium2(pk) => Err(D::Error::invalid_length(pk.len(), &"expected 1952")),
            #[cfg(feature = "backend-dilithium5")]
            CrvOrPk::Dilithium5(pk) => Err(D::Error::invalid_length(pk.len(), &"expected 1952")),
            CrvOrPk::Ec(crv) => return Err(D::Error::invalid_type(Unexpected::Signed(crv as _), &"expected Bytes")),
        }
    }
}

#[cfg(feature = "backend-dilithium5")]
impl<'de> serde::Deserialize<'de> for Dilithium5PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let RawPublicKey {
            kty, alg, crv_or_pk, ..
        } = RawPublicKey::deserialize(deserializer)?;
        check_key_constants::<Dilithium5PublicKey, D::Error>(kty, alg, &crv_or_pk)?;
        let pk = crv_or_pk.ok_or_else(|| D::Error::missing_field("pk"))?;
        match pk {
            CrvOrPk::Dilithium5(pk) => Ok(Self { pk }),
            #[cfg(feature = "backend-dilithium2")]
            CrvOrPk::Dilithium2(pk) => Err(D::Error::invalid_length(pk.len(), &"expected 2592")),
            #[cfg(feature = "backend-dilithium3")]
            CrvOrPk::Dilithium3(pk) => Err(D::Error::invalid_length(pk.len(), &"expected 2592")),
            CrvOrPk::Ec(crv) => return Err(D::Error::invalid_type(Unexpected::Signed(crv as _), &"expected Bytes")),
        }
    }
}
