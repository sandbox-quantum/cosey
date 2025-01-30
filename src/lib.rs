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
use ::with_builtin_macros::with_eager_expansions;
use core::fmt::{self, Formatter};
pub use heapless_bytes::Bytes;
use paste::paste;
#[cfg(feature = "backend-dilithium2")]
use pqcrypto_dilithium::dilithium2;
#[cfg(feature = "backend-dilithium3")]
use pqcrypto_dilithium::dilithium3;
#[cfg(feature = "backend-dilithium5")]
use pqcrypto_dilithium::dilithium5;
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

#[derive(Clone, Debug, Default)]
struct RawEcPublicKey {
    kty: Option<Kty>,
    alg: Option<Alg>,
    crv: Option<Crv>,
    x: Option<Bytes<32>>,
    y: Option<Bytes<32>>,
}

impl<'de> Deserialize<'de> for RawEcPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct IndexedVisitor;
        impl<'de> serde::de::Visitor<'de> for IndexedVisitor {
            type Value = RawEcPublicKey;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("RawEcPublicKey")
            }

            fn visit_map<V>(self, mut map: V) -> Result<RawEcPublicKey, V::Error>
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

                let mut public_key = RawEcPublicKey::default();

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
                    public_key.crv = Some(map.next_value()?);
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

impl Serialize for RawEcPublicKey {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_set = [
            self.kty.is_some(),
            self.alg.is_some(),
            self.crv.is_some(),
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
        // -1: crv
        if let Some(crv) = &self.crv {
            map.serialize_entry(&(Label::CrvOrPk as i8), &(*crv as i8))?;
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
#[serde(into = "RawEcPublicKey")]
pub struct P256PublicKey {
    pub x: Bytes<32>,
    pub y: Bytes<32>,
}

impl PublicKeyConstants for P256PublicKey {
    const KTY: Kty = Kty::Ec2;
    const ALG: Alg = Alg::Es256;
    const CRV: Crv = Crv::P256;
}

impl From<P256PublicKey> for RawEcPublicKey {
    fn from(key: P256PublicKey) -> Self {
        Self {
            kty: Some(P256PublicKey::KTY),
            alg: Some(P256PublicKey::ALG),
            crv: Some(P256PublicKey::CRV),
            x: Some(key.x),
            y: Some(key.y),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(into = "RawEcPublicKey")]
pub struct EcdhEsHkdf256PublicKey {
    pub x: Bytes<32>,
    pub y: Bytes<32>,
}

impl PublicKeyConstants for EcdhEsHkdf256PublicKey {
    const KTY: Kty = Kty::Ec2;
    const ALG: Alg = Alg::EcdhEsHkdf256;
    const CRV: Crv = Crv::P256;
}

impl From<EcdhEsHkdf256PublicKey> for RawEcPublicKey {
    fn from(key: EcdhEsHkdf256PublicKey) -> Self {
        Self {
            kty: Some(EcdhEsHkdf256PublicKey::KTY),
            alg: Some(EcdhEsHkdf256PublicKey::ALG),
            crv: Some(EcdhEsHkdf256PublicKey::CRV),
            x: Some(key.x),
            y: Some(key.y),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(into = "RawEcPublicKey")]
pub struct Ed25519PublicKey {
    pub x: Bytes<32>,
}

impl PublicKeyConstants for Ed25519PublicKey {
    const KTY: Kty = Kty::Okp;
    const ALG: Alg = Alg::EdDsa;
    const CRV: Crv = Crv::Ed25519;
}

impl From<Ed25519PublicKey> for RawEcPublicKey {
    fn from(key: Ed25519PublicKey) -> Self {
        Self {
            kty: Some(Ed25519PublicKey::KTY),
            alg: Some(Ed25519PublicKey::ALG),
            crv: Some(Ed25519PublicKey::CRV),
            x: Some(key.x),
            y: None,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(into = "RawEcPublicKey")]
pub struct TotpPublicKey {}

impl PublicKeyConstants for TotpPublicKey {
    const KTY: Kty = Kty::Symmetric;
    const ALG: Alg = Alg::Totp;
    const CRV: Crv = Crv::None;
}

impl From<TotpPublicKey> for RawEcPublicKey {
    fn from(_key: TotpPublicKey) -> Self {
        Self {
            kty: Some(TotpPublicKey::KTY),
            alg: Some(TotpPublicKey::ALG),
            crv: None,
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
    crv: Option<Crv>,
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
        let crv = crv.ok_or_else(|| E::missing_field("crv"))?;
        if crv != K::CRV {
            return Err(E::invalid_value(Unexpected::Signed(crv as _), &K::CRV));
        }
    }
    Ok(())
}

impl<'de> serde::Deserialize<'de> for P256PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let RawEcPublicKey {
            kty,
            alg,
            crv,
            x,
            y,
        } = RawEcPublicKey::deserialize(deserializer)?;
        check_key_constants::<P256PublicKey, D::Error>(kty, alg, crv)?;
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
        let RawEcPublicKey {
            kty,
            alg,
            crv,
            x,
            y,
        } = RawEcPublicKey::deserialize(deserializer)?;
        check_key_constants::<EcdhEsHkdf256PublicKey, D::Error>(kty, alg, crv)?;
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
        let RawEcPublicKey {
            kty, alg, crv, x, ..
        } = RawEcPublicKey::deserialize(deserializer)?;
        check_key_constants::<Ed25519PublicKey, D::Error>(kty, alg, crv)?;
        let x = x.ok_or_else(|| D::Error::missing_field("x"))?;
        Ok(Self { x })
    }
}

#[cfg(feature = "backend-dilithium")]
macro_rules! dilithium_public_key {
    ($dilithium_number: tt) => {
        paste! {
            with_eager_expansions! {
                #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
                #[serde(into = #{ concat!("RawDilithium", stringify!($dilithium_number), "PublicKey") })]
                pub struct [<Dilithium $dilithium_number PublicKey>] {
                    pub pk: Bytes<{ [<dilithium $dilithium_number>]::public_key_bytes() }>,
                }

                impl PublicKeyConstants for [<Dilithium $dilithium_number PublicKey>] {
                    const KTY: Kty = Kty::Pqc;
                    const ALG: Alg = Alg::[<Dilithium $dilithium_number>];
                    const CRV: Crv = Crv::None;
                }

                impl From<[<Dilithium $dilithium_number PublicKey>]> for PublicKey {
                    fn from(key: [<Dilithium $dilithium_number PublicKey>]) -> Self {
                        PublicKey::[<Dilithium $dilithium_number>](key)
                    }
                }

                #[derive(Clone, Debug, Default)]
                struct [<RawDilithium $dilithium_number PublicKey>] {
                    kty: Option<Kty>,
                    alg: Option<Alg>,
                    pk: Option<Bytes<{ [<dilithium $dilithium_number>]::public_key_bytes() }>>,
                }

                impl From<[<Dilithium $dilithium_number PublicKey>]> for [<RawDilithium $dilithium_number PublicKey>] {
                    fn from(key: [<Dilithium $dilithium_number PublicKey>]) -> Self {
                        Self {
                            kty: Some([<Dilithium $dilithium_number PublicKey>]::KTY),
                            alg: Some([<Dilithium $dilithium_number PublicKey>]::ALG),
                            pk: Some(key.pk),
                        }
                    }
                }

                impl<'de> serde::Deserialize<'de> for [<Dilithium $dilithium_number PublicKey>] {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: serde::Deserializer<'de>,
                    {
                        let [<RawDilithium $dilithium_number PublicKey>] { kty, alg, pk, .. } =
                        [<RawDilithium $dilithium_number PublicKey>]::deserialize(deserializer)?;
                        check_key_constants::<[<Dilithium $dilithium_number PublicKey>], D::Error>(kty, alg, Some(Crv::None))?;
                        let pk = pk.ok_or_else(|| D::Error::missing_field("pk"))?;
                        Ok(Self { pk })
                    }
                }

                impl<'de> Deserialize<'de> for [<RawDilithium $dilithium_number PublicKey>] {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: serde::Deserializer<'de>,
                    {
                        struct IndexedVisitor;
                        impl<'de> serde::de::Visitor<'de> for IndexedVisitor {
                            type Value = [<RawDilithium $dilithium_number PublicKey>];

                            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                                formatter.write_str(concat!("RawDilithium", stringify!($dilithium_number), "PublicKey"))
                            }

                            fn visit_map<V>(self, mut map: V) -> Result<[<RawDilithium $dilithium_number PublicKey>], V::Error>
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

                                let mut public_key = [<RawDilithium $dilithium_number PublicKey>]::default();

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
                                    public_key.pk = Some(map.next_value()?);
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

                impl Serialize for [<RawDilithium $dilithium_number PublicKey>] {
                    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
                    where
                        S: serde::Serializer,
                    {
                        let is_set = [self.kty.is_some(), self.alg.is_some(), self.pk.is_some()];
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
                        // -1: pk
                        if let Some(pk) = &self.pk {
                            map.serialize_entry(&(Label::CrvOrPk as i8), pk)?;
                        }

                        map.end()
                    }
                }
            }
        }
    };
}

#[cfg(feature = "backend-dilithium2")]
dilithium_public_key!(2);
#[cfg(feature = "backend-dilithium3")]
dilithium_public_key!(3);
#[cfg(feature = "backend-dilithium5")]
dilithium_public_key!(5);
