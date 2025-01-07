use core::fmt::Debug;

use cbor_smol::{cbor_deserialize, cbor_serialize_bytes};
use ciborium::Value;
use cosey::{EcdhEsHkdf256PublicKey, Ed25519PublicKey, P256PublicKey};
use heapless_bytes::Bytes;
use itertools::Itertools as _;
use quickcheck::{Arbitrary, Gen};
use serde::{de::DeserializeOwned, Serialize};

#[cfg(feature = "backend-dilithium2")]
use cosey::Dilithium2PublicKey;
#[cfg(feature = "backend-dilithium3")]
use cosey::Dilithium3PublicKey;
#[cfg(feature = "backend-dilithium5")]
use cosey::Dilithium5PublicKey;
#[cfg(feature = "backend-dilithium2")]
use pqcrypto_dilithium::dilithium2;
#[cfg(feature = "backend-dilithium3")]
use pqcrypto_dilithium::dilithium3;
#[cfg(feature = "backend-dilithium5")]
use pqcrypto_dilithium::dilithium5;

#[derive(Clone, Debug)]
struct EcInput(Bytes<32>);

#[cfg(feature = "backend-dilithium2")]
#[derive(Clone, Debug)]
struct Dilithium2Input(Bytes<{ dilithium2::public_key_bytes() }>);

#[cfg(feature = "backend-dilithium3")]
#[derive(Clone, Debug)]
struct Dilithium3Input(Bytes<{ dilithium3::public_key_bytes() }>);

#[cfg(feature = "backend-dilithium5")]
#[derive(Clone, Debug)]
struct Dilithium5Input(Bytes<{ dilithium5::public_key_bytes() }>);

impl Arbitrary for EcInput {
    fn arbitrary(g: &mut Gen) -> Self {
        let mut data = vec![0; 32];
        data.fill_with(|| u8::arbitrary(g));
        Self(Bytes::from_slice(&data).unwrap())
    }
}

#[cfg(feature = "backend-dilithium2")]
impl Arbitrary for Dilithium2Input {
    fn arbitrary(g: &mut Gen) -> Self {
        let mut data = vec![0; dilithium2::public_key_bytes()];
        data.fill_with(|| u8::arbitrary(g));
        Self(Bytes::from_slice(&data).unwrap())
    }
}

#[cfg(feature = "backend-dilithium3")]
impl Arbitrary for Dilithium3Input {
    fn arbitrary(g: &mut Gen) -> Self {
        let mut data = vec![0; dilithium3::public_key_bytes()];
        data.fill_with(|| u8::arbitrary(g));
        Self(Bytes::from_slice(&data).unwrap())
    }
}

#[cfg(feature = "backend-dilithium5")]
impl Arbitrary for Dilithium5Input {
    fn arbitrary(g: &mut Gen) -> Self {
        let mut data = vec![0; dilithium5::public_key_bytes()];
        data.fill_with(|| u8::arbitrary(g));
        Self(Bytes::from_slice(&data).unwrap())
    }
}

fn deserialize_map<T: DeserializeOwned>(
    map: Vec<(Value, Value)>,
) -> (Result<T, cbor_smol::Error>, Vec<u8>) {
    let map = Value::Map(map);
    let mut serialized: Vec<u8> = Default::default();
    ciborium::into_writer(&map, &mut serialized).unwrap();
    (cbor_deserialize(&serialized), serialized)
}

fn print_input_output<T: Debug + PartialEq>(
    input: &T,
    serialized: &[u8],
    deserialized: &Result<T, cbor_smol::Error>,
) {
    println!("serialized:\n  {}", hex::encode(serialized));
    println!("input:\n     {:?}", input);
    print!("deserialized:\n  ");
    if deserialized.as_ref() == Ok(input) {
        println!("Ok(input)");
    } else {
        println!("{:?}", deserialized);
    }
}

fn test_serde<T: Serialize + DeserializeOwned + PartialEq>(data: T) -> bool {
    let serialized: Bytes<3072> = cbor_serialize_bytes(&data).unwrap();
    let deserialized: T = cbor_deserialize(&serialized).unwrap();
    data == deserialized
}

fn test_de<T: DeserializeOwned + Debug + PartialEq>(s: &str, data: T) {
    let serialized = hex::decode(s).unwrap();
    let deserialized: T = cbor_deserialize(&serialized).unwrap();
    assert_eq!(data, deserialized);
}

fn test_de_alg<T: Serialize + DeserializeOwned + Debug + PartialEq>(
    data: T,
    alg: Option<i8>,
) -> bool {
    let serialized_value = Value::serialized(&data).unwrap();
    let mut fields = serialized_value.into_map().unwrap();
    // this must be alg
    assert_eq!(fields[1].0, Value::Integer(3.into()));

    let expect_success = if let Some(alg) = alg {
        // alg values may only work if they are correct
        let alg = Value::Integer(alg.into());
        if fields[1].1 == alg {
            true
        } else {
            fields[1].1 = alg;
            false
        }
    } else {
        // deserialization without alg must work
        fields.remove(1);
        true
    };

    let (deserialized, serialized) = deserialize_map::<T>(fields);
    let is_success = deserialized.is_ok() == expect_success;

    if !is_success {
        if alg.is_some() {
            if expect_success {
                println!("Expected correct deserialization for original algorithm");
            } else {
                println!("Expected error for invalid algorithm");
            }
        } else {
            println!("Expected correct deserialization for missing algorithm");
        }
        println!("alg: {:?}", alg);
        print_input_output(&data, &serialized, &deserialized);
    }

    is_success
}

fn test_de_order<T: Serialize + DeserializeOwned + Debug + PartialEq>(data: T) -> bool {
    let serialized_value = Value::serialized(&data).unwrap();
    let canonical_fields = serialized_value.into_map().unwrap();

    for fields in canonical_fields
        .iter()
        .cloned()
        .permutations(canonical_fields.len())
    {
        let is_canonical = fields == canonical_fields;
        let (deserialized, serialized) = deserialize_map::<T>(fields);

        // only the canonical order should be accepted
        let is_success = if is_canonical {
            Ok(&data) == deserialized.as_ref()
        } else {
            deserialized.is_err()
        };

        if !is_success {
            if is_canonical {
                println!("Expected correct deserialization for canonical order");
            } else {
                println!("Expected error for non-canonical order");
            }
            print_input_output(&data, &serialized, &deserialized);
            return false;
        }
    }

    let mut fields = canonical_fields;
    fields.push((Value::Integer(42.into()), Value::Text("foobar".to_owned())));
    fields.push((Value::Integer(24.into()), Value::Text("foobar".to_owned())));
    let (deserialized, serialized) = deserialize_map::<T>(fields);

    // injecting an unsupported field should not change the result
    let is_success = Ok(&data) == deserialized.as_ref();

    if !is_success {
        println!("Expected correct deserialization with unsupported fields");
        print_input_output(&data, &serialized, &deserialized);
    }

    is_success
}

#[test]
fn de_p256() {
    let x = Bytes::from_slice(&[0xff; 32]).unwrap();
    let y = Bytes::from_slice(&[0xff; 32]).unwrap();
    let key = P256PublicKey { x, y };
    test_de("a5010203262001215820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff225820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", key);
}

#[test]
fn de_ecdh() {
    let x = Bytes::from_slice(&[0xff; 32]).unwrap();
    let y = Bytes::from_slice(&[0xff; 32]).unwrap();
    let key = EcdhEsHkdf256PublicKey { x, y };
    test_de("a501020338182001215820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff225820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", key);
}

#[test]
fn de_ed25519() {
    let x = Bytes::from_slice(&[0xff; 32]).unwrap();
    let key = Ed25519PublicKey { x };
    test_de(
        "a4010103272006215820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        key,
    );
}

#[test]
#[cfg(feature = "backend-dilithium2")]
fn de_dilithium2() {
    const DILITHIUM2_KAT_PK: &str = "1c0ee1111b08003f28e65e8b3bdeb037cf8f221dfcdaf5950edb38d506d85bef6177e3de0d4f1ef5847735947b56d08e841db2444fa2b729adeb1417ca7adf42a1490c5a097f002760c1fc419be8325aad0197c52ced80d3df18e7774265b289912ceca1be3a90d8a4fde65c84c610864e47deecae3eea4430b9909559408d11a6abdb7db9336df7f96eab4864a6579791265fa56c348cb7d2ddc90e133a95c3f6b13601429f5408bd999aa479c1018159550ec55a113c493be648f4e036dd4f8c809e036b4fbb918c2c484ad8e1747ae05585ab433fdf461af03c25a773700721aa05f7379fe7f5ed96175d4021076e7f52b60308eff5d42ba6e093b3d0815eb3496646e49230a9b35c8d41900c2bb8d3b446a23127f7e096d85a1c794ad4c89277904fc6bfec57b1cdd80df9955030fdca741afbdac827b13ccd5403588af4644003c2265dfa4d419dbccd2064892386518be9d51c16498275ebecf5cdc7a820f2c29314ac4a6f08b2252ad3cfb199aa42fe0b4fb571975c1020d949e194ee1ead937bfb550bb3ba8e357a029c29f077554602e1ca2f2289cb9169941c3aafdb8e58c7f2ac77291fb4147c65f6b031d3eba42f2acfd9448a5bc22b476e07ccceda2306c554ec9b7ab655f1d7318c2b7e67d5f69bedf56000fda98986b5ab1b3a22d8dfd6681697b23a55c96e8710f3f98c044fb15f606313ee56c0f1f5ca0f512e08484fcb358e6e528ffa89f8a866ccff3c0c5813147ec59af0470c4aad0141d34f101da2e5e1bd52d0d4c9b13b3e3d87d1586105796754e7978ca1c68a7d85df112b7ab921b359a9f03cbd27a7eac87a9a80b0b26b4c9657ed85ad7fa2616ab345eb8226f69fc0f48183ff574bcd767b5676413adb12ea2150a0e97683ee54243c25b7ea8a718606f86993d8d0dace834ed341eeb724fe3d5ff0bc8b8a7b8104ba269d34133a4cf8300a2d688496b59b6fcbc61ae96062ea1d8e5b410c5671f424417ed693329cd983001ffcd10023d598859fb7ad5fd263547117100690c6ce7438956e6cc57f1b5de53bb0dc72ce9b6deaa85789599a70f0051f1a0e25e86d888b00df36bdbc93ef7217c45ace11c0790d70e9953e5b417ba2fd9a4caf82f1fce6f45f53e215b8355ef61d891df1c794231c162dd24164b534a9d48467cdc323624c2f95d4402ff9d66ab1191a8124144afa35d4e31dc86caa797c31f68b85854cd959c4fac5ec53b3b56d374b888a9e979a6576b6345ec8522c9606990281bf3ef7c5945d10fd21a2a1d2e5404c5cf21220641391b98bcf825398305b56e58b611fe5253203e3df0d22466a73b3f0fbe43b9a62928091898b8a0e5b269db586b0e4ddef50d682a12d2c1be824149aa254c6381bb412d77c3f9aa902b688c81715a59c839558556d35ed4fc83b4ab18181f40f73dcd76860d8d8bf94520237c2ac0e463ba09e3c9782380dc07fe4fcba340cc2003439fd2314610638070d6c9eea0a70bae83b5d5d3c5d3fde26dd01606c8c520158e7e5104020f248ceaa666457c10aebf068f8a3bd5ce7b52c6af0abd5944af1ad4752c9113976083c03b6c34e1d47ed69644cad782c2f7d05f8a148961d965fa2e1723a8ddebc22a90cd783dd1f4db38fb9ae5a6714b3d946781643d317b7dd79381cf789a9588bb3e193b92a0b60d6b07d047f6984b0609ec57543c394ca8d5e5bcc2a731a79618bd1e2e0da8704af98f20f5f8f5452ddf646b95b341dd7f0d2cc1fa15bd9895cd5b65aa1cb94b5e2e788fda9825b656639193d98328154a4f2c35495a38b6ea0d2ffaaa35df92c203c7f31cbbca7bd03c3c2302190cecd161fd49237e4f839e3f3";
    let pk = Bytes::from_slice(hex::decode(DILITHIUM2_KAT_PK).unwrap().as_slice()).unwrap();
    let key = Dilithium2PublicKey { pk };
    test_de(
        "a30107033856205905201c0ee1111b08003f28e65e8b3bdeb037cf8f221dfcdaf5950edb38d506d85bef6177e3de0d4f1ef5847735947b56d08e841db2444fa2b729adeb1417ca7adf42a1490c5a097f002760c1fc419be8325aad0197c52ced80d3df18e7774265b289912ceca1be3a90d8a4fde65c84c610864e47deecae3eea4430b9909559408d11a6abdb7db9336df7f96eab4864a6579791265fa56c348cb7d2ddc90e133a95c3f6b13601429f5408bd999aa479c1018159550ec55a113c493be648f4e036dd4f8c809e036b4fbb918c2c484ad8e1747ae05585ab433fdf461af03c25a773700721aa05f7379fe7f5ed96175d4021076e7f52b60308eff5d42ba6e093b3d0815eb3496646e49230a9b35c8d41900c2bb8d3b446a23127f7e096d85a1c794ad4c89277904fc6bfec57b1cdd80df9955030fdca741afbdac827b13ccd5403588af4644003c2265dfa4d419dbccd2064892386518be9d51c16498275ebecf5cdc7a820f2c29314ac4a6f08b2252ad3cfb199aa42fe0b4fb571975c1020d949e194ee1ead937bfb550bb3ba8e357a029c29f077554602e1ca2f2289cb9169941c3aafdb8e58c7f2ac77291fb4147c65f6b031d3eba42f2acfd9448a5bc22b476e07ccceda2306c554ec9b7ab655f1d7318c2b7e67d5f69bedf56000fda98986b5ab1b3a22d8dfd6681697b23a55c96e8710f3f98c044fb15f606313ee56c0f1f5ca0f512e08484fcb358e6e528ffa89f8a866ccff3c0c5813147ec59af0470c4aad0141d34f101da2e5e1bd52d0d4c9b13b3e3d87d1586105796754e7978ca1c68a7d85df112b7ab921b359a9f03cbd27a7eac87a9a80b0b26b4c9657ed85ad7fa2616ab345eb8226f69fc0f48183ff574bcd767b5676413adb12ea2150a0e97683ee54243c25b7ea8a718606f86993d8d0dace834ed341eeb724fe3d5ff0bc8b8a7b8104ba269d34133a4cf8300a2d688496b59b6fcbc61ae96062ea1d8e5b410c5671f424417ed693329cd983001ffcd10023d598859fb7ad5fd263547117100690c6ce7438956e6cc57f1b5de53bb0dc72ce9b6deaa85789599a70f0051f1a0e25e86d888b00df36bdbc93ef7217c45ace11c0790d70e9953e5b417ba2fd9a4caf82f1fce6f45f53e215b8355ef61d891df1c794231c162dd24164b534a9d48467cdc323624c2f95d4402ff9d66ab1191a8124144afa35d4e31dc86caa797c31f68b85854cd959c4fac5ec53b3b56d374b888a9e979a6576b6345ec8522c9606990281bf3ef7c5945d10fd21a2a1d2e5404c5cf21220641391b98bcf825398305b56e58b611fe5253203e3df0d22466a73b3f0fbe43b9a62928091898b8a0e5b269db586b0e4ddef50d682a12d2c1be824149aa254c6381bb412d77c3f9aa902b688c81715a59c839558556d35ed4fc83b4ab18181f40f73dcd76860d8d8bf94520237c2ac0e463ba09e3c9782380dc07fe4fcba340cc2003439fd2314610638070d6c9eea0a70bae83b5d5d3c5d3fde26dd01606c8c520158e7e5104020f248ceaa666457c10aebf068f8a3bd5ce7b52c6af0abd5944af1ad4752c9113976083c03b6c34e1d47ed69644cad782c2f7d05f8a148961d965fa2e1723a8ddebc22a90cd783dd1f4db38fb9ae5a6714b3d946781643d317b7dd79381cf789a9588bb3e193b92a0b60d6b07d047f6984b0609ec57543c394ca8d5e5bcc2a731a79618bd1e2e0da8704af98f20f5f8f5452ddf646b95b341dd7f0d2cc1fa15bd9895cd5b65aa1cb94b5e2e788fda9825b656639193d98328154a4f2c35495a38b6ea0d2ffaaa35df92c203c7f31cbbca7bd03c3c2302190cecd161fd49237e4f839e3f3",
        key,
    );
}

#[test]
#[cfg(feature = "backend-dilithium3")]
fn de_dilithium3() {
    const DILITHIUM3_KAT_PK: &str = "1c0ee1111b08003f28e65e8b3bdeb037cf8f221dfcdaf5950edb38d506d85befd9fde3a496f75819f0a20d0441dc7830b4aa1cb8ecfc91ba0eec3afb6744e477b4e6ec3fdae75048ffebaabea8e822117d5787f79070ea88287ce3cd5011fd8d93ab7e8b51f26116bf9b6d21c03f88bfec488876f4d075a142d4e784d734407511f992069353f1db67acf73034a468a118588062111d320e00bcff6dc63573fced1e96aaeba6452e3c7acd19181f9b814ba19d39b4bab5496dc055426e7ea461af55d5b9fe97f9df7e253203c1f9e152e96d75f9d9a84f5c263ec8c250440adc986f4e36414c703b3e05426b28b7065950da6d0e0b2c60ac3672db6f3c78447db7c20915770ea6fce81dab5339c1d5af82a5d3324099df56516a07db7c0fc64383805c65f2b02fbcfce63e93c4bf09409f9f0f77e73da3b0019f2057e4cd7cff0e5745ef18c3fd766e01747a64d415fc9789abfa62284e11c7ff05d0548d973f679559a6a3aad77ed5132d0150c014c3ec3a395f017e7acfe3eabfca44910ca06ff33542ecce6241974742357d37f5c284bf0fe1a74b50c073551372133af2dd41e21bafc9c590ee6ebc4ace731ef566156ca03755dc493c137028af3b3de5b00bd6cb3d9a87d0151f887c6768bc6ca02a94fb2086551a0f89ba26154e9d4506ad9faf39f5723e234e06cfded69d4ee4146b73e5dc1e4152a2a3159d73dbc833d3d417cd5cf7fb3dc7745ceed4dc0f5b1c6d6b69c1764157ea43df9dbb442efa39d1d0162e87c2d30c5012fd16d869c8a1fcbb45edcc8e1813b2b190a961f9fc86591d3abc5388af678ff03da78b7cc0f6185721c0df33cc906435225df2611002df120e83566532292dea3d8acd109a0dffab3b0b43012796db5b50683fb4c2d250dab76aae35a48e8c8d4a5cc154759745f0a1230f6ca9dd9c99e2f80edc83304ce01e98f6c9489529a822f90033c228315eb2fcc8dba382ed4301e07607a5b076c725f124994f18a997d2c5bbf9a324605265108acbf4610fa1c3374408850a0864e2b61017ebec1fbab89de3ab1b93ce4918b9e2c9e3fe456758062a9f882b283318271f4b9552fcf32624a9fdaa44c65c60e2b3648bef1f17d0b7c74869ee0b53c4a62a24845dcea5bcbf93b92e4c26648584e33479282e6c8b1d8fe21181bd9cf75f8a961724d4c4309779f1f1b775d254f70bd1769cc7c0edd2a95fe5c9d84b16f7c54d85cce4c8a182810809ed81e97d074884eedf401ccacdaead82c14d06b68aea6ce14b861b0cfd16090cbbf469c5e084314c0d8d3960ea06a3426d8b3fe762e00d09bda374f3ae2cbede2838ff89d81deb3013090e44199aed604963eaf919914ce04f207ac82cd4351fef7b2d94393066fe4d44e3cc5952e75eb6f3714058915de0ee184d8c55300f576a8b82a863e81af33417bd4cfc94e7a61263b39f01f6e2e70748b6e5e59cf6ca01b0028c93bbbcebc548f987f10755bf33ca585cb41cf578df5ffe37924e3c2c072ed1dac9162176972971e79b62fb208f1a73bf0361e2993dcccd3110c34d839d18dd43a5e8f0d941e99adcf441405f32107671b2d8b2244f7ba92dced587a210fe8ff43c616acb5e766e6af2ceb03599ba3de376eb5735ef16143953d1fddb7e9f2874b0d6083dd7ec4386ae003f51ccf2d21ef6059163c5152174423f57119d0fce627d763d81c10aa1329f74c8d445437ba6718a33db6e79375172b2ae3591821978d520824e2d2ff898b7f4c867ff462722bc07eadad389a910b6f65429da129735fe049e3ecb3889f6047cf2bd2a88d50a651b3235d2480e1da5a35247fa76c831736399d37e8d033c1d051c9b6a99ab80b1313fa24c5c59766e6c51a38fe9f1186a767eebd0d88001ae0246cd4ebe2c979de82c30bbdb98b4744f11f9e639eddd8c194d7911201a8fa745991b4d8a5709b62a21b63b9762913d36ce995c2d6b79151e8d83838cd1f38840a9417255dd166b7a3584499003fb625611404c95b960df0db1bcf1574b0965dbd834ee148117d5e05a7cc7cc1a865618a2be4854db8935cda1e68bd8d09e72f0ac9053c882c4aba4004a614d10505300b6176ca1f324e22e7824299f9c40755b71d82b679547f06ad48be66d68072c9390233c933f80a14f8d4a6b0b4e1970e1acc1bea7f5d3be224448f857bab68aefa6d8cb819b64294a12997916cdbf56e9a8d002dd065f12c61823f4fc214508232e431f0b6898475bb5dd0d7d528e840c22809af7e15363724a613accfbe2b37438c159ce14cb0c98bfd499c08dac0cf45d821cc2fa47319b6fb4ced7e5985ec8274de09071d3c10da5bf9e522b01ce91d66b91795d3d22c00483454275dd2bbdd7c2dcc4a167e5d7fcdbb9f6208cd4c9a485faaeb809a7711dac2865ced4306474b22b4448f85df33417f3face1c05d42703ed313042a05de0362740130188ecb445bb255dc76ee8443f733117f8351f17603175554feb00b7ff54d80786f305cde18cd5ec56ec0962a3e04482dce3622d040d24c40f2e8a14a447659d6c561f2ffee68f8d3de511b23e8b172a01a3eda4d3780e74c677244330e9aeff019fe07be3d33f322f9ce2214b9d9cff99d05a59e47551432ae76f4cd4f8dd51520ffe811b4b93cd6219c81b63b1d627785c2a0fc22e3aea86ceee1f7fbc4efcb46ddfbcd88a02f3b4e67c5ff2e8dc68bf16c74699bbb628902f72c3debc8bf5df706d47a605a107daa0014139ce40f0d46d8d6dc7";
    let pk = Bytes::from_slice(hex::decode(DILITHIUM3_KAT_PK).unwrap().as_slice()).unwrap();
    let key = Dilithium3PublicKey { pk };
    test_de(
        "a30107033857205907a01c0ee1111b08003f28e65e8b3bdeb037cf8f221dfcdaf5950edb38d506d85befd9fde3a496f75819f0a20d0441dc7830b4aa1cb8ecfc91ba0eec3afb6744e477b4e6ec3fdae75048ffebaabea8e822117d5787f79070ea88287ce3cd5011fd8d93ab7e8b51f26116bf9b6d21c03f88bfec488876f4d075a142d4e784d734407511f992069353f1db67acf73034a468a118588062111d320e00bcff6dc63573fced1e96aaeba6452e3c7acd19181f9b814ba19d39b4bab5496dc055426e7ea461af55d5b9fe97f9df7e253203c1f9e152e96d75f9d9a84f5c263ec8c250440adc986f4e36414c703b3e05426b28b7065950da6d0e0b2c60ac3672db6f3c78447db7c20915770ea6fce81dab5339c1d5af82a5d3324099df56516a07db7c0fc64383805c65f2b02fbcfce63e93c4bf09409f9f0f77e73da3b0019f2057e4cd7cff0e5745ef18c3fd766e01747a64d415fc9789abfa62284e11c7ff05d0548d973f679559a6a3aad77ed5132d0150c014c3ec3a395f017e7acfe3eabfca44910ca06ff33542ecce6241974742357d37f5c284bf0fe1a74b50c073551372133af2dd41e21bafc9c590ee6ebc4ace731ef566156ca03755dc493c137028af3b3de5b00bd6cb3d9a87d0151f887c6768bc6ca02a94fb2086551a0f89ba26154e9d4506ad9faf39f5723e234e06cfded69d4ee4146b73e5dc1e4152a2a3159d73dbc833d3d417cd5cf7fb3dc7745ceed4dc0f5b1c6d6b69c1764157ea43df9dbb442efa39d1d0162e87c2d30c5012fd16d869c8a1fcbb45edcc8e1813b2b190a961f9fc86591d3abc5388af678ff03da78b7cc0f6185721c0df33cc906435225df2611002df120e83566532292dea3d8acd109a0dffab3b0b43012796db5b50683fb4c2d250dab76aae35a48e8c8d4a5cc154759745f0a1230f6ca9dd9c99e2f80edc83304ce01e98f6c9489529a822f90033c228315eb2fcc8dba382ed4301e07607a5b076c725f124994f18a997d2c5bbf9a324605265108acbf4610fa1c3374408850a0864e2b61017ebec1fbab89de3ab1b93ce4918b9e2c9e3fe456758062a9f882b283318271f4b9552fcf32624a9fdaa44c65c60e2b3648bef1f17d0b7c74869ee0b53c4a62a24845dcea5bcbf93b92e4c26648584e33479282e6c8b1d8fe21181bd9cf75f8a961724d4c4309779f1f1b775d254f70bd1769cc7c0edd2a95fe5c9d84b16f7c54d85cce4c8a182810809ed81e97d074884eedf401ccacdaead82c14d06b68aea6ce14b861b0cfd16090cbbf469c5e084314c0d8d3960ea06a3426d8b3fe762e00d09bda374f3ae2cbede2838ff89d81deb3013090e44199aed604963eaf919914ce04f207ac82cd4351fef7b2d94393066fe4d44e3cc5952e75eb6f3714058915de0ee184d8c55300f576a8b82a863e81af33417bd4cfc94e7a61263b39f01f6e2e70748b6e5e59cf6ca01b0028c93bbbcebc548f987f10755bf33ca585cb41cf578df5ffe37924e3c2c072ed1dac9162176972971e79b62fb208f1a73bf0361e2993dcccd3110c34d839d18dd43a5e8f0d941e99adcf441405f32107671b2d8b2244f7ba92dced587a210fe8ff43c616acb5e766e6af2ceb03599ba3de376eb5735ef16143953d1fddb7e9f2874b0d6083dd7ec4386ae003f51ccf2d21ef6059163c5152174423f57119d0fce627d763d81c10aa1329f74c8d445437ba6718a33db6e79375172b2ae3591821978d520824e2d2ff898b7f4c867ff462722bc07eadad389a910b6f65429da129735fe049e3ecb3889f6047cf2bd2a88d50a651b3235d2480e1da5a35247fa76c831736399d37e8d033c1d051c9b6a99ab80b1313fa24c5c59766e6c51a38fe9f1186a767eebd0d88001ae0246cd4ebe2c979de82c30bbdb98b4744f11f9e639eddd8c194d7911201a8fa745991b4d8a5709b62a21b63b9762913d36ce995c2d6b79151e8d83838cd1f38840a9417255dd166b7a3584499003fb625611404c95b960df0db1bcf1574b0965dbd834ee148117d5e05a7cc7cc1a865618a2be4854db8935cda1e68bd8d09e72f0ac9053c882c4aba4004a614d10505300b6176ca1f324e22e7824299f9c40755b71d82b679547f06ad48be66d68072c9390233c933f80a14f8d4a6b0b4e1970e1acc1bea7f5d3be224448f857bab68aefa6d8cb819b64294a12997916cdbf56e9a8d002dd065f12c61823f4fc214508232e431f0b6898475bb5dd0d7d528e840c22809af7e15363724a613accfbe2b37438c159ce14cb0c98bfd499c08dac0cf45d821cc2fa47319b6fb4ced7e5985ec8274de09071d3c10da5bf9e522b01ce91d66b91795d3d22c00483454275dd2bbdd7c2dcc4a167e5d7fcdbb9f6208cd4c9a485faaeb809a7711dac2865ced4306474b22b4448f85df33417f3face1c05d42703ed313042a05de0362740130188ecb445bb255dc76ee8443f733117f8351f17603175554feb00b7ff54d80786f305cde18cd5ec56ec0962a3e04482dce3622d040d24c40f2e8a14a447659d6c561f2ffee68f8d3de511b23e8b172a01a3eda4d3780e74c677244330e9aeff019fe07be3d33f322f9ce2214b9d9cff99d05a59e47551432ae76f4cd4f8dd51520ffe811b4b93cd6219c81b63b1d627785c2a0fc22e3aea86ceee1f7fbc4efcb46ddfbcd88a02f3b4e67c5ff2e8dc68bf16c74699bbb628902f72c3debc8bf5df706d47a605a107daa0014139ce40f0d46d8d6dc7",
        key,
    );
}

#[test]
#[cfg(feature = "backend-dilithium5")]
fn de_dilithium5() {
    const DILITHIUM5_KAT_PK: &str = "1c0ee1111b08003f28e65e8b3bdeb037cf8f221dfcdaf5950edb38d506d85bef032369a2ce572fd08bfc304b4848e78d752d77e97a28b99b9bb6fb5c7c6337514b321ecdc1fb669f26d4171ab42b72720ee70e0519a6e1d3d6d9914ec1b21cde38b41aac1d3abee6f2b7495c4c820c1fc0cc9e71e24cfb5c9c0d8eef4264af484fae4d6e5dde65d4df72b61c6dbd26f861a5e0b853ac5413226febbaba5eb474c6fb25a82678ea1606b452a23112221017b8c073c10378f9145641a8c078c0ed9e421650f748892522ab9fb7d1ff8cf1cc71b8566e8da33cd7361770c044349ac440cccdc6bbe35e6c55782766f38e688bf47821037299e344ecdeca17ad5d15cd27a4f7b070661138ede8ed72a8959c5ae36b1c46094a53cb21a7a42673f1401c2b259494090e2f53d7ee7063431ee5858002d850af909c3783436010f7ea88625a36a0f0189fde75b7e8c7e4b19d8527008328adbc929bbc86e964cfc48b8cf1da5d7ed3333ab55c15072832214a779a5fd10cc04005f46c1aa8884a161992472fd535b95ed18bde1c6d8ce678d2817d69f90571103e8520e7313ce7b930c5ebfaf2f4ec758b626b5543a068cde0fd0e94e6a64475b23268bf0380d075508f85128ca26f31a90c4a7d28440d54d4066b404588588b4ccf850b975c73afe68cbcd102755f61eb3e60323c576e529ec0bf23bfa5bea39cb73c37e8395d8dbd4c8dc8ab2f70a0bfc3a78c0d413f08d14d632bc0403b0383dbbb22bd9b113c89452aeab11210097947feaaa3c9f05d1d300c33a55e3fbc81259e862705c3a13b9ee35f6b23ed10f4edea9519fa91b7bcd0d501b5ed57d9049fab91aa779c725ff8e9f78017ea7807fa254b7105e826d096c01adae2c5d138251a92a478a33373f4de912b83b6fb4b0d0de6bc1118bb2fcfb07bd227a5f7f991439a13de1238180cdc55119e65c418584d807a926e4a9c0f70155ee196fb07656d9aa7982b8795dbad43d1059ca7f580d3320c0438a5ed5a7032b2e959678410f11ad98be8826a44262615645d759a862b2ac52d3b014a25e8473f1f1ea4cfa819930ab3a34d710deee70ca13e88fd71aa064e6cb4697de0e463b1370a6a3bfe98fdfe7b5471ff8df6a6879fbef9afb3519d780757d67440ac36e837bac3833eeaa980bd82b7936436a0307d164b6438869ae606e980518e913d0ee302396ef4eb25d9866e4bafa101e5992931361c4a982253d58abe3bd57107635a46f09512085f4ada08ec8b1b3910b0153b2aafcae5033edd4153248dcd85b02c9a25d8bdc4068bb85741726297a25aec55c44aa28059b71bb9f34067887ade4c1ca4908b19b3d78123453876db4dceb42773069572cd8777e62cfbaf7203f020f281a6678f790720eaa20e34327d7a63688b09a01f4d7088f7b5059eddeb45c0ce39321c79521d79a59ecdd468ced0ea82ca484928702f57d6fc18d347af3ed22aaf45abb0f20bab9e01557607ae3ed9cf0e26d34d305449669ec6fc1beceadce183f7a594cea196d059a1e550e547866cc087333f030e628f2cf1147925410ed0421dc7506138b1d19099c695e1afdace4153825b66a8ecf55a021d21eb9f848fe55c21769a755fa9807ef73a6c5ba15a06347d3f1c5c619a315598629106ac0b86ae0d8e55578292517258ae85f72e737af5638d096b76a3c57f1b9c80e770a2d4ea4e42fe469ad421285241960a8a86355ef22f583fe3bacadf8da31d5c2de254161bc6d10f9841dd27ed462a6b94b6deea90cbab687fb84b56395da763ab4b7fe3095d572d77eff3ff0d8f9d19aa5af7b676053dbef64e61dd0a41d402318e3308669106259bf7a4ce31b346a9e983edaba05180149ab057f9972977da7c6f46e0cdf86f3091f04fd4e83c6022e18ce4382b54d5daba82e4df1e53bf31fe4bb65a8524eda83fd29d07e49747b75291cbc8f8ee1415ec921e19022ade2c047e4df3507289e9d79a8e6992b48b8864204a416b769cc787d6df4407e93d121f7fbee0e408963e0609a9c75cb3117ca583df6e79f31c635bf0f1be98df550727a45d3ca337d79de5dcdb0b91cabbc30d7ef0ae1ca1e94904f78c1fd8fba87545fdc174ad8190f9b5ed7b5869494ffa91033fdc6117bf662ec5f2af2634ba3f8c02210f1c9bcdda9bb39760e00f25a7270c345666fb6df85c919aa150ca7fc80fc0eacfe242ef55f4298063628e61056c966db9964428d9ce99108271e29a12328e23999734e036f18a0eb8f030e88062c56717e7a36314e44ecf357ff56eedf90d3fb11b22a1b25905b379fcca5ca1acb956e178ad3f51d535ad119813b1e70f7317651bc75cac64276bb98110b54ea0ef34541d73910721d657387677e332e9c8811c3fc1b923b2ee9c512f6d09df372a5f97fad7123389cee197b5c269e221d7eed3160a521e56ff8aafab686179d09d78fc387b3ea6a672034d24ac7999d196b2316475f37db8e9ed431df58341fa88003d3c6489e78053d8e44ce7e16aef416859b3d2aece09086a748b7bcfd10f73e3cf8b31f0cc44da059c69aba5bc8efad45d3f376af3a0de6e169878bd842e28798e4743f843844bcdf8506f136391ec8e721dc2b6282d9c50fab653a6abf28947420e8c22a9a487d76a938933b34e497da95394176b2774c09ef0bb1ed8c3b131a21957b31a0b47cbfbff0533caf33125221db6ba4a518864892cf21d3d4d58b599a37a08f344aa7ef98e7d7d9d3316a6b115d9b8f20f93bc6865734699eb54c888d7e5a0acafd1915352b294243712cfe82f85248b00045cf3d090c0c00d7ca0e3a1f147703fd94f717e49c81a7c3a76946e20a63f3b7c3eaba9225abe0b34cb0cf235063967d16bc8a69c130cce287615cc053114167eac4e95bbabdfbbcf96bc0c0d65ea000aeaf490d723955bd1b4d69154d262f6a6d3534bb0bc397c29ecc6b1447b75c953af441de2e7133a7ac98988a7ef9e6ee63558aaada0603bd529776f05558d2df5641c412e7347440f65eb823afc7ccae6b97108b857287a0486dbbe689d770ca92471309e73ad390abf56912b2b7c49242cec157bdbbd493553735cb1d9b40afc214da153359c9df576135901c2fda58c0095b6fce3fd0731df34863af2882d53773ce7c182473722aa79a6b37d3eddde38fa71df8c0edc081efed8ce606e48299180ec6fe35fab649910c48a6a29f9d0f85557e10bc5ae2ecf028ae399f55cd7976028935cc03c0cafd5003c9eaed247fbe30a284cc4470a5525a6498e1dbbd3085c3f9d77c6064d0181bc5a829561560aa9a4ea8173d7937a9428109cb3a66b2b3de11f88f55ab21eb49b77a39762ca9264e0156566765e2d3626b72b80bd1411e4ec53552828a24bc8cdc47f465fddf4772c7bc02066854011287f739aba6047596747f4234ae227dbffabf0e13153e2e069f0b790251be877fe5a198e808258639f5e79d3d5cd16f1a573724dd6a9f6990c4502334dc66f65493490673ab30dca7c031f0c212c0d8bc9d0c874b319a97ad1ce9395d3d154203156c51cc3b9cb13d0ba1bdf618bc8eeca9ddd9412050cfa09235727aa50d46f79ad6f3c5a1bb6b284c8311dcf93756859704df8fc3bb8d2f5e094e04502354942e9c852b208d4901834332ebc603270cb57ed418c34ce48aa";
    let pk = Bytes::from_slice(hex::decode(DILITHIUM5_KAT_PK).unwrap().as_slice()).unwrap();
    let key = Dilithium5PublicKey { pk };
    test_de(
        "a3010703385820590a201c0ee1111b08003f28e65e8b3bdeb037cf8f221dfcdaf5950edb38d506d85bef032369a2ce572fd08bfc304b4848e78d752d77e97a28b99b9bb6fb5c7c6337514b321ecdc1fb669f26d4171ab42b72720ee70e0519a6e1d3d6d9914ec1b21cde38b41aac1d3abee6f2b7495c4c820c1fc0cc9e71e24cfb5c9c0d8eef4264af484fae4d6e5dde65d4df72b61c6dbd26f861a5e0b853ac5413226febbaba5eb474c6fb25a82678ea1606b452a23112221017b8c073c10378f9145641a8c078c0ed9e421650f748892522ab9fb7d1ff8cf1cc71b8566e8da33cd7361770c044349ac440cccdc6bbe35e6c55782766f38e688bf47821037299e344ecdeca17ad5d15cd27a4f7b070661138ede8ed72a8959c5ae36b1c46094a53cb21a7a42673f1401c2b259494090e2f53d7ee7063431ee5858002d850af909c3783436010f7ea88625a36a0f0189fde75b7e8c7e4b19d8527008328adbc929bbc86e964cfc48b8cf1da5d7ed3333ab55c15072832214a779a5fd10cc04005f46c1aa8884a161992472fd535b95ed18bde1c6d8ce678d2817d69f90571103e8520e7313ce7b930c5ebfaf2f4ec758b626b5543a068cde0fd0e94e6a64475b23268bf0380d075508f85128ca26f31a90c4a7d28440d54d4066b404588588b4ccf850b975c73afe68cbcd102755f61eb3e60323c576e529ec0bf23bfa5bea39cb73c37e8395d8dbd4c8dc8ab2f70a0bfc3a78c0d413f08d14d632bc0403b0383dbbb22bd9b113c89452aeab11210097947feaaa3c9f05d1d300c33a55e3fbc81259e862705c3a13b9ee35f6b23ed10f4edea9519fa91b7bcd0d501b5ed57d9049fab91aa779c725ff8e9f78017ea7807fa254b7105e826d096c01adae2c5d138251a92a478a33373f4de912b83b6fb4b0d0de6bc1118bb2fcfb07bd227a5f7f991439a13de1238180cdc55119e65c418584d807a926e4a9c0f70155ee196fb07656d9aa7982b8795dbad43d1059ca7f580d3320c0438a5ed5a7032b2e959678410f11ad98be8826a44262615645d759a862b2ac52d3b014a25e8473f1f1ea4cfa819930ab3a34d710deee70ca13e88fd71aa064e6cb4697de0e463b1370a6a3bfe98fdfe7b5471ff8df6a6879fbef9afb3519d780757d67440ac36e837bac3833eeaa980bd82b7936436a0307d164b6438869ae606e980518e913d0ee302396ef4eb25d9866e4bafa101e5992931361c4a982253d58abe3bd57107635a46f09512085f4ada08ec8b1b3910b0153b2aafcae5033edd4153248dcd85b02c9a25d8bdc4068bb85741726297a25aec55c44aa28059b71bb9f34067887ade4c1ca4908b19b3d78123453876db4dceb42773069572cd8777e62cfbaf7203f020f281a6678f790720eaa20e34327d7a63688b09a01f4d7088f7b5059eddeb45c0ce39321c79521d79a59ecdd468ced0ea82ca484928702f57d6fc18d347af3ed22aaf45abb0f20bab9e01557607ae3ed9cf0e26d34d305449669ec6fc1beceadce183f7a594cea196d059a1e550e547866cc087333f030e628f2cf1147925410ed0421dc7506138b1d19099c695e1afdace4153825b66a8ecf55a021d21eb9f848fe55c21769a755fa9807ef73a6c5ba15a06347d3f1c5c619a315598629106ac0b86ae0d8e55578292517258ae85f72e737af5638d096b76a3c57f1b9c80e770a2d4ea4e42fe469ad421285241960a8a86355ef22f583fe3bacadf8da31d5c2de254161bc6d10f9841dd27ed462a6b94b6deea90cbab687fb84b56395da763ab4b7fe3095d572d77eff3ff0d8f9d19aa5af7b676053dbef64e61dd0a41d402318e3308669106259bf7a4ce31b346a9e983edaba05180149ab057f9972977da7c6f46e0cdf86f3091f04fd4e83c6022e18ce4382b54d5daba82e4df1e53bf31fe4bb65a8524eda83fd29d07e49747b75291cbc8f8ee1415ec921e19022ade2c047e4df3507289e9d79a8e6992b48b8864204a416b769cc787d6df4407e93d121f7fbee0e408963e0609a9c75cb3117ca583df6e79f31c635bf0f1be98df550727a45d3ca337d79de5dcdb0b91cabbc30d7ef0ae1ca1e94904f78c1fd8fba87545fdc174ad8190f9b5ed7b5869494ffa91033fdc6117bf662ec5f2af2634ba3f8c02210f1c9bcdda9bb39760e00f25a7270c345666fb6df85c919aa150ca7fc80fc0eacfe242ef55f4298063628e61056c966db9964428d9ce99108271e29a12328e23999734e036f18a0eb8f030e88062c56717e7a36314e44ecf357ff56eedf90d3fb11b22a1b25905b379fcca5ca1acb956e178ad3f51d535ad119813b1e70f7317651bc75cac64276bb98110b54ea0ef34541d73910721d657387677e332e9c8811c3fc1b923b2ee9c512f6d09df372a5f97fad7123389cee197b5c269e221d7eed3160a521e56ff8aafab686179d09d78fc387b3ea6a672034d24ac7999d196b2316475f37db8e9ed431df58341fa88003d3c6489e78053d8e44ce7e16aef416859b3d2aece09086a748b7bcfd10f73e3cf8b31f0cc44da059c69aba5bc8efad45d3f376af3a0de6e169878bd842e28798e4743f843844bcdf8506f136391ec8e721dc2b6282d9c50fab653a6abf28947420e8c22a9a487d76a938933b34e497da95394176b2774c09ef0bb1ed8c3b131a21957b31a0b47cbfbff0533caf33125221db6ba4a518864892cf21d3d4d58b599a37a08f344aa7ef98e7d7d9d3316a6b115d9b8f20f93bc6865734699eb54c888d7e5a0acafd1915352b294243712cfe82f85248b00045cf3d090c0c00d7ca0e3a1f147703fd94f717e49c81a7c3a76946e20a63f3b7c3eaba9225abe0b34cb0cf235063967d16bc8a69c130cce287615cc053114167eac4e95bbabdfbbcf96bc0c0d65ea000aeaf490d723955bd1b4d69154d262f6a6d3534bb0bc397c29ecc6b1447b75c953af441de2e7133a7ac98988a7ef9e6ee63558aaada0603bd529776f05558d2df5641c412e7347440f65eb823afc7ccae6b97108b857287a0486dbbe689d770ca92471309e73ad390abf56912b2b7c49242cec157bdbbd493553735cb1d9b40afc214da153359c9df576135901c2fda58c0095b6fce3fd0731df34863af2882d53773ce7c182473722aa79a6b37d3eddde38fa71df8c0edc081efed8ce606e48299180ec6fe35fab649910c48a6a29f9d0f85557e10bc5ae2ecf028ae399f55cd7976028935cc03c0cafd5003c9eaed247fbe30a284cc4470a5525a6498e1dbbd3085c3f9d77c6064d0181bc5a829561560aa9a4ea8173d7937a9428109cb3a66b2b3de11f88f55ab21eb49b77a39762ca9264e0156566765e2d3626b72b80bd1411e4ec53552828a24bc8cdc47f465fddf4772c7bc02066854011287f739aba6047596747f4234ae227dbffabf0e13153e2e069f0b790251be877fe5a198e808258639f5e79d3d5cd16f1a573724dd6a9f6990c4502334dc66f65493490673ab30dca7c031f0c212c0d8bc9d0c874b319a97ad1ce9395d3d154203156c51cc3b9cb13d0ba1bdf618bc8eeca9ddd9412050cfa09235727aa50d46f79ad6f3c5a1bb6b284c8311dcf93756859704df8fc3bb8d2f5e094e04502354942e9c852b208d4901834332ebc603270cb57ed418c34ce48aa",
        key,
    );
}

quickcheck::quickcheck! {
    fn serde_p256(x: EcInput, y: EcInput) -> bool {
        test_serde(P256PublicKey {
            x: x.0,
            y: y.0,
        })
    }

    fn serde_ecdh(x: EcInput, y: EcInput) -> bool {
        test_serde(EcdhEsHkdf256PublicKey {
            x: x.0,
            y: y.0,
        })
    }

    fn serde_ed25519(x: EcInput) -> bool {
        test_serde(Ed25519PublicKey {
            x: x.0,
        })
    }

    #[cfg(feature="backend-dilithium2")]
    fn serde_dilithium2(pk: Dilithium2Input) -> bool {
        test_serde(Dilithium2PublicKey {
            pk: pk.0,
        })
    }

    #[cfg(feature="backend-dilithium3")]
    fn serde_dilithium3(pk: Dilithium3Input) -> bool {
        test_serde(Dilithium3PublicKey {
            pk: pk.0,
        })
    }

    #[cfg(feature="backend-dilithium5")]
    fn serde_dilithium5(pk: Dilithium5Input) -> bool {
        test_serde(Dilithium5PublicKey {
            pk: pk.0,
        })
    }

    fn de_order_p256(x: EcInput, y: EcInput) -> bool {
        test_de_order(P256PublicKey {
            x: x.0,
            y: y.0,
        })
    }

    fn de_order_ecdh(x: EcInput, y: EcInput) -> bool {
        test_de_order(EcdhEsHkdf256PublicKey {
            x: x.0,
            y: y.0,
        })
    }

    fn de_order_ed25519(x: EcInput) -> bool {
        test_de_order(Ed25519PublicKey {
            x: x.0,
        })
    }

    #[cfg(feature="backend-dilithium2")]
    fn de_order_dilithium2(pk: Dilithium2Input) -> bool {
        test_de_order(Dilithium2PublicKey {
            pk: pk.0,
        })
    }

    #[cfg(feature="backend-dilithium3")]
    fn de_order_dilithium3(pk: Dilithium3Input) -> bool {
        test_de_order(Dilithium3PublicKey {
            pk: pk.0,
        })
    }

    #[cfg(feature="backend-dilithium5")]
    fn de_order_dilithium5(pk: Dilithium5Input) -> bool {
        test_de_order(Dilithium5PublicKey {
            pk: pk.0,
        })
    }

    fn de_alg_p256(x: EcInput, y: EcInput, alg: Option<i8>) -> bool {
        test_de_alg(P256PublicKey {
            x: x.0,
            y: y.0,
        }, alg)
    }

    fn de_alg_ecdh(x: EcInput, y: EcInput, alg: Option<i8>) -> bool {
        test_de_alg(EcdhEsHkdf256PublicKey {
            x: x.0,
            y: y.0,
        }, alg)
    }

    fn de_alg_ed25519(x: EcInput, alg: Option<i8>) -> bool {
        test_de_alg(Ed25519PublicKey {
            x: x.0,
        }, alg)
    }

    #[cfg(feature="backend-dilithium2")]
    fn de_alg_dilithium2(pk: Dilithium2Input, alg: Option<i8>) -> bool {
        test_de_alg(Dilithium2PublicKey {
            pk: pk.0,
        }, alg)
    }

    #[cfg(feature="backend-dilithium3")]
    fn de_alg_dilithium3(pk: Dilithium3Input, alg: Option<i8>) -> bool {
        test_de_alg(Dilithium3PublicKey {
            pk: pk.0,
        }, alg)
    }

    #[cfg(feature="backend-dilithium5")]
    fn de_alg_dilithium5(pk: Dilithium5Input, alg: Option<i8>) -> bool {
        test_de_alg(Dilithium5PublicKey {
            pk: pk.0,
        }, alg)
    }
}
