/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeyPair as RsaKeyPair;
use aws_lc_rs::signature::{
    RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512, RSA_PSS_SHA256,
    RSA_PSS_SHA384, RSA_PSS_SHA512, UnparsedPublicKey,
};
use js::context::JSContext;

use crate::dom::bindings::codegen::Bindings::CryptoKeyBinding::{
    CryptoKeyMethods, CryptoKeyPair, KeyType, KeyUsage,
};
use crate::dom::bindings::codegen::Bindings::SubtleCryptoBinding::KeyFormat;
use crate::dom::bindings::error::Error;
use crate::dom::bindings::root::DomRoot;
use crate::dom::cryptokey::{CryptoKey, Handle};
use crate::dom::globalscope::GlobalScope;
use crate::dom::subtlecrypto::rsa_common::{self, RsaAlgorithm};
use crate::dom::subtlecrypto::{
    CryptoAlgorithm, ExportedKey, KeyAlgorithmAndDerivatives, NormalizedAlgorithm,
    SubtleRsaHashedImportParams, SubtleRsaHashedKeyGenParams, SubtleRsaPssParams,
};

/// <https://w3c.github.io/webcrypto/#rsa-pss-operations-sign>
pub(crate) fn sign(
    normalized_algorithm: &SubtleRsaPssParams,
    key: &CryptoKey,
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    // Step 1. If the [[type]] internal slot of key is not "private", then throw an
    // InvalidAccessError.
    if key.Type() != KeyType::Private {
        return Err(Error::InvalidAccess(Some(
            "[[type]] internal slot of key is not \"private\"".to_string(),
        )));
    }

    // Step 2. Perform the signature generation operation defined in Section 8.1 of [RFC3447] with
    // the key represented by the [[handle]] internal slot of key as the signer's private key, K,
    // and message as the message to be signed, M, and using the hash function specified by the
    // hash attribute of the [[algorithm]] internal slot of key as the Hash option, MGF1 (defined
    // in Section B.2.1 of [RFC3447]) as the MGF option and the saltLength member of
    // normalizedAlgorithm as the salt length option for the EMSA-PSS-ENCODE operation.
    // Step 3. If performing the operation results in an error, then throw an OperationError.
    // Step 4. Let signature be the signature, S, that results from performing the operation.
    let Handle::RsaPrivateKey(private_key) = key.handle() else {
        return Err(Error::Operation(Some(
            "[[handle]] internal slot of key is not an RSA private key".to_string(),
        )));
    };
    let KeyAlgorithmAndDerivatives::RsaHashedKeyAlgorithm(algorithm) = key.algorithm() else {
        return Err(Error::Operation(Some(
            "[[algorithm]] internal slot of key is not an RsaHashedKeyAlgorithm".to_string(),
        )));
    };
    let rsa_key = RsaKeyPair::from_pkcs8(private_key.as_bytes())
        .map_err(|_| Error::Operation(Some("Failed to parse RSA private key".into())))?;
    let signature_algorithm = match algorithm.hash.name() {
        CryptoAlgorithm::Sha256 if normalized_algorithm.salt_length == 32 => &RSA_PSS_SHA256,
        CryptoAlgorithm::Sha384 if normalized_algorithm.salt_length == 48 => &RSA_PSS_SHA384,
        CryptoAlgorithm::Sha512 if normalized_algorithm.salt_length == 64 => &RSA_PSS_SHA512,
        CryptoAlgorithm::Sha1 => {
            return Err(Error::NotSupported(Some(
                "AWS-LC RSA-PSS does not expose SHA-1 in its safe API".into(),
            )));
        },
        algorithm_hash_name => {
            return Err(Error::NotSupported(Some(format!(
                "AWS-LC RSA-PSS requires a salt length equal to the digest size for {}",
                algorithm_hash_name.as_str()
            ))));
        },
    };
    let mut signature = vec![0; rsa_key.public_modulus_len()];
    rsa_key
        .sign(
            signature_algorithm,
            &SystemRandom::new(),
            message,
            &mut signature,
        )
        .map_err(|_| Error::Operation(Some("RSA-PSS failed to sign message".to_string())))?;

    // Step 5. Return signature.
    Ok(signature)
}

/// <https://w3c.github.io/webcrypto/#rsa-pss-operations-verify>
pub(crate) fn verify(
    normalized_algorithm: &SubtleRsaPssParams,
    key: &CryptoKey,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Error> {
    // Step 1. If the [[type]] internal slot of key is not "public", then throw an
    // InvalidAccessError.
    if key.Type() != KeyType::Public {
        return Err(Error::InvalidAccess(Some(
            "[[type]] internal slot of key is not \"public\"".to_string(),
        )));
    }

    // Step 2. Perform the signature verification operation defined in Section 8.1 of [RFC3447]
    // with the key represented by the [[handle]] internal slot of key as the signer's RSA public
    // key and message as M and signature as S and using the hash function specified by the hash
    // attribute of the [[algorithm]] internal slot of key as the Hash option, MGF1 (defined in
    // Section B.2.1 of [RFC3447]) as the MGF option and the saltLength member of
    // normalizedAlgorithm as the salt length option for the EMSA-PSS-VERIFY operation.
    // Step 3. Let result be a boolean with the value true if the result of the operation was
    // "valid signature" and the value false otherwise.
    let Handle::RsaPublicKey(public_key) = key.handle() else {
        return Err(Error::Operation(Some(
            "[[handle]] internal slot of key is not an RSA public key".to_string(),
        )));
    };
    let KeyAlgorithmAndDerivatives::RsaHashedKeyAlgorithm(algorithm) = key.algorithm() else {
        return Err(Error::Operation(Some(
            "[[algorithm]] internal slot of key is not an RsaHashedKeyAlgorithm".to_string(),
        )));
    };
    let verification_algorithm = match algorithm.hash.name() {
        CryptoAlgorithm::Sha256 if normalized_algorithm.salt_length == 32 => {
            &RSA_PSS_2048_8192_SHA256
        },
        CryptoAlgorithm::Sha384 if normalized_algorithm.salt_length == 48 => {
            &RSA_PSS_2048_8192_SHA384
        },
        CryptoAlgorithm::Sha512 if normalized_algorithm.salt_length == 64 => {
            &RSA_PSS_2048_8192_SHA512
        },
        CryptoAlgorithm::Sha1 => {
            return Err(Error::NotSupported(Some(
                "AWS-LC RSA-PSS does not expose SHA-1 in its safe API".into(),
            )));
        },
        _ => {
            return Err(Error::NotSupported(Some(format!(
                "AWS-LC RSA-PSS requires a salt length equal to the digest size for {}",
                algorithm.hash.name().as_str()
            ))));
        },
    };
    let result = UnparsedPublicKey::new(verification_algorithm, public_key.as_bytes())
        .verify(message, signature)
        .is_ok();

    // Step 4. Return result.
    Ok(result)
}

/// <https://w3c.github.io/webcrypto/#rsa-pss-operations-generate-key>
pub(crate) fn generate_key(
    cx: &mut JSContext,
    global: &GlobalScope,
    normalized_algorithm: &SubtleRsaHashedKeyGenParams,
    extractable: bool,
    usages: Vec<KeyUsage>,
) -> Result<CryptoKeyPair, Error> {
    rsa_common::generate_key(
        RsaAlgorithm::RsaPss,
        cx,
        global,
        normalized_algorithm,
        extractable,
        usages,
    )
}

/// <https://w3c.github.io/webcrypto/#rsa-pss-operations-import-key>
pub(crate) fn import_key(
    cx: &mut JSContext,
    global: &GlobalScope,
    normalized_algorithm: &SubtleRsaHashedImportParams,
    format: KeyFormat,
    key_data: &[u8],
    extractable: bool,
    usages: Vec<KeyUsage>,
) -> Result<DomRoot<CryptoKey>, Error> {
    rsa_common::import_key(
        RsaAlgorithm::RsaPss,
        cx,
        global,
        normalized_algorithm,
        format,
        key_data,
        extractable,
        usages,
    )
}

/// <https://w3c.github.io/webcrypto/#rsa-pss-operations-export-key>
pub(crate) fn export_key(format: KeyFormat, key: &CryptoKey) -> Result<ExportedKey, Error> {
    rsa_common::export_key(RsaAlgorithm::RsaPss, format, key)
}

/// <https://wicg.github.io/webcrypto-modern-algos/#SubtleCrypto-method-getPublicKey>
/// Step 9 - 15, for RSA-PSS
pub(crate) fn get_public_key(
    cx: &mut JSContext,
    global: &GlobalScope,
    key: &CryptoKey,
    algorithm: &KeyAlgorithmAndDerivatives,
    usages: Vec<KeyUsage>,
) -> Result<DomRoot<CryptoKey>, Error> {
    rsa_common::get_public_key(RsaAlgorithm::RsaPss, cx, global, key, algorithm, usages)
}
