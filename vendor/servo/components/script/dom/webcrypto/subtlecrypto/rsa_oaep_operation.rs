/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use aws_lc_rs::rsa::{
    OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256, OAEP_SHA384_MGF1SHA384, OAEP_SHA512_MGF1SHA512,
    OaepPrivateDecryptingKey, OaepPublicEncryptingKey, PrivateDecryptingKey, PublicEncryptingKey,
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
    SubtleRsaHashedImportParams, SubtleRsaHashedKeyGenParams, SubtleRsaOaepParams,
};

/// <https://w3c.github.io/webcrypto/#rsa-oaep-operations-encrypt>
pub(crate) fn encrypt(
    normalized_algorithm: &SubtleRsaOaepParams,
    key: &CryptoKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    // Step 1. If the [[type]] internal slot of key is not "public", then throw an
    // InvalidAccessError.
    if key.Type() != KeyType::Public {
        return Err(Error::InvalidAccess(Some(
            "[[type]] internal slot of key is not \"public\"".to_string(),
        )));
    }

    // Step 2. Let label be the label member of normalizedAlgorithm or the empty byte sequence if
    // the label member of normalizedAlgorithm is not present.
    let label = normalized_algorithm.label.as_deref().unwrap_or_default();

    // Step 3. Perform the encryption operation defined in Section 7.1 of [RFC3447] with the key
    // represented by key as the recipient's RSA public key, plaintext as the message to be
    // encrypted, M and label as the label, L, and with the hash function specified by the hash
    // attribute of the [[algorithm]] internal slot of key as the Hash option and MGF1 (defined in
    // Section B.2.1 of [RFC3447]) as the MGF option.
    // Step 4. If performing the operation results in an error, then throw an OperationError.
    // Step 5. Let ciphertext be the value C that results from performing the operation.
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
    let public_key = PublicEncryptingKey::from_der(public_key.as_bytes())
        .map_err(|_| Error::Operation(Some("Failed to parse RSA public key".into())))?;
    let encryption_key = OaepPublicEncryptingKey::new(public_key)
        .map_err(|_| Error::Operation(Some("Failed to construct RSA-OAEP key".into())))?;
    let algorithm = match algorithm.hash.name() {
        CryptoAlgorithm::Sha1 => &OAEP_SHA1_MGF1SHA1,
        CryptoAlgorithm::Sha256 => &OAEP_SHA256_MGF1SHA256,
        CryptoAlgorithm::Sha384 => &OAEP_SHA384_MGF1SHA384,
        CryptoAlgorithm::Sha512 => &OAEP_SHA512_MGF1SHA512,
        algorithm_hash_name => {
            return Err(Error::Operation(Some(format!(
                "Unsupported hash for RSA-OAEP: {}",
                algorithm_hash_name.as_str()
            ))));
        },
    };
    let mut ciphertext = vec![0; encryption_key.ciphertext_size()];
    let label = (!label.is_empty()).then_some(label);
    let ciphertext = encryption_key
        .encrypt(algorithm, plaintext, &mut ciphertext, label)
        .map_err(|_| Error::Operation(Some("RSA-OAEP failed to encrypt plaintext".into())))?;

    // Step 6. Return ciphertext.
    Ok(ciphertext.to_vec())
}

/// <https://w3c.github.io/webcrypto/#rsa-oaep-operations-decrypt>
pub(crate) fn decrypt(
    normalized_algorithm: &SubtleRsaOaepParams,
    key: &CryptoKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    // Step 1. If the [[type]] internal slot of key is not "private", then throw an
    // InvalidAccessError.
    if key.Type() != KeyType::Private {
        return Err(Error::InvalidAccess(Some(
            "[[type]] internal slot of key is not \"private\"".to_string(),
        )));
    }

    // Step 2. Let label be the label member of normalizedAlgorithm or the empty byte sequence if
    // the label member of normalizedAlgorithm is not present.
    let label = normalized_algorithm.label.as_deref().unwrap_or_default();

    // Step 3. Perform the decryption operation defined in Section 7.1 of [RFC3447] with the key
    // represented by key as the recipient's RSA private key, ciphertext as the ciphertext to be
    // decrypted, C, and label as the label, L, and with the hash function specified by the hash
    // attribute of the [[algorithm]] internal slot of key as the Hash option and MGF1 (defined in
    // Section B.2.1 of [RFC3447]) as the MGF option.
    // Step 4. If performing the operation results in an error, then throw an OperationError.
    // Step 5. Let plaintext the value M that results from performing the operation.
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
    let private_key = PrivateDecryptingKey::from_pkcs8(private_key.as_bytes())
        .map_err(|_| Error::Operation(Some("Failed to parse RSA private key".into())))?;
    let decrypting_key = OaepPrivateDecryptingKey::new(private_key)
        .map_err(|_| Error::Operation(Some("Failed to construct RSA-OAEP key".into())))?;
    let algorithm = match algorithm.hash.name() {
        CryptoAlgorithm::Sha1 => &OAEP_SHA1_MGF1SHA1,
        CryptoAlgorithm::Sha256 => &OAEP_SHA256_MGF1SHA256,
        CryptoAlgorithm::Sha384 => &OAEP_SHA384_MGF1SHA384,
        CryptoAlgorithm::Sha512 => &OAEP_SHA512_MGF1SHA512,
        algorithm_hash_name => {
            return Err(Error::Operation(Some(format!(
                "Unsupported hash for RSA-OAEP: {}",
                algorithm_hash_name.as_str()
            ))));
        },
    };
    let mut plaintext = vec![0; decrypting_key.min_output_size()];
    let label = (!label.is_empty()).then_some(label);
    let plaintext = decrypting_key
        .decrypt(algorithm, ciphertext, &mut plaintext, label)
        .map_err(|_| Error::Operation(Some("RSA-OAEP failed to decrypt ciphertext".into())))?;

    // Step 6. Return plaintext.
    Ok(plaintext.to_vec())
}

/// <https://w3c.github.io/webcrypto/#rsa-oaep-operations-generate-key>
pub(crate) fn generate_key(
    cx: &mut JSContext,
    global: &GlobalScope,
    normalized_algorithm: &SubtleRsaHashedKeyGenParams,
    extractable: bool,
    usages: Vec<KeyUsage>,
) -> Result<CryptoKeyPair, Error> {
    rsa_common::generate_key(
        RsaAlgorithm::RsaOaep,
        cx,
        global,
        normalized_algorithm,
        extractable,
        usages,
    )
}

/// <https://w3c.github.io/webcrypto/#rsa-oaep-operations-import-key>
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
        RsaAlgorithm::RsaOaep,
        cx,
        global,
        normalized_algorithm,
        format,
        key_data,
        extractable,
        usages,
    )
}

/// <https://w3c.github.io/webcrypto/#rsa-oaep-operations-export-key>
pub(crate) fn export_key(format: KeyFormat, key: &CryptoKey) -> Result<ExportedKey, Error> {
    rsa_common::export_key(RsaAlgorithm::RsaOaep, format, key)
}

/// <https://wicg.github.io/webcrypto-modern-algos/#SubtleCrypto-method-getPublicKey>
/// Step 9 - 15, for RSA-OAEP
pub(crate) fn get_public_key(
    cx: &mut JSContext,
    global: &GlobalScope,
    key: &CryptoKey,
    algorithm: &KeyAlgorithmAndDerivatives,
    usages: Vec<KeyUsage>,
) -> Result<DomRoot<CryptoKey>, Error> {
    rsa_common::get_public_key(RsaAlgorithm::RsaOaep, cx, global, key, algorithm, usages)
}
