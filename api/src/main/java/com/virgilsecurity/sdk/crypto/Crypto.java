/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.virgilsecurity.sdk.crypto;

import java.io.InputStream;
import java.io.OutputStream;

import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.DecryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.EncryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.SigningException;
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException;

/**
 * This interface describes generic Crypto functionality.
 *
 * @author Andrii Iakovenko
 *
 */
public interface Crypto {

    /**
     * Calculate fingerprint.
     * 
     * @param content
     *            The data to calculate fingerprint for.
     * @return the fingerprint as {@code String}.
     */
    Fingerprint calculateFingerprint(byte[] content);

    /**
     * Compute data hash with algorithm specified.
     * 
     * @param data
     *            the data for hashing.
     * @param algorithm
     *            the algorithm to be used for hash calculation.
     * @return the hash code.
     */
    byte[] computeHash(byte[] data, HashAlgorithm algorithm);

    /**
     * Decrypt byte array with private key.
     * 
     * @param data
     *            the data to be decrypted.
     * @param privateKey
     *            the recipients private key.
     * @return the decrypted data as byte array.
     * @throws DecryptionException
     */
    byte[] decrypt(byte[] data, PrivateKey privateKey) throws DecryptionException;

    /**
     * Decrypt stream data with private key.
     * 
     * @param inputStream
     *            the input stream to be decrypted.
     * @param outputStream
     *            the decrypted data as stream.
     * @param privateKey
     *            the recipients private key.
     * @throws DecryptionException
     * 
     * @see PublicKey
     * @see PrivateKey
     */
    void decrypt(InputStream inputStream, OutputStream outputStream, PrivateKey privateKey) throws DecryptionException;

    /**
     * Encrypt byte array for single recipient.
     * 
     * @param data
     *            the data to be encrypted.
     * @param recipient
     *            the recipient's public key.
     * @return the encrypted data as byte array.
     * @throws EncryptionException
     * 
     * @see PublicKey
     */
    byte[] encrypt(byte[] data, PublicKey recipient) throws EncryptionException;

    /**
     * Encrypt byte array with public key set.
     * 
     * @param data
     *            the data to be encrypted.
     * @param recipients
     *            the recipients public key set.
     * @return the encrypted data as byte array.
     * @throws EncryptionException
     * 
     * @see PublicKey
     */
    byte[] encrypt(byte[] data, PublicKey[] recipients) throws EncryptionException;

    /**
     * Encrypt stream data with public key.
     * 
     * @param inputStream
     *            the input stream to be encrypted.
     * @param outputStream
     *            the output stream encrypted data written to.
     * @param recipient
     *            the recipient's public key.
     * @throws EncryptionException
     *             if encryption failed.
     */
    void encrypt(InputStream inputStream, OutputStream outputStream, PublicKey recipient) throws EncryptionException;

    /**
     * Encrypt stream data with public key set.
     * 
     * @param inputStream
     *            the input stream to be encrypted.
     * @param outputStream
     *            the output stream encrypted data written to.
     * @param recipients
     *            the recipients public key set.
     * @throws EncryptionException
     *             if encryption failed.
     */
    void encrypt(InputStream inputStream, OutputStream outputStream, PublicKey[] recipients) throws EncryptionException;

    /**
     * Export private key as byte array.
     * 
     * @param privateKey
     *            the private key.
     * @return the exported private key as byte array.
     * 
     * @see PrivateKey
     */
    byte[] exportPrivateKey(PrivateKey privateKey);

    /**
     * Export private key as byte array.
     * 
     * @param privateKey
     *            the private key.
     * @param password
     *            the private key password.
     * @return the exported private key as byte array.
     * 
     * @see PrivateKey
     */

    byte[] exportPrivateKey(PrivateKey privateKey, String password);

    /**
     * Export public key as byte array.
     * 
     * @param publicKey
     *            the public key.
     * @return the exported public key as byte array.
     * 
     * @see PublicKey
     */

    byte[] exportPublicKey(PublicKey publicKey);

    /**
     * Extract public key from private key.
     * 
     * @param privateKey
     *            the private key.
     * @return the extracted public key.
     */
    PublicKey extractPublicKey(PrivateKey privateKey);

    /**
     * Generate key pair.
     * 
     * @return the generated key pair.
     * 
     * @see PrivateKey
     * @see PublicKey
     */
    KeyPair generateKeys();

    /**
     * Import private key from byte array.
     * 
     * @param keyData
     *            the Base64 encoded private key.
     * @return the private key.
     * @throws CryptoException
     *             if private key couldn't be imported.
     * 
     * @see PrivateKey
     */
    PrivateKey importPrivateKey(byte[] keyData) throws CryptoException;

    /**
     * Import private key from byte array.
     * 
     * @param keyData
     *            the Base64 encoded private key.
     * @param password
     *            the private key password.
     * @return the private key.
     * @throws CryptoException
     *             if private key couldn't be imported.
     * 
     * @see PrivateKey
     */
    PrivateKey importPrivateKey(byte[] keyData, String password) throws CryptoException;

    /**
     * Import public key from byte array.
     * 
     * @param publicKey
     *            the public key.
     * @return the public key.
     * 
     * @see PublicKey
     */
    PublicKey importPublicKey(byte[] publicKey);

    /**
     * Sign byte array data with private key.
     * 
     * @param data
     *            the data to be signed.
     * @param privateKey
     *            the signer's private key.
     * @return the signature.
     * 
     * @see PrivateKey
     */
    byte[] generateSignature(byte[] data, PrivateKey privateKey);

    /**
     * Sign stream data with private key.
     * 
     * @param inputStream
     *            the input stream to be signed.
     * @param privateKey
     *            the signer's private key.
     * @return the signature.
     * @throws SigningException
     *             if stream couldn't be signed.
     * 
     * @see PrivateKey
     */
    byte[] generateStreamSignature(InputStream inputStream, PrivateKey privateKey) throws SigningException;

    /**
     * Verify byte array with signature.
     * 
     * @param data
     *            the data to be verified.
     * @param signature
     *            the signature.
     * @param signer
     *            the signer's public key.
     * @return {@code true} if signature is valid. {@code false} in other case.
     * @throws VerificationException
     *             if data couldn't be verified.
     */
    boolean verifySignature(byte[] data, byte[] signature, PublicKey signer) throws VerificationException;

    /**
     * Verify stream data with signature.
     * 
     * @param inputStream
     *            the input stream to be verified.
     * @param signature
     *            the signature.
     * @param signer
     *            the signer's public key.
     * @return {@code true} if signature is valid. {@code false} in other case.
     * @throws VerificationException
     *             if data couldn't be verified.
     */
    boolean verifyStreamSignature(InputStream inputStream, byte[] signature, PublicKey signer) throws VerificationException;

    /**
     * Sign data and encrypt.
     * 
     * @param data
     *            the data to be signed and encrypted.
     * @param privateKey
     *            the private key used for signing.
     * @param recipient
     *            the recipient's public key.
     * @return the signed and encrypted data.
     * @throws CryptoException
     */
    byte[] signThenEncrypt(byte[] data, PrivateKey privateKey, PublicKey recipient) throws CryptoException;

    /**
     * Sign data and encrypt.
     * 
     * @param data
     *            the data to be signed and encrypted.
     * @param privateKey
     *            the private key used for signing.
     * @param recipients
     *            the recipient public keys.
     * @return the signed and encrypted data.
     * @throws CryptoException
     */
    byte[] signThenEncrypt(byte[] data, PrivateKey privateKey, PublicKey[] recipients) throws CryptoException;

    /**
     * Decrypt data and verifySignature.
     * 
     * @param cipherData
     *            the encrypted data to be decrypted.
     * @param privateKey
     *            the private key used for decryption.
     * @param publicKey
     *            the public key used for verifySignature.
     * @return the decrypted data.
     * @throws CryptoException
     */
    byte[] decryptThenVerify(byte[] cipherData, PrivateKey privateKey, PublicKey publicKey) throws CryptoException;
}
