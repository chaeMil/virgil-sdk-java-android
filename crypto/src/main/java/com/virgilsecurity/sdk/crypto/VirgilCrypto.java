/*
 * Copyright (c) 2015-2019, Virgil Security, Inc.
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

import com.virgilsecurity.crypto.foundation.PrivateKey;
import com.virgilsecurity.crypto.foundation.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.DecryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.EncryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.SignatureIsNotValidException;
import com.virgilsecurity.sdk.crypto.exceptions.SigningException;
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * The Virgil's implementation of Crypto.
 *
 * @author Andrii Iakovenko
 * 
 * @see VirgilPublicKey
 * @see VirgilPrivateKey
 *
 */
public class VirgilCrypto {

  private static final Charset UTF8_CHARSET = StandardCharsets.UTF_8;
  public static final byte[] CUSTOM_PARAM_SIGNATURE = "VIRGIL-DATA-SIGNATURE"
      .getBytes(UTF8_CHARSET);
  public static final byte[] CUSTOM_PARAM_SIGNER_ID = "VIRGIL-DATA-SIGNER-ID"
      .getBytes(UTF8_CHARSET);
  private static final String ERROR_PARSE_TEXT = "Error code: ";
  private static final int ERROR_CODE_WRONG_PRIVATE_KEY = 12;

  private Random rng;
  private KeysType defaultKeyType;
  private boolean useSHA256Fingerprints;

  /**
   * Create new instance of {@link VirgilCrypto}.
   */
  public VirgilCrypto() {
    this(false);
  }

  /**
   * Create new instance of {@link VirgilCrypto}.
   *
   * @param useSHA256Fingerprints set this flag to {@code true} to use SHA256 algorithm when
   *                              calculating public key identifier.
   */
  public VirgilCrypto(boolean useSHA256Fingerprints) {
    CtrDrbg rng = new CtrDrbg();
    rng.setupDefaults();

    this.rng = rng;
    this.defaultKeyType = KeysType.ED25519;
    this.useSHA256Fingerprints = useSHA256Fingerprints;
  }

  /**
   * Create new instance of {@link VirgilCrypto}.
   *
   * @param keysType the {@link KeysType} to be used by default for generating key pair.
   */
  public VirgilCrypto(KeysType keysType) {
    CtrDrbg rng = new CtrDrbg();
    rng.setupDefaults();

    this.defaultKeyType = keysType;
    this.useSHA256Fingerprints = false;
  }

  /**
   * Create new instance of {@link VirgilCrypto}.
   *
   * @param keysType              the {@link KeysType} to be used by default for generating key pair.
   * @param useSHA256Fingerprints set this flag to {@code true} to use SHA256 algorithm when
   *                              calculating public key identifier.
   */
  public VirgilCrypto(KeysType keysType, boolean useSHA256Fingerprints) {
    CtrDrbg rng = new CtrDrbg();
    rng.setupDefaults();

    this.defaultKeyType = keysType;
    this.useSHA256Fingerprints = useSHA256Fingerprints;
  }

  /**
   * Computes hash of given {@code data} with {@link HashAlgorithm#SHA512}.
   *
   * @param data data to be hashed.
   *
   * @return hash value.
   */
  public byte[] computeHash(byte[] data) {
    return computeHash(data, HashAlgorithm.SHA512);
  }

  /**
   * Computes hash of given {@code data} according to {@code algorithm}.
   *
   * @param data      data to be hashed.
   * @param algorithm hash {@link HashAlgorithm} to use.
   *
   * @return hash value.
   */
  public byte[] computeHash(byte[] data, HashAlgorithm algorithm) {
    Hash hash;

    switch (algorithm) {
      case SHA224:
        hash = new Sha224();
        break;
      case SHA256:
        hash = new Sha256();
        break;
      case SHA384:
        hash = new Sha384();
        break;
      case SHA512:
        hash = new Sha512();
        break;
      default:
        throw new IllegalArgumentException("Please, choose one of: SHA224, SHA256, SHA384, SHA512");
    }

    return hash.hash(data);
  }

  /**
   * Encrypts the specified data using recipient's Public key. // TODO review methods docs for uppercase letters in the beginning.
   *
   * @param data      Raw data bytes for encryption.
   * @param publicKey Recipient's public key.
   *
   * @return Encrypted bytes.
   *
   * @throws EncryptionException If encryption failed.
   */
  public byte[] encrypt(byte[] data, VirgilPublicKey publicKey) throws EncryptionException {
    return encrypt(data, Collections.singletonList(publicKey));
  }

  /**
   * Encrypts the specified data using recipients Public keys.
   *
   * @param data       Raw data bytes for encryption.
   * @param publicKeys List of recipients' public keys.
   *
   * @return Encrypted bytes.
   *
   * @throws EncryptionException If encryption failed.
   */
  public byte[] encrypt(byte[] data, List<VirgilPublicKey> publicKeys) throws EncryptionException {
    try (RecipientCipher cipher = new RecipientCipher()) {
      Aes256Gcm aesGcm = new Aes256Gcm();
      cipher.setEncryptionCipher(aesGcm);
      cipher.setRandom(this.rng);

      for (VirgilPublicKey recipient : publicKeys) {
        cipher.addKeyRecipient(recipient.getIdentifier(), recipient.getPublicKey());
      }
      cipher.startEncryption();
      byte[] messageInfo = cipher.packMessageInfo();
      byte[] process = cipher.processDecryption(data);
      byte[] finish = cipher.finishDecryption();

      byte[] encryptedData = new byte[messageInfo.length + process.length + finish.length];
      System.arraycopy(messageInfo, 0, encryptedData, 0, messageInfo.length);
      System.arraycopy(process, 0, encryptedData, messageInfo.length, process.length);
      System.arraycopy(finish,
                       0,
                       encryptedData,
                       messageInfo.length + process.length,
                       finish.length);

      return encryptedData;
    } catch (Exception e) {
      throw new EncryptionException(e);
    }
  }

  /**
   * Encrypts the specified stream using recipients Public keys.
   *
   * @param inputStream  Input stream for encrypted.
   * @param outputStream Output stream for encrypted data.
   * @param publicKeys   List of recipients' public keys.
   *
   * @throws EncryptionException if encryption failed
   */
  public void encrypt(InputStream inputStream, OutputStream outputStream,
                      List<VirgilPublicKey> publicKeys) throws EncryptionException {
    try (VirgilStreamCipher cipher = new VirgilStreamCipher();
         VirgilDataSource dataSource = new VirgilStreamDataSource(inputStream);
         VirgilDataSink dataSink = new VirgilStreamDataSink(outputStream)) {
      for (VirgilPublicKey recipient : publicKeys) {
        cipher.addKeyRecipient(recipient.getIdentifier(), recipient.getRawKey());
      }

      cipher.encrypt(dataSource, dataSink, true);
    } catch (IOException e) {
      throw new EncryptionException(e);
    }
  }

  /**
   * Encrypts the specified stream using recipient's Public key.
   *
   * @param inputStream  Input stream for encrypted.
   * @param outputStream Output stream for encrypted data.
   * @param publicKey    Recipient's public key.
   *
   * @throws EncryptionException if encryption failed
   */
  public void encrypt(InputStream inputStream, OutputStream outputStream, VirgilPublicKey publicKey)
      throws EncryptionException {
    encrypt(inputStream, outputStream, Collections.singletonList(publicKey));
  }

  /**
   * Decrypts the specified data using Private key.
   *
   * @param cipherData
   *          the ncrypted data bytes to decrypt
   * @param privateKey
   *          the private key used for decryption
   * @return Decrypted data bytes.
   * @throws DecryptionException
   *           if decryption failed
   */
  public byte[] decrypt(byte[] cipherData, PrivateKey privateKey) throws DecryptionException {
    try (RecipientCipher cipher = new RecipientCipher()) {
      cipher.customParams();

      byte[] decryptedData = cipher.startDecryptionWithKey(cipherData, privateKey.getIdentifier(),
                                                           privateKey.getRawKey());
      return decryptedData;
    } catch (Exception exception) {
      // Trying to get code from crypto exception or rethrow provided `exception`.
      processErrorCode(exception);
    }
  }

  /**
   * Decrypts the specified stream using Private key.
   *
   * @param inputStream
   *          Encrypted stream for decryption.
   * @param outputStream
   *          Output stream for decrypted data.
   * @param privateKey
   *          Private key for decryption.
   * @throws DecryptionException
   *           if decryption failed
   */
  public void decrypt(InputStream inputStream, OutputStream outputStream,
      VirgilPrivateKey privateKey) throws DecryptionException {
    try (VirgilStreamCipher cipher = new VirgilStreamCipher();
        VirgilDataSource dataSource = new VirgilStreamDataSource(inputStream);
        VirgilDataSink dataSink = new VirgilStreamDataSink(outputStream)) {

      cipher.decryptWithKey(dataSource, dataSink, privateKey.getIdentifier(),
          privateKey.getRawKey());
    } catch (IOException exception) {
      // Trying to get code from crypto exception or rethrow provided `exception`.
      processErrorCode(exception);
    }
  }

  /**
   * Decrypts and verifies the data.
   *
   * @param cipherData
   *          The cipher data.
   * @param privateKey
   *          The Private key to decrypt.
   * @param publicKeys
   *          The list of trusted public keys for verification, which can contain signer's public
   *          key
   * @return The decrypted data.
   * @throws CryptoException
   *           if decryption or verification failed
   */
  public byte[] decryptThenVerify(byte[] cipherData, VirgilPrivateKey privateKey,
      List<VirgilPublicKey> publicKeys) throws CryptoException {
    try (VirgilSigner signer = new VirgilSigner(VirgilHash.Algorithm.SHA512);
        VirgilCipher cipher = new VirgilCipher()) {
      byte[] decryptedData = cipher.decryptWithKey(cipherData, privateKey.getIdentifier(),
          privateKey.getRawKey());
      byte[] signature = cipher.customParams().getData(CUSTOM_PARAM_SIGNATURE);

      VirgilPublicKey signerPublicKey = null;
      if (publicKeys != null) {
        byte[] signerId = cipher.customParams().getData(CUSTOM_PARAM_SIGNER_ID);
        for (VirgilPublicKey publicKey : publicKeys) {
          if (Arrays.equals(signerId, publicKey.getIdentifier())) {
            signerPublicKey = publicKey;
            break;
          }
        }
      }
      if (signerPublicKey == null) {
        throw new SignatureIsNotValidException();
      }

      boolean isValid = signer.verify(decryptedData, signature, signerPublicKey.getRawKey());
      if (!isValid) {
        throw new SignatureIsNotValidException();
      }

      return decryptedData;
    } catch (Exception exception) {
      // Trying to get code from crypto exception or rethrow provided `exception`.
      processErrorCode(exception);
    }
  }

  /**
   * Temporary workaround till we find other places where error usage is needed.
   * Extract code from crypto exception and throw corresponding exception with message,
   * or rethrow provided {@code exception}.
   *
   * @param exception to extract code from.
   *
   * @throws DecryptionException with default *error message* if *error message* is {@code null}
   * or extraction failed, otherwise custom message for exception is being generated depending
   * on extracted erro code.
   */
  private void processErrorCode(Exception exception) throws DecryptionException {
    String errorMessage = exception.getMessage();

    if (errorMessage != null) {
      int errorCode;

      try {
        // If we're unable to extract code - just forward exception
        errorCode = Integer.parseInt(errorMessage.substring(
            errorMessage.indexOf(ERROR_PARSE_TEXT) + ERROR_PARSE_TEXT.length(),
            errorMessage.indexOf('.', errorMessage.indexOf(ERROR_PARSE_TEXT)
                + ERROR_PARSE_TEXT.length())));
      } catch (Throwable throwable) {
        throw new DecryptionException(exception);
      }

      if (errorCode == ERROR_CODE_WRONG_PRIVATE_KEY) {
        throw new DecryptionException("Given Private key does not corresponds to any of "
                                          + "Public keys that were used for encryption.");
      } else {
        throw new DecryptionException(exception);
      }
    } else {
      throw new DecryptionException(exception);
    }
  }

  /**
   * Exports the Private key into material representation.
   *
   * @param privateKey
   *          The private key for export.
   * @return Key material representation bytes.
   * @throws CryptoException
   *           if key couldn't be exported
   */
  public byte[] exportPrivateKey(VirgilPrivateKey privateKey) throws CryptoException {
    return exportPrivateKey(privateKey, null);
  }

  /**
   * Exports the Private key into material representation.
   * 
   * @param privateKey
   *          The private key for export.
   * @param password
   *          The password.
   * @return Key material representation bytes.
   * @throws CryptoException
   *           if key couldn't be exported
   */
  public byte[] exportPrivateKey(VirgilPrivateKey privateKey, String password)
      throws CryptoException {
    try {
      if (password == null) {
        return VirgilKeyPair.privateKeyToDER(privateKey.getRawKey());
      }
      byte[] passwordBytes = password.getBytes(UTF8_CHARSET);
      byte[] encryptedKey = VirgilKeyPair.encryptPrivateKey(privateKey.getRawKey(), passwordBytes);

      return VirgilKeyPair.privateKeyToDER(encryptedKey, passwordBytes);
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Exports the Public key into material representation.
   * 
   * @param publicKey
   *          Public key for export.
   * @return Key material representation bytes.
   * @throws CryptoException
   *           if key couldn't be exported
   */
  public byte[] exportPublicKey(VirgilPublicKey publicKey) throws CryptoException {
    try {
      return VirgilKeyPair.publicKeyToDER(publicKey.getRawKey());
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Extract public key from private key.
   *
   * @param keyData
   *          the private key.
   * @return the extracted public key.
   */
  public VirgilPublicKey extractPublicKey(VirgilPrivateKey keyData) {
    return extractPublicKey(keyData, null);
  }

  /**
   * Extract public key from private key.
   *
   * @param keyData
   *          the private key.
   * @param password
   *          the password
   * @return the extracted public key.
   */
  public VirgilPublicKey extractPublicKey(VirgilPrivateKey keyData, String password) {
    if (keyData == null) {
      throw new NullArgumentException("keyData");
    }

    if (password != null && password.isEmpty()) {
      throw new IllegalArgumentException("VirgilCrypto -> 'password' should not be empty");
    }

    byte[] publicKeyData;
    if (password == null) {
      publicKeyData = VirgilKeyPair.extractPublicKey(keyData.getRawKey(), new byte[0]);
    } else {
      publicKeyData = VirgilKeyPair.extractPublicKey(keyData.getRawKey(),
          password.getBytes(UTF8_CHARSET));
    }

    byte[] receiverId = keyData.getIdentifier();
    byte[] value = VirgilKeyPair.publicKeyToDER(publicKeyData);

    return new VirgilPublicKey(receiverId, value);
  }

  /**
   * @param data
   *          the data
   * @return the generated hash
   * @throws CryptoException
   *           if crypto hash operation failed
   */
  public byte[] generateHash(byte[] data) throws CryptoException {
    if (useSHA256Fingerprints) {
      return generateHash(data, HashAlgorithm.SHA256);
    }
    return generateHash(data, HashAlgorithm.SHA512);
  }

  /**
   * Computes the hash of specified data.
   * 
   * @param data
   *          the data
   * @param algorithm
   *          the hash algorithm
   * @return the computed hash
   * @throws CryptoException
   *           if crypto hash operation failed
   */
  public byte[] generateHash(byte[] data, HashAlgorithm algorithm) throws CryptoException {
    if (data == null) {
      throw new NullArgumentException("data");
    }

    try (VirgilHash hasher = computeHash(algorithm)) {
      return hasher.hash(data);
    } catch (Exception e) {
      throw new CryptoException(e.getMessage());
    }
  }

  /**
   * Generates asymmetric key pair that is comprised of both public and private keys.
   * 
   * @return Generated key pair.
   * @throws CryptoException
   *           if crypto operation failed
   */
  public com.virgilsecurity.sdk.crypto.VirgilKeyPair generateKeys() throws CryptoException {
    return generateKeys(this.defaultKeyType);
  }

  /**
   * Generates asymmetric key pair that is comprised of both public and private keys by specified
   * type.
   * 
   * @param keysType
   *          Type of the generated keys. The possible values can be found in {@link KeysType}.
   * @return Generated key pair.
   * @throws CryptoException
   *           if crypto operation failed
   */
  public com.virgilsecurity.sdk.crypto.VirgilKeyPair generateKeys(KeysType keysType)
      throws CryptoException {
    VirgilKeyPair keyPair = VirgilKeyPair.generate(toVirgilKeyPairType(keysType));

    return wrapKeyPair(keyPair.privateKey(), keyPair.publicKey());
  }

  /**
   * Signs the specified data using Private key.
   * 
   * @param data
   *          the raw data bytes for signing
   * @param privateKey
   *          the private key for signing
   * @return the calculated signature data
   * @throws SigningException
   *           if crypto sign operation failed
   */
  public byte[] generateSignature(byte[] data, VirgilPrivateKey privateKey)
      throws SigningException {
    if (data == null) {
      throw new NullArgumentException("data");
    }

    if (privateKey == null) {
      throw new NullArgumentException("privateKey");
    }

    try (VirgilSigner signer = new VirgilSigner(VirgilHash.Algorithm.SHA512)) {
      return signer.sign(data, privateKey.getRawKey());
    } catch (Exception e) {
      throw new SigningException(e.getMessage());
    }
  }

  /**
   * Signs the specified stream using Private key.
   * 
   * @param stream
   *          the stream for signing
   * @param privateKey
   *          the private key for signing
   * @return the calculated signature data
   * @throws SigningException
   *           if crypto sign operation failed
   */
  public byte[] generateSignature(InputStream stream, VirgilPrivateKey privateKey)
      throws SigningException {
    if (stream == null) {
      throw new NullArgumentException("stream");
    }

    if (privateKey == null) {
      throw new NullArgumentException("privateKey");
    }

    try (VirgilStreamSigner signer = new VirgilStreamSigner(VirgilHash.Algorithm.SHA512);
        VirgilDataSource dataSource = new VirgilStreamDataSource(stream)) {
      byte[] signature = signer.sign(dataSource, privateKey.getRawKey());
      return signature;
    } catch (IOException e) {
      throw new SigningException(e);
    }
  }

  /**
   * Imports the Private key from material representation.
   *
   * @param keyData
   *          the private key material representation bytes
   * @return imported private key
   * @throws CryptoException
   *           if key couldn't be imported
   */
  public VirgilPrivateKey importPrivateKey(byte[] keyData) throws CryptoException {
    return importPrivateKey(keyData, null);
  }

  /**
   * Imports the Private key from material representation.
   * 
   * @param keyData
   *          the private key material representation bytes
   * @param password
   *          the private key password
   * @return imported private key
   * @throws CryptoException
   *           if key couldn't be imported
   */
  public VirgilPrivateKey importPrivateKey(byte[] keyData, String password) throws CryptoException {
    if (keyData == null) {
      throw new NullArgumentException("keyData");
    }

    try {
      byte[] privateKeyBytes;
      if (password == null) {
        privateKeyBytes = VirgilKeyPair.privateKeyToDER(keyData);
      } else {
        privateKeyBytes = VirgilKeyPair.decryptPrivateKey(keyData, password.getBytes(UTF8_CHARSET));
      }

      byte[] publicKey = VirgilKeyPair.extractPublicKey(privateKeyBytes, new byte[] {});

      byte[] receiverId = computePublicKeyHash(publicKey);
      byte[] value = VirgilKeyPair.privateKeyToDER(privateKeyBytes);

      return new VirgilPrivateKey(receiverId, value);
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Imports the Public key from material representation.
   * 
   * @param keyData
   *          the public key material representation bytes
   * @return an imported public key
   * @throws CryptoException
   *           if key couldn't be imported
   */
  public VirgilPublicKey importPublicKey(byte[] keyData) throws CryptoException {
    if (keyData == null) {
      throw new NullArgumentException("keyData");
    }
    try {
      byte[] receiverId = computePublicKeyHash(keyData);
      byte[] value = VirgilKeyPair.publicKeyToDER(keyData);

      return new VirgilPublicKey(receiverId, value);
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * @return the useSHA256Fingerprints
   */
  public boolean isUseSHA256Fingerprints() {
    return useSHA256Fingerprints;
  }

  /**
   * @param useSHA256Fingerprints
   *          the useSHA256Fingerprints to set
   */
  public void setUseSHA256Fingerprints(boolean useSHA256Fingerprints) {
    this.useSHA256Fingerprints = useSHA256Fingerprints;
  }

  /**
   * Signs and encrypts the data.
   * 
   * @param data
   *          The data to encrypt.
   * @param privateKey
   *          The Private key to sign the data.
   * @param publicKeys
   *          The list of Public key recipients to encrypt the data.
   * @return Signed and encrypted data bytes.
   * @throws CryptoException
   *           if crypto sing or encrypt operation failed
   */
  public byte[] signThenEncrypt(byte[] data, VirgilPrivateKey privateKey,
      List<VirgilPublicKey> publicKeys) throws CryptoException {
    try (VirgilSigner signer = new VirgilSigner(VirgilHash.Algorithm.SHA512);
        VirgilCipher cipher = new VirgilCipher()) {

      byte[] signature = signer.sign(data, privateKey.getRawKey());

      VirgilCustomParams customData = cipher.customParams();
      customData.setData(CUSTOM_PARAM_SIGNATURE, signature);
      customData.setData(CUSTOM_PARAM_SIGNER_ID, privateKey.getIdentifier());

      for (VirgilPublicKey publicKey : publicKeys) {
        cipher.addKeyRecipient(publicKey.getIdentifier(), publicKey.getRawKey());
      }
      return cipher.encrypt(data, true);

    } catch (Exception e) {
      throw new CryptoException(e.getMessage());
    }
  }

  /**
   * Signs and encrypts the data.
   * 
   * @param data
   *          The data to encrypt.
   * @param privateKey
   *          The Private key to sign the data.
   * @param publicKey
   *          The recipient's Public key to encrypt the data.
   * @return Signed and encrypted data bytes.
   * @throws CryptoException
   *           if crypto sing or encrypt operation failed
   */
  public byte[] signThenEncrypt(byte[] data, VirgilPrivateKey privateKey, VirgilPublicKey publicKey)
      throws CryptoException {
    return signThenEncrypt(data, privateKey, Arrays.asList(publicKey));
  }

  /**
   * Verifies the specified signature using original data and signer's Public key.
   * 
   * @param signature
   *          Signature bytes for verification.
   * @param data
   *          Original data bytes for verification.
   * @param publicKey
   *          Signer's public key for verification.
   * @return {@code true} if signature is valid, {@code false} otherwise.
   * @throws VerificationException
   *           if crypto sing operation failed
   */
  public boolean verifySignature(byte[] signature, byte[] data, VirgilPublicKey publicKey)
      throws VerificationException {
    if (data == null) {
      throw new NullArgumentException("data");
    }
    if (signature == null) {
      throw new NullArgumentException("signature");
    }
    if (publicKey == null) {
      throw new NullArgumentException("publicKey");
    }

    try (VirgilSigner virgilSigner = new VirgilSigner(VirgilHash.Algorithm.SHA512)) {
      boolean valid = virgilSigner.verify(data, signature, publicKey.getRawKey());
      return valid;
    } catch (Exception e) {
      throw new VerificationException(e);
    }
  }

  /**
   * Verifies the specified signature using original stream and signer's Public key.
   * 
   * @param signature
   *          Signature bytes for verification.
   * @param stream
   *          Original stream for verification.
   * @param publicKey
   *          Signer's public key for verification.
   * @return {@code true} if signature is valid, {@code false} otherwise.
   * @throws VerificationException
   *           if crypto verify operation failed
   */
  public boolean verifySignature(byte[] signature, InputStream stream, VirgilPublicKey publicKey)
      throws VerificationException {
    if (stream == null) {
      throw new NullArgumentException("stream");
    }
    if (signature == null) {
      throw new NullArgumentException("signature");
    }
    if (publicKey == null) {
      throw new NullArgumentException("publicKey");
    }

    try (VirgilStreamSigner virgilSigner = new VirgilStreamSigner(VirgilHash.Algorithm.SHA512);
        VirgilDataSource dataSource = new VirgilStreamDataSource(stream)) {
      boolean valid = virgilSigner.verify(dataSource, signature, publicKey.getRawKey());
      return valid;
    } catch (Exception e) {
      throw new VerificationException(e);
    }
  }

  /**
   * Wrap key pair with {@link com.virgilsecurity.sdk.crypto.VirgilKeyPair}.
   * 
   * @param privateKey
   *          the private key data.
   * @param publicKey
   *          the public key data.
   * @return wrapped key pair.
   * @throws CryptoException
   *           if crypto operation failed.
   */
  public com.virgilsecurity.sdk.crypto.VirgilKeyPair wrapKeyPair(byte[] privateKey,
      byte[] publicKey) throws CryptoException {
    byte[] keyPairId = this.computePublicKeyHash(publicKey);

    VirgilPublicKey virgilPublicKey = new VirgilPublicKey(keyPairId,
        VirgilKeyPair.publicKeyToDER(publicKey));
    VirgilPrivateKey virgilPrivateKey = new VirgilPrivateKey(keyPairId,
        VirgilKeyPair.privateKeyToDER(privateKey));

    return new com.virgilsecurity.sdk.crypto.VirgilKeyPair(virgilPublicKey, virgilPrivateKey);
  }

  private byte[] computePublicKeyHash(byte[] publicKey) throws CryptoException {
    byte[] publicKeyDer = VirgilKeyPair.publicKeyToDER(publicKey);
    try {
      byte[] hash;
      if (useSHA256Fingerprints) {
        hash = this.generateHash(publicKeyDer, HashAlgorithm.SHA256);
      } else {
        hash = this.generateHash(publicKeyDer, HashAlgorithm.SHA512);
        hash = Arrays.copyOfRange(hash, 0, 8);
      }
      return hash;
    } catch (Exception e) {
      // This should never happen
      throw new CryptoException(e);
    }
  }

}
