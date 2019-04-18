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
 * @see VirgilPublicKey
 * @see VirgilPrivateKey
 */
public class VirgilCrypto {

  private static final Charset UTF8_CHARSET = StandardCharsets.UTF_8;
  private static final byte[] CUSTOM_PARAM_SIGNATURE = "VIRGIL-DATA-SIGNATURE"
      .getBytes(UTF8_CHARSET);
  private static final byte[] CUSTOM_PARAM_SIGNER_ID = "VIRGIL-DATA-SIGNER-ID"
      .getBytes(UTF8_CHARSET);
  private static final String ERROR_PARSE_TEXT = "Error code: ";
  private static final int ERROR_CODE_WRONG_PRIVATE_KEY = 12;
  private static final int CHUNK_SIZE = 1024;

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
   * Generates asymmetric key pair that is comprised of both public and private keys.
   *
   * @return Generated key pair.
   *
   * @throws CryptoException if crypto operation failed
   */
  public com.virgilsecurity.sdk.crypto.VirgilKeyPair generateKeys() throws CryptoException {
    return generateKeys(this.defaultKeyType);
  }

  /**
   * Generates asymmetric key pair that is comprised of both public and private keys by specified
   * type.
   *
   * @param keysType Type of the generated keys. The possible values can be found in {@link KeysType}.
   *
   * @return Generated key pair.
   *
   * @throws CryptoException if crypto operation failed
   */
  public com.virgilsecurity.sdk.crypto.VirgilKeyPair generateKeys(KeysType keysType)
      throws CryptoException {
    VirgilKeyPair keyPair = VirgilKeyPair.generate(toVirgilKeyPairType(keysType));

    return wrapKeyPair(keyPair.privateKey(), keyPair.publicKey());
  }

  /**
   * Encrypts data for passed PublicKey. // TODO review methods docs for uppercase letters in the beginning.
   * <p><p>
   * 1. Generates random AES-256 KEY1<p>
   * 2. Encrypts data with KEY1 using AES-256-GCM<p>
   * 3. Generates ephemeral key pair for each recipient<p>
   * 4. Uses Diffie-Hellman to obtain shared secret with each recipient's public key & each
   *    ephemeral private key<p>
   * 5. Computes KDF to obtain AES-256 key from shared secret for each recipient<p>
   * 6. Encrypts KEY1 with this key using AES-256-CBC for each recipient
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
   * Encrypts data for passed PublicKeys.
   * <p><p>
   * 1. Generates random AES-256 KEY1<p>
   * 2. Encrypts data with KEY1 using AES-256-GCM<p>
   * 3. Generates ephemeral key pair for each recipient<p>
   * 4. Uses Diffie-Hellman to obtain shared secret with each recipient's public key & each
   *    ephemeral private key<p>
   * 5. Computes KDF to obtain AES-256 key from shared secret for each recipient<p>
   * 6. Encrypts KEY1 with this key using AES-256-CBC for each recipient
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

      return encryptData(data, cipher);
    } catch (Exception e) {
      throw new EncryptionException(e);
    }
  }

  /**
   * Encrypts the specified stream using recipient's Public key.
   * <p><p>
   * 1. Generates random AES-256 KEY1<p>
   * 2. Encrypts data with KEY1 using AES-256-GCM<p>
   * 3. Generates ephemeral key pair for each recipient<p>
   * 4. Uses Diffie-Hellman to obtain shared secret with each recipient's public key & each
   *    ephemeral private key<p>
   * 5. Computes KDF to obtain AES-256 key from shared secret for each recipient<p>
   * 6. Encrypts KEY1 with this key using AES-256-CBC for each recipient
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
   * Encrypts data stream for passed PublicKeys.
   * <p><p>
   * 1. Generates random AES-256 KEY1<p>
   * 2. Encrypts data with KEY1 using AES-256-GCM<p>
   * 3. Generates ephemeral key pair for each recipient<p>
   * 4. Uses Diffie-Hellman to obtain shared secret with each recipient's public key & each
   *    ephemeral private key<p>
   * 5. Computes KDF to obtain AES-256 key from shared secret for each recipient<p>
   * 6. Encrypts KEY1 with this key using AES-256-CBC for each recipient
   *
   * @param inputStream  Input stream to be encrypted.
   * @param outputStream Output stream for encrypted data.
   * @param publicKeys   List of recipients' public keys.
   *
   * @throws EncryptionException if encryption failed
   */
  public void encrypt(InputStream inputStream, OutputStream outputStream,
                      List<VirgilPublicKey> publicKeys) throws EncryptionException {
    try (RecipientCipher cipher = new RecipientCipher()) {
      Aes256Gcm aesGcm = new Aes256Gcm();
      cipher.setEncryptionCipher(aesGcm);
      cipher.setRandom(rng);

      for (VirgilPublicKey recipient : publicKeys) {
        cipher.addKeyRecipient(recipient.getIdentifier(), recipient.getPublicKey());
      }

      cipher.startEncryption();
      byte[] messageInfo = cipher.packMessageInfo();

      outputStream.write(messageInfo);

      byte[] dataChunk = new byte[CHUNK_SIZE];

      while (inputStream.read(dataChunk) != -1) {
        cipher.processEncryption(dataChunk);
        outputStream.write(dataChunk);
      }

      byte[] finish = cipher.finishEncryption();
      outputStream.write(finish);
    } catch (IOException e) {
      throw new EncryptionException(e);
    }
  }

  /**
   * Signs and encrypts the data.
   *
   * @param data       The data to encrypt.
   * @param privateKey The Private key to sign the data.
   * @param publicKey  The recipient's Public key to encrypt the data.
   *
   * @return Signed and encrypted data bytes.
   *
   * @throws CryptoException if crypto sing or encrypt operation failed
   */
  public byte[] signThenEncrypt(byte[] data, VirgilPrivateKey privateKey, VirgilPublicKey publicKey)
      throws CryptoException {
    return signThenEncrypt(data, privateKey, Collections.singletonList(publicKey));
  }

  /**
   * Signs (with Private key) Then Encrypts data for passed PublicKeys.
   * <p><p>
   * 1. Generates signature depending on KeyType<p>
   * 2. Generates random AES-256 KEY1<p>
   * 3. Encrypts both data and signature with KEY1 using AES-256-GCM<p>
   * 4. Generates ephemeral key pair for each recipient<p>
   * 5. Uses Diffie-Hellman to obtain shared secret with each recipient's public key & each ephemeral private key<p>
   * 6. Computes KDF to obtain AES-256 key from shared secret for each recipient<p>
   * 7. Encrypts KEY1 with this key using AES-256-CBC for each recipient
   *
   * @param data       The data to encrypt.
   * @param privateKey The Private key to sign the data.
   * @param publicKeys The list of Public key recipients to encrypt the data.
   *
   * @return Signed and encrypted data bytes.
   *
   * @throws CryptoException If crypto sing or encrypt operation failed.
   */
  public byte[] signThenEncrypt(byte[] data,
                                VirgilPrivateKey privateKey,
                                List<VirgilPublicKey> publicKeys) throws CryptoException {
    try (RecipientCipher cipher = new RecipientCipher()) {
      byte[] signature = generateSignature(data, privateKey);
      Aes256Gcm aesGcm = new Aes256Gcm();
      cipher.setEncryptionCipher(aesGcm);
      cipher.setRandom(rng);

      for (VirgilPublicKey publicKey : publicKeys) {
        cipher.addKeyRecipient(publicKey.getIdentifier(), publicKey.getPublicKey());
      }

      cipher.customParams().addData(CUSTOM_PARAM_SIGNATURE, signature);
      cipher.customParams().addData(CUSTOM_PARAM_SIGNER_ID, privateKey.getIdentifier());

      return encryptData(data, cipher);

    } catch (Exception e) {
      throw new CryptoException(e.getMessage());
    }
  }

  /**
   * Encrypts data using provided {@link RecipientCipher}.
   *
   * @param data   Data to encrypt.
   * @param cipher To encrypt provided data.
   *
   * @return Encrypted data.
   */
  private byte[] encryptData(byte[] data, RecipientCipher cipher) {
    cipher.startEncryption();

    byte[] messageInfo = cipher.packMessageInfo();
    byte[] processEncryption = cipher.processEncryption(data);
    byte[] finish = cipher.finishEncryption();

    return concatenate(concatenate(messageInfo, processEncryption), finish);
  }

  /**
   * Decrypts data using passed PrivateKey.
   * <p><p>
   * 1. Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key & recipient's
   * private key<p>
   * 2. Computes KDF to obtain AES-256 KEY2 from shared secret<p>
   * 3. Decrypts KEY1 using AES-256-CBC<p>
   * 4. Decrypts data using KEY1 and AES-256-GCM
   *
   * @param data       The encrypted data bytes to decrypt.
   * @param privateKey The private key used for decryption.
   *
   * @return Decrypted data bytes.
   *
   * @throws DecryptionException If decryption failed.
   */
  public byte[] decrypt(byte[] data, VirgilPrivateKey privateKey) throws DecryptionException {
    try (RecipientCipher cipher = new RecipientCipher()) {

      cipher.startDecryptionWithKey(privateKey.getIdentifier(),
                                    privateKey.getPrivateKey(),
                                    new byte[0]);

      byte[] processDecryption = cipher.processDecryption(data);
      byte[] finish = cipher.finishEncryption();

      return concatenate(processDecryption, finish);
    } catch (Exception exception) {
      // Trying to get code from crypto exception or rethrow provided `exception`.
      throw new DecryptionException(processErrorCode(exception));
    }
  }

  /**
   * Decrypts the specified stream using Private key.
   *
   * @param inputStream  Encrypted stream for decryption.
   * @param outputStream Output stream for decrypted data.
   * @param privateKey   Private key for decryption.
   *
   * @throws DecryptionException if decryption failed
   */
  public void decrypt(InputStream inputStream, OutputStream outputStream,
                      VirgilPrivateKey privateKey) throws DecryptionException {
    try (RecipientCipher cipher = new RecipientCipher()) {
      cipher.startDecryptionWithKey(privateKey.getIdentifier(),
                                    privateKey.getPrivateKey(),
                                    new byte[0]);

      byte[] dataChunk = new byte[CHUNK_SIZE];

      while (inputStream.read(dataChunk) != -1) {
        cipher.processDecryption(dataChunk);
        outputStream.write(dataChunk);
      }

      byte[] finish = cipher.finishDecryption();
      outputStream.write(finish);
    } catch (IOException exception) {
      // Trying to get code from crypto exception or rethrow provided `exception`.
      throw new DecryptionException(processErrorCode(exception));
    }
  }


  /**
   * Decrypts (with private key) Then Verifies data using signers PublicKey.
   *
   * @param data             Signed Then Encrypted data.
   * @param privateKey       Receiver's private key.
   * @param signersPublicKey Signer's public keys.
   *                         WARNING: Data should have signature of ANY public key from array.
   *
   * @return Decrypted then verified data.
   *
   * @throws CryptoException if decryption or verification failed.
   */
  public byte[] decryptThenVerify(byte[] data,
                                  VirgilPrivateKey privateKey,
                                  VirgilPublicKey signersPublicKey) throws CryptoException {
    return decryptThenVerify(data, privateKey, Collections.singletonList(signersPublicKey));
  }

  /**
   * Decrypts (with private key) Then Verifies data using any of signers' PublicKeys.
   *
   * @param data              Signed Then Encrypted data.
   * @param privateKey        Receiver's private key.
   * @param signersPublicKeys The list of possible signers' public keys.
   *                          WARNING: Data should have signature of ANY public key from array.
   *
   * @return Decrypted then verified data.
   *
   * @throws CryptoException if decryption or verification failed.
   */
  public byte[] decryptThenVerify(byte[] data,
                                  VirgilPrivateKey privateKey,
                                  List<VirgilPublicKey> signersPublicKeys) throws CryptoException {
    try (RecipientCipher cipher = new RecipientCipher()) {
      cipher.startDecryptionWithKey(privateKey.getIdentifier(),
                                    privateKey.getPrivateKey(),
                                    new byte[0]);

      byte[] processDecryption = cipher.processDecryption(data);
      byte[] finish = cipher.finishDecryption();

      byte[] decryptedData = concatenate(processDecryption, finish);

      VirgilPublicKey signerPublicKey = null;

      if (signersPublicKeys.size() == 1) {
        signerPublicKey = signersPublicKeys.get(0);
      } else {
        byte[] signerId;
        try {
          signerId = cipher.customParams().findData(CUSTOM_PARAM_SIGNER_ID);
        } catch (Throwable throwable) {
          throw new CryptoException("Signer not found");
        }

        for (VirgilPublicKey publicKey : signersPublicKeys) {
          if (Arrays.equals(publicKey.getIdentifier(), signerId)) {
            signerPublicKey = publicKey;
            break;
          }
        }
        if (signerPublicKey == null) {
          throw new CryptoException("Signer not found");
        }
      }

      byte[] signature;

      try {
        signature = cipher.customParams().findData(CUSTOM_PARAM_SIGNATURE);
      } catch (Throwable throwable) {
        throw new CryptoException("Signature not found");
      }

      boolean isValid = verifySignature(signature, decryptedData, signerPublicKey);
      if (!isValid) {
        throw new SignatureIsNotValidException();
      }

      return decryptedData;
    } catch (Exception exception) {
      // Trying to get code from crypto exception or rethrow provided `exception`.
      throw new DecryptionException(processErrorCode(exception));
    }
  }

  /**
   * Temporary workaround till we find other places where error usage is needed.
   * Extract code from crypto exception and throw corresponding exception with message,
   * or rethrow provided {@code exception}.
   *
   * @param exception to extract code from.
   *
   * @return default *error message* if *error message* is {@code null} or extraction failed,
   *         otherwise custom message for exception is being generated depending on extracted
   *         error code.
   */
  private String processErrorCode(Exception exception) {
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
        return exception.getMessage();
      }

      if (errorCode == ERROR_CODE_WRONG_PRIVATE_KEY) {
        return "Given Private key does not corresponds to any of "
            + "Public keys that were used for encryption.";
      } else {
        return exception.getMessage();
      }
    } else {
      return exception.getMessage();
    }
  }

  /**
   * Generates digital signature of data using Private key.
   * <p><p>
   * - Note: Returned value contains only digital signature, not data itself
   * <p>
   * - Note: Data inside this function is guaranteed to be hashed with SHA512 at least one time.
   * It's secure to pass raw data here
   * <p>
   * - Note: Verification algorithm depends on Private Key type. Default: EdDSA for ed25519 key.
   *
   * @param data       Data to sign.
   * @param privateKey Private key used to generate signature.
   *
   * @return The calculated signature data.
   *
   * @throws SigningException If crypto sign operation failed.
   */
  public byte[] generateSignature(byte[] data,
                                  VirgilPrivateKey privateKey) throws SigningException {
    if (data == null) {
      throw new NullArgumentException("data");
    }
    if (privateKey == null) {
      throw new NullArgumentException("privateKey");
    }

    SignHash signHash;
    if (privateKey.getPrivateKey() instanceof SignHash) {
      signHash = (SignHash) privateKey.getPrivateKey();
    } else {
      throw new SigningException("This key doesn\'t support signing");
    }

    try (Signer signer = new Signer()) {
      signer.setHash(new Sha512());

      signer.reset();
      signer.update(data);

      return signer.sign(signHash);
    } catch (Exception e) {
      throw new SigningException(e.getMessage());
    }
  }

  /**
   * Generates digital signature of data stream using Private key.
   * <p><p>
   * - Note: Returned value contains only digital signature, not data itself.
   * <p>
   * - Note: Data inside this function is guaranteed to be hashed with SHA512 at least one time.
   * It's secure to pass raw data here.
   *
   * @param stream     Data stream to sign
   * @param privateKey Private key used to generate signature
   *
   * @return The calculated digital signature data.
   *
   * @throws SigningException If crypto sign operation failed.
   */
  public byte[] generateSignature(InputStream stream, VirgilPrivateKey privateKey)
      throws SigningException {
    if (stream == null) {
      throw new NullArgumentException("stream");
    }
    if (privateKey == null) {
      throw new NullArgumentException("privateKey");
    }

    SignHash signHash;
    if (privateKey.getPrivateKey() instanceof SignHash) {
      signHash = (SignHash) privateKey.getPrivateKey();
    } else {
      throw new SigningException("This key doesn\'t support signing");
    }

    try (Signer signer = new Signer()) {
      signer.setHash(new Sha512());
      signer.reset();
      byte[] dataChunk = new byte[CHUNK_SIZE];

      while (stream.read(dataChunk) != -1) {
        signer.update(dataChunk);
      }

      return signer.sign(signHash);
    } catch (IOException e) {
      throw new SigningException(e);
    }
  }

  /**
   * Verifies digital signature of data.
   * <p><p>
   * - Note: Verification algorithm depends on PublicKey type. Default: EdDSA for ed25519 key.
   *
   * @param signature Digital signature.
   * @param data      Data that was signed.
   * @param publicKey Signer's public key for verification.
   *
   * @return {@code true} if signature is verified, {@code false} otherwise.
   *
   * @throws VerificationException If signature verification operation failed.
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

    VerifyHash verifyHash;
    if (publicKey.getPublicKey() instanceof VerifyHash) {
      verifyHash = (VerifyHash) publicKey.getPublicKey();
    } else {
      throw new VerificationException("This key doesn\'t support verification");
    }

    try (Verifier verifier = new Verifier()) {
      verifier.reset(signature);
      verifier.update(data);

      return verifier.verify(verifyHash);
    } catch (Exception e) {
      throw new VerificationException(e);
    }
  }

  /**
   * Verifies digital signature of data stream.
   * <p>
   * Note: Verification algorithm depends on PublicKey type. Default: EdDSA.
   *
   * @param signature Digital signature.
   * @param stream    Data stream that was signed.
   * @param publicKey Signed public key.
   *
   * @return {@code true} if signature is verified, {@code false} otherwise.
   *
   * @throws VerificationException If crypto verify operation failed.
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

    VerifyHash verifyHash;
    if (publicKey.getPublicKey() instanceof VerifyHash) {
      verifyHash = (VerifyHash) publicKey.getPublicKey();
    } else {
      throw new VerificationException("This key doesn\'t support verification");
    }

    try (Verifier verifier = new Verifier()) {
      verifier.reset(signature);

      byte[] dataChunk = new byte[CHUNK_SIZE]; // TODO check what will happen in situation when only 1 of 1024 bytes is left in last iteration.

      while (stream.read(dataChunk) != -1) {
        verifier.update(dataChunk);
      }

      return verifier.verify(verifyHash);
    } catch (Exception e) {
      throw new VerificationException(e);
    }
  }

  /**
   * Exports the Private key into material representation.
   *
   * @param privateKey The private key for export.
   *
   * @return Key material representation bytes.
   *
   * @throws CryptoException if key couldn't be exported
   */
  public byte[] exportPrivateKey(VirgilPrivateKey privateKey) throws CryptoException {
    return exportPrivateKey(privateKey, null);
  }

  /**
   * Exports the Private key into material representation.
   *
   * @param privateKey The private key for export.
   * @param password   The password.
   *
   * @return Key material representation bytes.
   *
   * @throws CryptoException if key couldn't be exported
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
   * Imports the Private key from material representation.
   *
   * @param keyData the private key material representation bytes
   *
   * @return imported private key
   *
   * @throws CryptoException if key couldn't be imported
   */
  public VirgilPrivateKey importPrivateKey(byte[] keyData) throws CryptoException {
    return importPrivateKey(keyData, null);
  }

  /**
   * Imports the Private key from material representation.
   *
   * @param keyData  the private key material representation bytes
   * @param password the private key password
   *
   * @return imported private key
   *
   * @throws CryptoException if key couldn't be imported
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

      byte[] publicKey = VirgilKeyPair.extractPublicKey(privateKeyBytes, new byte[]{});

      byte[] receiverId = computePublicKeyHash(publicKey);
      byte[] value = VirgilKeyPair.privateKeyToDER(privateKeyBytes);

      return new VirgilPrivateKey(receiverId, value);
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Exports the Public key into material representation.
   *
   * @param publicKey Public key for export.
   *
   * @return Key material representation bytes.
   *
   * @throws CryptoException if key couldn't be exported
   */
  public byte[] exportPublicKey(VirgilPublicKey publicKey) throws CryptoException {
    try {
      return VirgilKeyPair.publicKeyToDER(publicKey.getRawKey());
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  /**
   * Imports the Public key from material representation.
   *
   * @param keyData the public key material representation bytes
   *
   * @return an imported public key
   *
   * @throws CryptoException if key couldn't be imported
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
   * Extract public key from private key.
   *
   * @param keyData the private key.
   *
   * @return the extracted public key.
   */
  public VirgilPublicKey extractPublicKey(VirgilPrivateKey keyData) {
    return extractPublicKey(keyData, null);
  }

  /**
   * Extract public key from private key.
   *
   * @param keyData  the private key.
   * @param password the password
   *
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
   * @return the useSHA256Fingerprints
   */
  public boolean isUseSHA256Fingerprints() {
    return useSHA256Fingerprints;
  }

  /**
   * @param useSHA256Fingerprints the useSHA256Fingerprints to set
   */
  public void setUseSHA256Fingerprints(boolean useSHA256Fingerprints) {
    this.useSHA256Fingerprints = useSHA256Fingerprints;
  }

  /**
   * Wrap key pair with {@link com.virgilsecurity.sdk.crypto.VirgilKeyPair}.
   *
   * @param privateKey the private key data.
   * @param publicKey  the public key data.
   *
   * @return wrapped key pair.
   *
   * @throws CryptoException if crypto operation failed.
   */
  public com.virgilsecurity.sdk.crypto.VirgilKeyPair wrapKeyPair(byte[] privateKey,
                                                                 byte[] publicKey) throws CryptoException {
    byte[] keyPairId = this.computePublicKeyHash(publicKey);

    VirgilPublicKey virgilPublicKey = new VirgilPublicKey(keyPairId,
                                                          VirgilKeyPair.publicKeyToDER(publicKey));
    VirgilPrivateKey virgilPrivateKey = new VirgilPrivateKey(keyPairId,
                                                             VirgilKeyPair.privateKeyToDER(
                                                                 privateKey));

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

  /**
   * Concatenate two byte arrays.
   *
   * @param first  the first array.
   * @param second the second array.
   *
   * @return a byte array.
   */
  private byte[] concatenate(byte[] first, byte[] second) {
    byte[] result = new byte[first.length + second.length];
    System.arraycopy(first, 0, result, 0, first.length);
    System.arraycopy(second, 0, result, first.length, second.length);

    return result;
  }
}
