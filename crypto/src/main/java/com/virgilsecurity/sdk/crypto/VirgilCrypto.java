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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;

import com.virgilsecurity.crypto.VirgilCipher;
import com.virgilsecurity.crypto.VirgilCustomParams;
import com.virgilsecurity.crypto.VirgilDataSink;
import com.virgilsecurity.crypto.VirgilDataSource;
import com.virgilsecurity.crypto.VirgilHash;
import com.virgilsecurity.crypto.VirgilHash.Algorithm;
import com.virgilsecurity.crypto.VirgilKeyPair;
import com.virgilsecurity.crypto.VirgilSigner;
import com.virgilsecurity.crypto.VirgilStreamCipher;
import com.virgilsecurity.crypto.VirgilStreamDataSink;
import com.virgilsecurity.crypto.VirgilStreamDataSource;
import com.virgilsecurity.crypto.VirgilStreamSigner;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.DecryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.EncryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.SignatureIsNotValidException;
import com.virgilsecurity.sdk.crypto.exceptions.SigningException;
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException;
import com.virgilsecurity.sdk.exception.NullArgumentException;

/**
 * The Virgil's implementation of Crypto.
 *
 * @author Andrii Iakovenko
 * 
 * @see Crypto
 * @see VirgilPublicKey
 * @see VirgilPrivateKey
 *
 */
public class VirgilCrypto {

    private static final Charset UTF8_CHARSET = Charset.forName("UTF-8");
    private static final byte[] CUSTOM_PARAM_SIGNATURE = "VIRGIL-DATA-SIGNATURE".getBytes(UTF8_CHARSET);
    private KeysType defaultKeyPairType;

    /**
     * Create new instance of {@link VirgilCrypto}.
     */
    public VirgilCrypto() {
        this.defaultKeyPairType = KeysType.Default;
    }

    /**
     * Create new instance of {@link VirgilCrypto}.
     * 
     * @param keysType
     */
    public VirgilCrypto(KeysType keysType) {
        this.defaultKeyPairType = keysType;
    }

    public static VirgilHash createVirgilHash(HashAlgorithm algorithm) {
        switch (algorithm) {
        case MD5:
            return new VirgilHash(VirgilHash.Algorithm.MD5);
        case SHA1:
            return new VirgilHash(VirgilHash.Algorithm.SHA1);
        case SHA224:
            return new VirgilHash(VirgilHash.Algorithm.SHA224);
        case SHA256:
            return new VirgilHash(VirgilHash.Algorithm.SHA256);
        case SHA384:
            return new VirgilHash(VirgilHash.Algorithm.SHA384);
        case SHA512:
            return new VirgilHash(VirgilHash.Algorithm.SHA512);
        default:
            throw new IllegalArgumentException();
        }
    }

    public static VirgilKeyPair.Type toVirgilKeyPairType(KeysType keysType) {
        switch (keysType) {
        case Default:
            return VirgilKeyPair.Type.FAST_EC_ED25519;
        case RSA_2048:
            return VirgilKeyPair.Type.RSA_2048;
        case RSA_3072:
            return VirgilKeyPair.Type.RSA_3072;
        case RSA_4096:
            return VirgilKeyPair.Type.RSA_4096;
        case RSA_8192:
            return VirgilKeyPair.Type.RSA_8192;
        case EC_SECP256R1:
            return VirgilKeyPair.Type.EC_SECP256R1;
        case EC_SECP384R1:
            return VirgilKeyPair.Type.EC_SECP384R1;
        case EC_SECP521R1:
            return VirgilKeyPair.Type.EC_SECP521R1;
        case EC_BP256R1:
            return VirgilKeyPair.Type.EC_BP256R1;
        case EC_BP384R1:
            return VirgilKeyPair.Type.EC_BP384R1;
        case EC_BP512R1:
            return VirgilKeyPair.Type.EC_BP512R1;
        case EC_SECP256K1:
            return VirgilKeyPair.Type.EC_SECP256K1;
        case EC_CURVE25519:
            return VirgilKeyPair.Type.EC_CURVE25519;
        case FAST_EC_X25519:
            return VirgilKeyPair.Type.FAST_EC_X25519;
        case FAST_EC_ED25519:
            return VirgilKeyPair.Type.FAST_EC_ED25519;
        }
        assert false; // This should never happen! Some key type missed.
        return VirgilKeyPair.Type.FAST_EC_ED25519;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#calculateFingerprint(byte[])
     */
    public Fingerprint calculateFingerprint(byte[] content) {
        if (content == null) {
            throw new NullArgumentException("content");
        }

        try (VirgilHash sha256 = new VirgilHash(Algorithm.SHA256)) {
            byte[] hash = sha256.hash(content);
            return new VirgilFingerprint(hash);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#generateHash(byte[], com.virgilsecurity.sdk.crypto.HashAlgorithm)
     */
    public byte[] generateHash(byte[] data, HashAlgorithm algorithm) {
        if (data == null) {
            throw new NullArgumentException("data");
        }

        try (VirgilHash hasher = createVirgilHash(algorithm)) {
            return hasher.hash(data);
        }
    }

    /**
     * @param publicKey
     * @return
     */
    private byte[] computePublicKeyHash(byte[] publicKey) {
        byte[] publicKeyDER = VirgilKeyPair.publicKeyToDER(publicKey);
        return this.generateHash(publicKeyDER, HashAlgorithm.SHA256);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#decrypt(byte[], com.virgilsecurity.sdk.crypto.VirgilPrivateKey)
     */
    public byte[] decrypt(byte[] cipherData, VirgilPrivateKey privateKey) throws DecryptionException {
        try (VirgilCipher cipher = new VirgilCipher()) {
            byte[] decryptedData = cipher.decryptWithKey(cipherData, privateKey.getIdentifier(), privateKey.getRawKey());
            return decryptedData;
        } catch (Exception e) {
            throw new DecryptionException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#decrypt(java.io.InputStream, java.io.OutputStream,
     * com.virgilsecurity.sdk.crypto.VirgilPrivateKey)
     */
    public void decrypt(InputStream inputStream, OutputStream outputStream, VirgilPrivateKey privateKey)
            throws DecryptionException {
        try (VirgilStreamCipher cipher = new VirgilStreamCipher();
                VirgilDataSource dataSource = new VirgilStreamDataSource(inputStream);
                VirgilDataSink dataSink = new VirgilStreamDataSink(outputStream)) {

            cipher.decryptWithKey(dataSource, dataSink, privateKey.getIdentifier(), privateKey.getRawKey());
        } catch (IOException e) {
            throw new DecryptionException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#decryptThenVerify(byte[], com.virgilsecurity.sdk.crypto.VirgilPrivateKey,
     * com.virgilsecurity.sdk.crypto.VirgilPublicKey)
     */
    public byte[] decryptThenVerify(byte[] cipherData, VirgilPrivateKey privateKey, VirgilPublicKey publicKey)
            throws CryptoException {
        try (VirgilSigner signer = new VirgilSigner(); VirgilCipher cipher = new VirgilCipher()) {
            byte[] decryptedData = cipher.decryptWithKey(cipherData, privateKey.getIdentifier(), privateKey.getRawKey());
            byte[] signature = cipher.customParams().getData(CUSTOM_PARAM_SIGNATURE);

            boolean isValid = signer.verify(decryptedData, signature, publicKey.getRawKey());
            if (!isValid) {
                throw new SignatureIsNotValidException();
            }

            return decryptedData;
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#encrypt(byte[], com.virgilsecurity.sdk.crypto.VirgilPublicKey)
     */
    public byte[] encrypt(byte[] data, VirgilPublicKey recipient) throws EncryptionException {
        try (VirgilCipher cipher = new VirgilCipher()) {
            cipher.addKeyRecipient(recipient.getIdentifier(), recipient.getRawKey());

            byte[] encryptedData = cipher.encrypt(data, true);
            return encryptedData;
        } catch (Exception e) {
            throw new EncryptionException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#encrypt(byte[], com.virgilsecurity.sdk.crypto.VirgilPublicKey[])
     */
    public byte[] encrypt(byte[] data, VirgilPublicKey[] recipients) throws EncryptionException {
        try (VirgilCipher cipher = new VirgilCipher()) {
            for (VirgilPublicKey recipient : recipients) {
                cipher.addKeyRecipient(recipient.getIdentifier(), recipient.getRawKey());
            }

            byte[] encryptedData = cipher.encrypt(data, true);
            return encryptedData;
        } catch (Exception e) {
            throw new EncryptionException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#encrypt(java.io.InputStream, java.io.OutputStream,
     * com.virgilsecurity.sdk.crypto.VirgilPublicKey)
     */
    public void encrypt(InputStream inputStream, OutputStream outputStream, VirgilPublicKey recipient)
            throws EncryptionException {
        try (VirgilStreamCipher cipher = new VirgilStreamCipher();
                VirgilDataSource dataSource = new VirgilStreamDataSource(inputStream);
                VirgilDataSink dataSink = new VirgilStreamDataSink(outputStream)) {

            cipher.addKeyRecipient(recipient.getIdentifier(), recipient.getRawKey());

            cipher.encrypt(dataSource, dataSink, true);
        } catch (IOException e) {
            throw new EncryptionException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#encrypt(java.io.InputStream, java.io.OutputStream,
     * com.virgilsecurity.sdk.crypto.VirgilPublicKey[])
     */
    public void encrypt(InputStream inputStream, OutputStream outputStream, VirgilPublicKey[] recipients)
            throws EncryptionException {
        try (VirgilStreamCipher cipher = new VirgilStreamCipher();
                VirgilDataSource dataSource = new VirgilStreamDataSource(inputStream);
                VirgilDataSink dataSink = new VirgilStreamDataSink(outputStream)) {
            for (VirgilPublicKey recipient : recipients) {
                cipher.addKeyRecipient(recipient.getIdentifier(), recipient.getRawKey());
            }

            cipher.encrypt(dataSource, dataSink, true);
        } catch (IOException e) {
            throw new EncryptionException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#exportPrivateKey(com.virgilsecurity. sdk.crypto.VirgilPrivateKey)
     */
    public byte[] exportPrivateKey(VirgilPrivateKey privateKey) {
        return exportPrivateKey(privateKey, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#exportPrivateKey(com.virgilsecurity. sdk.crypto.VirgilPrivateKey,
     * java.lang.String)
     */
    public byte[] exportPrivateKey(VirgilPrivateKey privateKey, String password) {
        if (password == null) {
            return VirgilKeyPair.privateKeyToDER(privateKey.getRawKey());
        }
        byte[] passwordBytes = password.getBytes(UTF8_CHARSET);
        byte[] encryptedKey = VirgilKeyPair.encryptPrivateKey(privateKey.getRawKey(), passwordBytes);

        return VirgilKeyPair.privateKeyToDER(encryptedKey, passwordBytes);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#exportPublicKey(com.virgilsecurity. sdk.crypto.VirgilPublicKey)
     */
    public byte[] exportPublicKey(VirgilPublicKey publicKey) {
        return VirgilKeyPair.publicKeyToDER(publicKey.getRawKey());
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#extractPublicKey(com.virgilsecurity. sdk.crypto.VirgilPrivateKey)
     */
    public VirgilPublicKey extractPublicKey(VirgilPrivateKey privateKey) {
        byte[] publicKeyData = VirgilKeyPair.extractPublicKey(privateKey.getRawKey(), new byte[0]);

        byte[] receiverId = privateKey.getIdentifier();
        byte[] value = VirgilKeyPair.publicKeyToDER(publicKeyData);

        return new VirgilPublicKey(receiverId, value);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#generateKeys()
     */
    public KeyPairVirgiled generateKeys() {
        return generateKeys(this.defaultKeyPairType);
    }

    /**
     * Generate key pair by type.
     * 
     * @param keysType
     *            the key type.
     * @return generated key pair.
     */
    public KeyPairVirgiled generateKeys(KeysType keysType) {
        VirgilKeyPair keyPair = VirgilKeyPair.generate(toVirgilKeyPairType(keysType));

        byte[] keyPairId = this.computePublicKeyHash(keyPair.publicKey());

        VirgilPublicKey publicKey = new VirgilPublicKey(keyPairId, VirgilKeyPair.publicKeyToDER(keyPair.publicKey()));
        VirgilPrivateKey privateKey = new VirgilPrivateKey(keyPairId, VirgilKeyPair.privateKeyToDER(keyPair.privateKey()));

        return new KeyPairVirgiled(publicKey, privateKey);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#importPrivateKey(byte[])
     */
    public VirgilPrivateKey importPrivateKey(byte[] privateKey) throws CryptoException {
        return importPrivateKey(privateKey, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#importPrivateKey(byte[], java.lang.String)
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
            VirgilPrivateKey privateKey = new VirgilPrivateKey(receiverId, value);

            return privateKey;
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#importPublicKey(byte[])
     */
    public VirgilPublicKey importPublicKey(byte[] publicKey) {
        byte[] receiverId = computePublicKeyHash(publicKey);
        byte[] value = VirgilKeyPair.publicKeyToDER(publicKey);

        return new VirgilPublicKey(receiverId, value);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#generateStreamSignature(byte[], com.virgilsecurity.sdk.crypto.VirgilPrivateKey)
     */
    public byte[] generateSignature(byte[] data, VirgilPrivateKey privateKey) {
        if (data == null) {
            throw new NullArgumentException("data");
        }

        if (privateKey == null) {
            throw new NullArgumentException("privateKey");
        }

        try (VirgilSigner signer = new VirgilSigner()) {
            byte[] signature = signer.sign(data, privateKey.getRawKey());
            return signature;
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#generateStreamSignature(java.io.InputStream, com.virgilsecurity.sdk.crypto.VirgilPrivateKey)
     */
    public byte[] generateStreamSignature(InputStream inputStream, VirgilPrivateKey privateKey) throws SigningException {
        if (inputStream == null) {
            throw new NullArgumentException("inputStream");
        }

        if (privateKey == null) {
            throw new NullArgumentException("privateKey");
        }

        try (VirgilStreamSigner signer = new VirgilStreamSigner();
                VirgilDataSource dataSource = new VirgilStreamDataSource(inputStream)) {
            byte[] signature = signer.sign(dataSource, privateKey.getRawKey());
            return signature;
        } catch (IOException e) {
            throw new SigningException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#signThenEncrypt(byte[], com.virgilsecurity.sdk.crypto.VirgilPrivateKey,
     * com.virgilsecurity.sdk.crypto.VirgilPublicKey)
     */
    public byte[] signThenEncrypt(byte[] data, VirgilPrivateKey privateKey, VirgilPublicKey recipient) throws CryptoException {
        return signThenEncrypt(data, privateKey, new VirgilPublicKey[] { recipient });
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#signThenEncrypt(byte[], com.virgilsecurity.sdk.crypto.VirgilPrivateKey,
     * com.virgilsecurity.sdk.crypto.VirgilPublicKey[])
     */
    public byte[] signThenEncrypt(byte[] data, VirgilPrivateKey privateKey, VirgilPublicKey[] recipients) throws CryptoException {
        try (VirgilSigner signer = new VirgilSigner(); VirgilCipher cipher = new VirgilCipher()) {

            byte[] signature = signer.sign(data, privateKey.getRawKey());

            VirgilCustomParams customData = cipher.customParams();
            customData.setData(CUSTOM_PARAM_SIGNATURE, signature);

            for (VirgilPublicKey publicKey : recipients) {
                cipher.addKeyRecipient(publicKey.getIdentifier(), publicKey.getRawKey());
            }
            return cipher.encrypt(data, true);

        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#verifySignature(byte[], byte[], com.virgilsecurity.sdk.crypto.VirgilPublicKey)
     */
    public boolean verifySignature(byte[] signature, byte[] data, VirgilPublicKey signer) throws VerificationException {
        if (data == null) {
            throw new NullArgumentException("data");
        }
        if (signature == null) {
            throw new NullArgumentException("signature");
        }
        if (signer == null) {
            throw new NullArgumentException("signer");
        }

        try (VirgilSigner virgilSigner = new VirgilSigner()) {
            boolean valid = virgilSigner.verify(data, signature, signer.getRawKey());
            return valid;
        } catch (Exception e) {
            throw new VerificationException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#verifySignature(java.io.InputStream, byte[],
     * com.virgilsecurity.sdk.crypto.VirgilPublicKey)
     */
    public boolean verifyStreamSignature(InputStream inputStream, byte[] signature, VirgilPublicKey signer) throws VerificationException {
        if (inputStream == null) {
            throw new NullArgumentException("inputStream");
        }
        if (signature == null) {
            throw new NullArgumentException("signature");
        }
        if (signer == null) {
            throw new NullArgumentException("signer");
        }

        try (VirgilStreamSigner virgilSigner = new VirgilStreamSigner();
                VirgilDataSource dataSource = new VirgilStreamDataSource(inputStream)) {
            boolean valid = virgilSigner.verify(dataSource, signature, signer.getRawKey());
            return valid;
        } catch (Exception e) {
            throw new VerificationException(e);
        }
    }
}
