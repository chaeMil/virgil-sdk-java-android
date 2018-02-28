/*******************************************************************************
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
 *******************************************************************************/
package com.virgilsecurity.sdk.highlevel;

import java.util.ArrayList;
import java.util.List;

import com.virgilsecurity.sdk.client.exceptions.VirgilKeyIsAlreadyExistsException;
import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.DecryptionException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.storage.KeyEntry;
import com.virgilsecurity.sdk.storage.VirgilKeyEntry;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * @author Andrii Iakovenko
 *
 */
public class VirgilKey {

    private VirgilApiContext context;
    private PrivateKey privateKey;

    /**
     * Create new instance of {@link VirgilKey}.
     * 
     * @param context
     *            The context.
     * @param privateKey
     *            The private key.
     */
    public VirgilKey(VirgilApiContext context, PrivateKey privateKey) {
        super();
        this.context = context;
        this.privateKey = privateKey;
    }

    /**
     * Exports the {@linkplain VirgilKey} to default format, specified in Crypto API.
     * 
     * @return The private key as a buffer.
     */
    public VirgilBuffer export() {
        return export(null);
    }

    /**
     * Exports the {@linkplain VirgilKey} to default format, specified in Crypto API.
     * 
     * @param password
     *            The password.
     * @return The private key as a buffer.
     */
    public VirgilBuffer export(String password) {
        byte[] exportedPrivateKey = this.context.getCrypto().exportPrivateKey(this.privateKey, password);
        return VirgilBuffer.from(exportedPrivateKey);
    }

    /**
     * @return the private key.
     */
    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    /**
     * Generates a digital signature for specified data using current {@linkplain VirgilKey}.
     * 
     * @param buffer
     *            The data for which the digital signature will be generated.
     * @return A byte array containing the result from performing the operation.
     * 
     * @throws NullArgumentException
     *             if data is null.
     */
    public VirgilBuffer sign(VirgilBuffer buffer) {
        if (buffer == null) {
            throw new NullArgumentException("buffer");
        }
        byte[] signature = this.context.getCrypto().sign(buffer.getBytes(), this.privateKey);
        return VirgilBuffer.from(signature);
    }

    /**
     * Generates a digital signature for specified plain text using current {@linkplain VirgilKey}.
     * 
     * @param plaintext
     *            The plain text for which the digital signature will be generated.
     * @return A byte array containing the result from performing the operation.
     * 
     * @throws NullArgumentException
     *             if data is null.
     */
    public VirgilBuffer sign(String plaintext) {
        if (plaintext == null) {
            throw new NullArgumentException("plaintext");
        }
        return sign(VirgilBuffer.from(plaintext));
    }

    /**
     * Generates a digital signature for specified data using current {@linkplain VirgilKey}.
     * 
     * @param data
     *            The data for which the digital signature will be generated.
     * @return A byte array containing the result from performing the operation.
     * 
     * @throws NullArgumentException
     *             if data is null.
     */
    public VirgilBuffer sign(byte[] data) {
        if (data == null) {
            throw new NullArgumentException("plaintext");
        }
        return sign(VirgilBuffer.from(data));
    }

    /**
     * Decrypts the specified cipher data using {@linkplain VirgilKey}.
     * 
     * @param cipherData
     *            The encrypted data.
     * @return A byte array containing the result from performing the operation.
     * @throws DecryptionException
     * 
     * @throws NullArgumentException
     *             if cipherData is null.
     */
    public VirgilBuffer decrypt(VirgilBuffer cipherData) throws DecryptionException {
        if (cipherData == null) {
            throw new NullArgumentException("cipherData");
        }

        byte[] data = this.context.getCrypto().decrypt(cipherData.getBytes(), this.privateKey);
        return VirgilBuffer.from(data);
    }

    /**
     * Decrypts the specified Base64-encoded string using {@linkplain VirgilKey}.
     * 
     * @param base64String
     *            The encrypted Base64-encoded string.
     * @return A byte array containing the result from performing the operation.
     * @throws DecryptionException
     * 
     * @throws NullArgumentException
     *             if base64String is null.
     */
    public VirgilBuffer decrypt(String base64String) throws DecryptionException {
        if (base64String == null) {
            throw new NullArgumentException("base64String");
        }
        return decrypt(ConvertionUtils.base64ToBytes(base64String));
    }

    /**
     * Decrypts the specified data using {@linkplain VirgilKey}.
     * 
     * @param data
     *            The encrypted data.
     * @return A byte array containing the result from performing the operation.
     * @throws DecryptionException
     * 
     * @throws NullArgumentException
     *             if base64String is null.
     */
    public VirgilBuffer decrypt(byte[] data) throws DecryptionException {
        if (data == null) {
            throw new NullArgumentException("data");
        }

        byte[] decryptedData = this.context.getCrypto().decrypt(data, this.privateKey);
        return VirgilBuffer.from(decryptedData);
    }

    /**
     * Encrypts and signs the data.
     * 
     * @param buffer
     *            The data to be encrypted.
     * @param recipients
     *            The list of {@linkplain VirgilCard} recipients.
     * @return The encrypted data.
     * @throws CryptoException
     * 
     * @throws NullArgumentException
     *             if recipients list is null.
     */
    public VirgilBuffer signThenEncrypt(VirgilBuffer buffer, List<VirgilCard> recipients) throws CryptoException {
        if (buffer == null) {
            throw new NullArgumentException("buffer");
        }
        return signThenEncrypt(buffer.getBytes(), recipients);
    }

    /**
     * Encrypts and signs the plain text.
     * 
     * @param plaintext
     *            The plain text to be encrypted.
     * @param recipients
     *            The list of {@linkplain VirgilCard} recipients.
     * @return The encrypted data.
     * @throws CryptoException
     * 
     * @throws NullArgumentException
     *             if recipients list is null.
     */
    public VirgilBuffer signThenEncrypt(String plaintext, List<VirgilCard> recipients) throws CryptoException {
        if (plaintext == null) {
            throw new NullArgumentException("plaintext");
        }
        return signThenEncrypt(ConvertionUtils.toBytes(plaintext), recipients);
    }

    /**
     * Encrypts and signs the data.
     * 
     * @param data
     *            The data to be encrypted.
     * @param recipients
     *            The list of {@linkplain VirgilCard} recipients.
     * @return The encrypted data.
     * @throws CryptoException
     * 
     * @throws NullArgumentException
     *             if recipients list is null.
     */
    public VirgilBuffer signThenEncrypt(byte[] data, List<VirgilCard> recipients) throws CryptoException {
        if (data == null) {
            throw new NullArgumentException("data");
        }
        if (recipients == null) {
            throw new NullArgumentException("recipients");
        }

        Crypto crypto = this.context.getCrypto();
        List<PublicKey> publicKeys = new ArrayList<>();
        for (VirgilCard recipient : recipients) {
            publicKeys.add(recipient.getPublicKey());
        }

        byte[] cipherdata = crypto.signThenEncrypt(data, this.privateKey, publicKeys.toArray(new PublicKey[0]));

        return VirgilBuffer.from(cipherdata);
    }

    /**
     * Decrypts and verifies the data.
     * 
     * @param cipherbuffer
     *            The data to be decrypted.
     * @param card
     *            The signer's {@link VirgilCard}.
     * @return The decrypted data, which is the original plain text before encryption.
     * @throws CryptoException
     */
    public VirgilBuffer decryptThenVerify(VirgilBuffer cipherbuffer, VirgilCard card) throws CryptoException {
        byte[] plaitext = this.context.getCrypto().decryptThenVerify(cipherbuffer.getBytes(), this.privateKey,
                card.getPublicKey());

        return new VirgilBuffer(plaitext);
    }

    /**
     * Decrypts and verifies the data.
     * 
     * @param base64String
     *            The encrypted Base64-encoded string.
     * @param card
     *            The signer's {@link VirgilCard}.
     * @return The decrypted data, which is the original plain text before encryption.
     * @throws CryptoException
     */
    public VirgilBuffer decryptThenVerify(String base64String, VirgilCard card) throws CryptoException {
        if (base64String == null) {
            throw new NullArgumentException("base64String");
        }
        return decryptThenVerify(ConvertionUtils.base64ToBytes(base64String), card);
    }

    /**
     * Decrypts and verifies the data.
     * 
     * @param data
     *            The encrypted data.
     * @param card
     *            The signer's {@link VirgilCard}.
     * @return The decrypted data, which is the original plain text before encryption.
     * @throws CryptoException
     */
    public VirgilBuffer decryptThenVerify(byte[] data, VirgilCard card) throws CryptoException {
        if (data == null) {
            throw new NullArgumentException("data");
        }
        byte[] decryptedData = this.context.getCrypto().decryptThenVerify(data, this.privateKey, card.getPublicKey());
        return VirgilBuffer.from(decryptedData);
    }

    /**
     * Saves a current {@linkplain VirgilKey} in secure storage.
     * 
     * @param keyName
     *            The name of the key.
     * @return This key.
     * @throws VirgilKeyIsAlreadyExistsException
     */
    public VirgilKey save(String keyName) throws VirgilKeyIsAlreadyExistsException {
        return save(keyName, null);
    }

    /**
     * Saves a current {@linkplain VirgilKey} in secure storage.
     * 
     * @param keyName
     *            The name of the key.
     * @param password
     *            The password.
     * @return This key.
     * @throws VirgilKeyIsAlreadyExistsException
     */
    public VirgilKey save(String keyName, String password) throws VirgilKeyIsAlreadyExistsException {
        byte[] exportedPrivateKey = this.context.getCrypto().exportPrivateKey(this.privateKey, password);
        KeyEntry keyEntry = new VirgilKeyEntry(keyName, exportedPrivateKey);

        if (this.context.getKeyStorage().exists(keyEntry.getName())) {
            throw new VirgilKeyIsAlreadyExistsException();
        }

        this.context.getKeyStorage().store(keyEntry);

        return this;
    }

    /**
     * Exports the Public key value from current {@linkplain VirgilKey}.
     * 
     * @return A new {@link VirgilBuffer} that contains Public Key value.
     */
    public VirgilBuffer exportPublicKey() {
        PublicKey publicKey = this.context.getCrypto().extractPublicKey(this.privateKey);
        return VirgilBuffer.from(this.context.getCrypto().exportPublicKey(publicKey));
    }

}
