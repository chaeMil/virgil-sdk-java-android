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

package com.virgilsecurity.crypto;

/**
 * This class provides configuration methods to all Virgil Cipher classes.
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilCipherBase implements java.lang.AutoCloseable {
    /**
     * <p>
     * Compute shared secret key on a given keys.
     * </p>
     * <p>
     * Keys SHOULD be of the identical type, i.e. both of type Curve25519.
     * </p>
     * 
     * @param publicKey
     *            the public key.
     * @param privateKey
     *            the private key.
     * @return the shared secret key.
     */
    public static byte[] computeShared(byte[] publicKey, byte[] privateKey) {
        return virgil_crypto_javaJNI.VirgilCipherBase_computeShared__SWIG_1(publicKey, privateKey);
    }
    /**
     * <p>
     * Compute shared secret key on a given keys.
     * </p>
     * <p>
     * Keys SHOULD be of the identical type, i.e. both of type Curve25519.
     * </p>
     * 
     * @param publicKey
     *            the public key.
     * @param privateKey
     *            the private key.
     * @param privateKeyPassword
     *            the private key password.
     * @return the shared secret key.
     */
    public static byte[] computeShared(byte[] publicKey, byte[] privateKey, byte[] privateKeyPassword) {
        return virgil_crypto_javaJNI.VirgilCipherBase_computeShared__SWIG_0(publicKey, privateKey, privateKeyPassword);
    }

    /**
     * Read content info size as part of the data.
     * 
     * @param data
     *            the data.
     * @return Size of the content info if it is exist as part of the data, {@code 0} - otherwise.
     */
    public static long defineContentInfoSize(byte[] data) {
        return virgil_crypto_javaJNI.VirgilCipherBase_defineContentInfoSize(data);
    }

    protected static long getCPtr(VirgilCipherBase obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    private transient long swigCPtr;

    protected transient boolean swigCMemOwn;

    /**
     * Create a new instance of {@code VirgilCipherBase}
     *
     */
    public VirgilCipherBase() {
        this(virgil_crypto_javaJNI.new_VirgilCipherBase(), true);
    }

    protected VirgilCipherBase(long cPtr, boolean cMemoryOwn) {
        swigCMemOwn = cMemoryOwn;
        swigCPtr = cPtr;
    }

    /**
     * Add recipient defined with id and public key.
     * 
     * 
     * @param recipientId
     *            Recipient's unique identifier, MUST not be empty.
     * @param publicKey
     *            Recipient's public key, MUST not be empty.
     */
    public void addKeyRecipient(byte[] recipientId, byte[] publicKey) {
        virgil_crypto_javaJNI.VirgilCipherBase_addKeyRecipient(swigCPtr, this, recipientId, publicKey);
    }

    /**
     * <p>
     * Add recipient defined with password.
     * </p>
     * <p>
     * Use it for password based encryption.
     * </p>
     * 
     * 
     * @param pwd
     *            Recipient's password, MUST not be empty.
     * 
     */
    public void addPasswordRecipient(byte[] pwd) {
        virgil_crypto_javaJNI.VirgilCipherBase_addPasswordRecipient(swigCPtr, this, pwd);
    }

    @Override
    public void close() {
        delete();
    }

    /**
     * <p>
     * Provide access to the object that handles custom parameters.
     * </p>
     * <p>
     * Use this method to add custom parameters to the content info object.
     * </p>
     * <p>
     * Use this method before encryption process.
     * </p>
     * 
     * @return custom params.
     */
    public VirgilCustomParams customParams() {
        return new VirgilCustomParams(virgil_crypto_javaJNI.VirgilCipherBase_customParams__SWIG_0(swigCPtr, this),
                false);
    }

    public synchronized void delete() {
        if (swigCPtr != 0) {
            if (swigCMemOwn) {
                swigCMemOwn = false;
                virgil_crypto_javaJNI.delete_VirgilCipherBase(swigCPtr);
            }
            swigCPtr = 0;
        }
    }

    protected void finalize() {
        delete();
    }

    /**
     * <p>
     * Get Virgil Security Cryptogram, that contains public algorithm parameters that was used for encryption.
     * </p>
     * <p>
     * Call this method after encryption process.
     * </p>
     * 
     * @return Encrypted data info.
     */
    public byte[] getContentInfo() {
        return virgil_crypto_javaJNI.VirgilCipherBase_getContentInfo(swigCPtr, this);
    }

    /**
     * <p>
     * Check whether recipient with given identifier exists.
     * </p>
     * <p>
     * Search order:
     * </p>
     * <ul>
     * <li>Local structures - useful when cipher is used for encryption.
     * <li>ContentInfo structure - useful when cipher is used for decryption.
     * </ul>
     * 
     * @param recipientId
     *            the recipient's unique identifier.
     * 
     * @return {@code true} if recipient with given identifier exists, {@code false} - otherwise.
     */
    public boolean keyRecipientExists(byte[] recipientId) {
        return virgil_crypto_javaJNI.VirgilCipherBase_keyRecipientExists(swigCPtr, this, recipientId);
    }

    /**
     * <p>
     * Check whether recipient with given password exists.
     * </p>
     * <p>
     * Search order:
     * </p>
     * <ul>
     * <li>Local structures - useful when cipher is used for encryption.
     * </ul>
     * 
     * @param password
     *            Recipient's unique identifier.
     * 
     * @return {@code true} if recipient with given password exists, {@code false} - otherwise.
     */
    public boolean passwordRecipientExists(byte[] password) {
        return virgil_crypto_javaJNI.VirgilCipherBase_passwordRecipientExists(swigCPtr, this, password);
    }

    /**
     * Remove all recipients.
     */
    public void removeAllRecipients() {
        virgil_crypto_javaJNI.VirgilCipherBase_removeAllRecipients(swigCPtr, this);
    }

    /**
     * <p>
     * Remove recipient with given identifier.
     * </p>
     * <p>
     * If recipient with given identifier is absent - do nothing.
     * </p>
     * 
     * 
     * @param recipientId
     *            Recipient's unique identifier.
     */
    public void removeKeyRecipient(byte[] recipientId) {
        virgil_crypto_javaJNI.VirgilCipherBase_removeKeyRecipient(swigCPtr, this, recipientId);
    }

    /**
     * <p>
     * Remove recipient with given password.
     * </p>
     * <p>
     * If recipient with given password is absent - do nothing.
     * </p>
     * 
     * 
     * @param pwd
     *            Recipient's password.
     */
    public void removePasswordRecipient(byte[] pwd) {
        virgil_crypto_javaJNI.VirgilCipherBase_removePasswordRecipient(swigCPtr, this, pwd);
    }

    /**
     * <p>
     * Create content info object from ASN.1 structure.
     * </p>
     * <p>
     * Call this method before decryption process.
     * </p>
     * 
     * @param contentInfo
     *            Virgil Security Cryptogram.
     */
    public void setContentInfo(byte[] contentInfo) {
        virgil_crypto_javaJNI.VirgilCipherBase_setContentInfo(swigCPtr, this, contentInfo);
    }

}
