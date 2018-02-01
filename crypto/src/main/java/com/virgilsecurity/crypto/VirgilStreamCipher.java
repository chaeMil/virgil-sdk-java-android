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
 * This class provides high-level interface to encrypt / decrypt streaming data using Virgil Security keys.
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilStreamCipher extends VirgilCipherBase implements java.lang.AutoCloseable {
    protected static long getCPtr(VirgilStreamCipher obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    private transient long swigCPtr;

    /**
     * Create a new instance of {@code VirgilStreamCipher}
     *
     */
    public VirgilStreamCipher() {
        this(virgil_crypto_javaJNI.new_VirgilStreamCipher(), true);
    }

    protected VirgilStreamCipher(long cPtr, boolean cMemoryOwn) {
        super(virgil_crypto_javaJNI.VirgilStreamCipher_SWIGUpcast(cPtr), cMemoryOwn);
        swigCPtr = cPtr;
    }

    @Override
    public void close() {
        delete();
    }

    /**
     * <p>
     * Decrypt data read from given source for recipient defined by id and private key, and write it to the sink.
     * </p>
     * <p>
     * Content info MUST be defined, if it was not embedded to the encrypted data.
     * </p>
     * 
     * @param source
     *            source of the data to be decrypted.
     * @param sink
     *            target sink for decrypted data.
     * @param recipientId
     *            the recipient identifier.
     * @param privateKey
     *            the private key.
     */
    public void decryptWithKey(VirgilDataSource source, VirgilDataSink sink, byte[] recipientId, byte[] privateKey) {
        virgil_crypto_javaJNI.VirgilStreamCipher_decryptWithKey__SWIG_1(swigCPtr, this,
                VirgilDataSource.getCPtr(source), source, VirgilDataSink.getCPtr(sink), sink, recipientId, privateKey);
    }

    /**
     * <p>
     * Decrypt data read from given source for recipient defined by id and private key, and write it to the sink.
     * </p>
     * <p>
     * Content info MUST be defined, if it was not embedded to the encrypted data.
     * </p>
     * 
     * @param source
     *            source of the data to be decrypted.
     * @param sink
     *            target sink for decrypted data.
     * @param recipientId
     *            the recipient identifier.
     * @param privateKey
     *            the private key protected with password.
     * @param privateKeyPassword
     *            the private key password.
     */
    public void decryptWithKey(VirgilDataSource source, VirgilDataSink sink, byte[] recipientId, byte[] privateKey,
            byte[] privateKeyPassword) {
        virgil_crypto_javaJNI.VirgilStreamCipher_decryptWithKey__SWIG_0(swigCPtr, this,
                VirgilDataSource.getCPtr(source), source, VirgilDataSink.getCPtr(sink), sink, recipientId, privateKey,
                privateKeyPassword);
    }

    /**
     * <p>
     * Decrypt data read from given source for recipient defined by password, and write it to the sink.
     * </p>
     * <p>
     * Content info MUST be defined, if it was not embedded to the encrypted data.
     * </p>
     * 
     * @param source
     *            source of the data to be decrypted.
     * @param sink
     *            target sink for decrypted data.
     * @param pwd
     *            the password.
     */
    public void decryptWithPassword(VirgilDataSource source, VirgilDataSink sink, byte[] pwd) {
        virgil_crypto_javaJNI.VirgilStreamCipher_decryptWithPassword(swigCPtr, this, VirgilDataSource.getCPtr(source),
                source, VirgilDataSink.getCPtr(sink), sink, pwd);
    }

    public synchronized void delete() {
        if (swigCPtr != 0) {
            if (swigCMemOwn) {
                swigCMemOwn = false;
                virgil_crypto_javaJNI.delete_VirgilStreamCipher(swigCPtr);
            }
            swigCPtr = 0;
        }
        super.delete();
    }

    /**
     * <p>
     * Encrypt data read from given source and write it the sink.
     * </p>
     * <p>
     * Store content info to use it for decription process, if embedContentInfo parameter is false.
     * </p>
     * 
     * @param source
     *            source of the data to be encrypted.
     * @param sink
     *            target sink for encrypted data.
     */
    public void encrypt(VirgilDataSource source, VirgilDataSink sink) {
        virgil_crypto_javaJNI.VirgilStreamCipher_encrypt__SWIG_1(swigCPtr, this, VirgilDataSource.getCPtr(source),
                source, VirgilDataSink.getCPtr(sink), sink);
    }

    /**
     * <p>
     * Encrypt data read from given source and write it the sink.
     * </p>
     * <p>
     * Store content info to use it for decription process, if embedContentInfo parameter is false.
     * </p>
     * 
     * @param source
     *            source of the data to be encrypted.
     * @param sink
     *            target sink for encrypted data.
     * @param embedContentInfo
     *            determines whether to embed content info the the encrypted data, or not.
     */
    public void encrypt(VirgilDataSource source, VirgilDataSink sink, boolean embedContentInfo) {
        virgil_crypto_javaJNI.VirgilStreamCipher_encrypt__SWIG_0(swigCPtr, this, VirgilDataSource.getCPtr(source),
                source, VirgilDataSink.getCPtr(sink), sink, embedContentInfo);
    }

    protected void finalize() {
        delete();
    }

}