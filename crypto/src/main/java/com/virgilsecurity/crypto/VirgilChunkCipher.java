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
 * This class provides high-level interface to encrypt / decrypt data splitted to chunks.
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilChunkCipher extends VirgilCipherBase implements java.lang.AutoCloseable {
    public final static long kPreferredChunkSize = virgil_crypto_javaJNI.VirgilChunkCipher_kPreferredChunkSize_get();

    protected static long getCPtr(VirgilChunkCipher obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    private transient long swigCPtr;

    /**
     * Create a new instance of {@code VirgilChunkCipher}
     *
     */
    public VirgilChunkCipher() {
        this(virgil_crypto_javaJNI.new_VirgilChunkCipher(), true);
    }

    protected VirgilChunkCipher(long cPtr, boolean cMemoryOwn) {
        super(virgil_crypto_javaJNI.VirgilChunkCipher_SWIGUpcast(cPtr), cMemoryOwn);
        swigCPtr = cPtr;
    }

    @Override
    public void close() {
        delete();
    }

    /**
     * Decrypt data read from given source for recipient defined by id and private key, and write it to the sink.
     * 
     * @param source
     *            The source of the data to be decrypted.
     * @param sink
     *            The target sink for decrypted data.
     * @param recipientId
     *            The recipient identifier.
     * @param privateKey
     *            Recipient's private key.
     */
    public void decryptWithKey(VirgilDataSource source, VirgilDataSink sink, byte[] recipientId, byte[] privateKey) {
        virgil_crypto_javaJNI.VirgilChunkCipher_decryptWithKey__SWIG_1(swigCPtr, this, VirgilDataSource.getCPtr(source),
                source, VirgilDataSink.getCPtr(sink), sink, recipientId, privateKey);
    }

    /**
     * Decrypt data read from given source for recipient defined by id and private key, and write it to the sink.
     * 
     * @param source
     *            The source of the data to be decrypted.
     * @param sink
     *            The target sink for decrypted data.
     * @param recipientId
     *            The recipient identifier.
     * @param privateKey
     *            Recipient's private key protected with password.
     * @param privateKeyPassword
     *            The private key password.
     */
    public void decryptWithKey(VirgilDataSource source, VirgilDataSink sink, byte[] recipientId, byte[] privateKey,
            byte[] privateKeyPassword) {
        virgil_crypto_javaJNI.VirgilChunkCipher_decryptWithKey__SWIG_0(swigCPtr, this, VirgilDataSource.getCPtr(source),
                source, VirgilDataSink.getCPtr(sink), sink, recipientId, privateKey, privateKeyPassword);
    }

    /**
     * Decrypt data read from given source for recipient defined by id and private key, and write it to the sink.
     * 
     * @param source
     *            The source of the data to be decrypted.
     * @param sink
     *            The target sink for decrypted data.
     * @param pwd
     *            The password.
     */
    public void decryptWithPassword(VirgilDataSource source, VirgilDataSink sink, byte[] pwd) {
        virgil_crypto_javaJNI.VirgilChunkCipher_decryptWithPassword(swigCPtr, this, VirgilDataSource.getCPtr(source),
                source, VirgilDataSink.getCPtr(sink), sink, pwd);
    }

    public synchronized void delete() {
        if (swigCPtr != 0) {
            if (swigCMemOwn) {
                swigCMemOwn = false;
                virgil_crypto_javaJNI.delete_VirgilChunkCipher(swigCPtr);
            }
            swigCPtr = 0;
        }
        super.delete();
    }

    /**
     * Encrypt data read from given source and write it the sink.
     * 
     * @param source
     *            The source of the data to be encrypted.
     * @param sink
     *            The target sink for encrypted data.
     */
    public void encrypt(VirgilDataSource source, VirgilDataSink sink) {
        virgil_crypto_javaJNI.VirgilChunkCipher_encrypt__SWIG_2(swigCPtr, this, VirgilDataSource.getCPtr(source),
                source, VirgilDataSink.getCPtr(sink), sink);
    }

    /**
     * Encrypt data read from given source and write it the sink.
     * 
     * @param source
     *            The source of the data to be encrypted.
     * @param sink
     *            The target sink for encrypted data.
     * @param embedContentInfo
     *            Determines whether to embed content info the the encrypted data, or not.
     */
    public void encrypt(VirgilDataSource source, VirgilDataSink sink, boolean embedContentInfo) {
        virgil_crypto_javaJNI.VirgilChunkCipher_encrypt__SWIG_1(swigCPtr, this, VirgilDataSource.getCPtr(source),
                source, VirgilDataSink.getCPtr(sink), sink, embedContentInfo);
    }

    /**
     * Encrypt data read from given source and write it the sink.
     * 
     * @param source
     *            The source of the data to be encrypted.
     * @param sink
     *            The target sink for encrypted data.
     * @param embedContentInfo
     *            Determines whether to embed content info the the encrypted data, or not.
     * @param preferredChunkSize
     *            Chunk size that will appropriate.
     */
    public void encrypt(VirgilDataSource source, VirgilDataSink sink, boolean embedContentInfo,
            long preferredChunkSize) {
        virgil_crypto_javaJNI.VirgilChunkCipher_encrypt__SWIG_0(swigCPtr, this, VirgilDataSource.getCPtr(source),
                source, VirgilDataSink.getCPtr(sink), sink, embedContentInfo, preferredChunkSize);
    }

    protected void finalize() {
        delete();
    }
}
