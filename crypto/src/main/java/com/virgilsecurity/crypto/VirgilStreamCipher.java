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

public class VirgilStreamCipher extends VirgilCipherBase implements java.lang.AutoCloseable {
    protected static long getCPtr(VirgilStreamCipher obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    private transient long swigCPtr;

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

    public void decryptWithKey(VirgilDataSource source, VirgilDataSink sink, byte[] recipientId, byte[] privateKey) {
        virgil_crypto_javaJNI.VirgilStreamCipher_decryptWithKey__SWIG_1(swigCPtr, this,
                VirgilDataSource.getCPtr(source), source, VirgilDataSink.getCPtr(sink), sink, recipientId, privateKey);
    }

    public void decryptWithKey(VirgilDataSource source, VirgilDataSink sink, byte[] recipientId, byte[] privateKey,
            byte[] privateKeyPassword) {
        virgil_crypto_javaJNI.VirgilStreamCipher_decryptWithKey__SWIG_0(swigCPtr, this,
                VirgilDataSource.getCPtr(source), source, VirgilDataSink.getCPtr(sink), sink, recipientId, privateKey,
                privateKeyPassword);
    }

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

    public void encrypt(VirgilDataSource source, VirgilDataSink sink) {
        virgil_crypto_javaJNI.VirgilStreamCipher_encrypt__SWIG_1(swigCPtr, this, VirgilDataSource.getCPtr(source),
                source, VirgilDataSink.getCPtr(sink), sink);
    }

    public void encrypt(VirgilDataSource source, VirgilDataSink sink, boolean embedContentInfo) {
        virgil_crypto_javaJNI.VirgilStreamCipher_encrypt__SWIG_0(swigCPtr, this, VirgilDataSource.getCPtr(source),
                source, VirgilDataSink.getCPtr(sink), sink, embedContentInfo);
    }

    protected void finalize() {
        delete();
    }

}
