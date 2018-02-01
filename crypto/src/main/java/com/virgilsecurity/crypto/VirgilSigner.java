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
 * This class provides high-level interface to generateStreamSignature and verifySignature data using Virgil Security keys.
 * 
 * This module can generateStreamSignature / verifySignature as raw data and Virgil Security tickets.
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilSigner extends VirgilSignerBase implements java.lang.AutoCloseable {
    protected static long getCPtr(VirgilSigner obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    private transient long swigCPtr;

    /**
     * Create a new instance of {@code VirgilSigner}
     *
     */
    public VirgilSigner() {
        this(virgil_crypto_javaJNI.new_VirgilSigner(), true);
    }

    protected VirgilSigner(long cPtr, boolean cMemoryOwn) {
        super(virgil_crypto_javaJNI.VirgilSigner_SWIGUpcast(cPtr), cMemoryOwn);
        swigCPtr = cPtr;
    }

    @Override
    public void close() {
        delete();
    }

    public synchronized void delete() {
        if (swigCPtr != 0) {
            if (swigCMemOwn) {
                swigCMemOwn = false;
                virgil_crypto_javaJNI.delete_VirgilSigner(swigCPtr);
            }
            swigCPtr = 0;
        }
        super.delete();
    }

    protected void finalize() {
        delete();
    }

    /**
     * Sign data with given private key.
     * 
     * @param data
     *            the data to be signed.
     * @param privateKey
     *            the private key.
     * @return the signature as byte array.
     */
    public byte[] sign(byte[] data, byte[] privateKey) {
        return virgil_crypto_javaJNI.VirgilSigner_sign__SWIG_1(swigCPtr, this, data, privateKey);
    }

    /**
     * Sign data with given private key.
     * 
     * @param data
     *            the data to be signed.
     * @param privateKey
     *            the private key protected with password.
     * @param privateKeyPassword
     *            the private key password.
     * @return the signature as byte array.
     */
    public byte[] sign(byte[] data, byte[] privateKey, byte[] privateKeyPassword) {
        return virgil_crypto_javaJNI.VirgilSigner_sign__SWIG_0(swigCPtr, this, data, privateKey, privateKeyPassword);
    }

    /**
     * Verify generateStreamSignature and data to be conformed to the given public key.
     * 
     * @param data
     *            the data signed with {@code generateStreamSignature}.
     * @param sign
     *            the signature.
     * @param publicKey
     *            the public key.
     * @return {@code true} if generateStreamSignature is valid and data was not malformed.
     */
    public boolean verify(byte[] data, byte[] sign, byte[] publicKey) {
        return virgil_crypto_javaJNI.VirgilSigner_verify(swigCPtr, this, data, sign, publicKey);
    }

}
