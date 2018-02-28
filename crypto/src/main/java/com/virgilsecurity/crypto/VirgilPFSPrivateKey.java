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
package com.virgilsecurity.crypto;

public class VirgilPFSPrivateKey implements java.lang.AutoCloseable {
    protected static long getCPtr(VirgilPFSPrivateKey obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    private transient long swigCPtr;

    protected transient boolean swigCMemOwn;

    public VirgilPFSPrivateKey() {
        this(virgil_crypto_javaJNI.new_VirgilPFSPrivateKey__SWIG_2(), true);
    }

    public VirgilPFSPrivateKey(byte[] key) {
        this(virgil_crypto_javaJNI.new_VirgilPFSPrivateKey__SWIG_1(key), true);
    }

    public VirgilPFSPrivateKey(byte[] key, byte[] password) {
        this(virgil_crypto_javaJNI.new_VirgilPFSPrivateKey__SWIG_0(key, password), true);
    }

    public VirgilPFSPrivateKey(VirgilPFSPrivateKey other) {
        this(virgil_crypto_javaJNI.new_VirgilPFSPrivateKey__SWIG_3(VirgilPFSPrivateKey.getCPtr(other), other), true);
    }

    protected VirgilPFSPrivateKey(long cPtr, boolean cMemoryOwn) {
        swigCMemOwn = cMemoryOwn;
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
                virgil_crypto_javaJNI.delete_VirgilPFSPrivateKey(swigCPtr);
            }
            swigCPtr = 0;
        }
    }

    public byte[] getKey() {
        return virgil_crypto_javaJNI.VirgilPFSPrivateKey_getKey(swigCPtr, this);
    }

    public byte[] getPassword() {
        return virgil_crypto_javaJNI.VirgilPFSPrivateKey_getPassword(swigCPtr, this);
    }

    public boolean isEmpty() {
        return virgil_crypto_javaJNI.VirgilPFSPrivateKey_isEmpty(swigCPtr, this);
    }

    protected void finalize() {
        delete();
    }

}
