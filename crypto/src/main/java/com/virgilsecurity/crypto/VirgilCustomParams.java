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

public class VirgilCustomParams extends VirgilAsn1Compatible implements java.lang.AutoCloseable {
    protected static long getCPtr(VirgilCustomParams obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    private transient long swigCPtr;

    public VirgilCustomParams() {
        this(virgil_crypto_javaJNI.new_VirgilCustomParams__SWIG_0(), true);
    }

    public VirgilCustomParams(VirgilCustomParams other) {
        this(virgil_crypto_javaJNI.new_VirgilCustomParams__SWIG_1(VirgilCustomParams.getCPtr(other), other), true);
    }

    protected VirgilCustomParams(long cPtr, boolean cMemoryOwn) {
        super(virgil_crypto_javaJNI.VirgilCustomParams_SWIGUpcast(cPtr), cMemoryOwn);
        swigCPtr = cPtr;
    }

    public void clear() {
        virgil_crypto_javaJNI.VirgilCustomParams_clear(swigCPtr, this);
    }

    @Override
    public void close() {
        delete();
    }

    public synchronized void delete() {
        if (swigCPtr != 0) {
            if (swigCMemOwn) {
                swigCMemOwn = false;
                virgil_crypto_javaJNI.delete_VirgilCustomParams(swigCPtr);
            }
            swigCPtr = 0;
        }
        super.delete();
    }

    public byte[] getData(byte[] key) {
        return virgil_crypto_javaJNI.VirgilCustomParams_getData(swigCPtr, this, key);
    }

    public int getInteger(byte[] key) {
        return virgil_crypto_javaJNI.VirgilCustomParams_getInteger(swigCPtr, this, key);
    }

    public byte[] getString(byte[] key) {
        return virgil_crypto_javaJNI.VirgilCustomParams_getString(swigCPtr, this, key);
    }

    public boolean isEmpty() {
        return virgil_crypto_javaJNI.VirgilCustomParams_isEmpty(swigCPtr, this);
    }

    public void removeData(byte[] key) {
        virgil_crypto_javaJNI.VirgilCustomParams_removeData(swigCPtr, this, key);
    }

    public void removeInteger(byte[] key) {
        virgil_crypto_javaJNI.VirgilCustomParams_removeInteger(swigCPtr, this, key);
    }

    public void removeString(byte[] key) {
        virgil_crypto_javaJNI.VirgilCustomParams_removeString(swigCPtr, this, key);
    }

    public void setData(byte[] key, byte[] value) {
        virgil_crypto_javaJNI.VirgilCustomParams_setData(swigCPtr, this, key, value);
    }

    public void setInteger(byte[] key, int value) {
        virgil_crypto_javaJNI.VirgilCustomParams_setInteger(swigCPtr, this, key, value);
    }

    public void setString(byte[] key, byte[] value) {
        virgil_crypto_javaJNI.VirgilCustomParams_setString(swigCPtr, this, key, value);
    }

    protected void finalize() {
        delete();
    }

}
