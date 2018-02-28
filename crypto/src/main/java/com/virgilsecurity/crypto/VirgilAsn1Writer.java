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

public class VirgilAsn1Writer implements java.lang.AutoCloseable {
    protected static long getCPtr(VirgilAsn1Writer obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    private transient long swigCPtr;

    protected transient boolean swigCMemOwn;

    public VirgilAsn1Writer() {
        this(virgil_crypto_javaJNI.new_VirgilAsn1Writer__SWIG_0(), true);
    }

    public VirgilAsn1Writer(long capacity) {
        this(virgil_crypto_javaJNI.new_VirgilAsn1Writer__SWIG_1(capacity), true);
    }

    protected VirgilAsn1Writer(long cPtr, boolean cMemoryOwn) {
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
                virgil_crypto_javaJNI.delete_VirgilAsn1Writer(swigCPtr);
            }
            swigCPtr = 0;
        }
    }

    public byte[] finish() {
        return virgil_crypto_javaJNI.VirgilAsn1Writer_finish(swigCPtr, this);
    }

    public void reset() {
        virgil_crypto_javaJNI.VirgilAsn1Writer_reset__SWIG_0(swigCPtr, this);
    }

    public void reset(long capacity) {
        virgil_crypto_javaJNI.VirgilAsn1Writer_reset__SWIG_1(swigCPtr, this, capacity);
    }

    public long writeBool(boolean value) {
        return virgil_crypto_javaJNI.VirgilAsn1Writer_writeBool(swigCPtr, this, value);
    }

    public long writeContextTag(short tag, long len) {
        return virgil_crypto_javaJNI.VirgilAsn1Writer_writeContextTag(swigCPtr, this, tag, len);
    }

    public long writeData(byte[] data) {
        return virgil_crypto_javaJNI.VirgilAsn1Writer_writeData(swigCPtr, this, data);
    }

    public long writeInteger(int value) {
        return virgil_crypto_javaJNI.VirgilAsn1Writer_writeInteger(swigCPtr, this, value);
    }

    public long writeNull() {
        return virgil_crypto_javaJNI.VirgilAsn1Writer_writeNull(swigCPtr, this);
    }

    public long writeOctetString(byte[] data) {
        return virgil_crypto_javaJNI.VirgilAsn1Writer_writeOctetString(swigCPtr, this, data);
    }

    public long writeOID(String oid) {
        return virgil_crypto_javaJNI.VirgilAsn1Writer_writeOID(swigCPtr, this, oid);
    }

    public long writeSequence(long len) {
        return virgil_crypto_javaJNI.VirgilAsn1Writer_writeSequence(swigCPtr, this, len);
    }

    public long writeSet(SWIGTYPE_p_std__vectorT_virgil__crypto__VirgilByteArray_t set) {
        return virgil_crypto_javaJNI.VirgilAsn1Writer_writeSet(swigCPtr, this,
                SWIGTYPE_p_std__vectorT_virgil__crypto__VirgilByteArray_t.getCPtr(set));
    }

    public long writeUTF8String(byte[] data) {
        return virgil_crypto_javaJNI.VirgilAsn1Writer_writeUTF8String(swigCPtr, this, data);
    }

    protected void finalize() {
        delete();
    }

}
