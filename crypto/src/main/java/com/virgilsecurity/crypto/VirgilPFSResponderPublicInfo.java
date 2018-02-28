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

public class VirgilPFSResponderPublicInfo implements java.lang.AutoCloseable {
    protected static long getCPtr(VirgilPFSResponderPublicInfo obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    private transient long swigCPtr;

    protected transient boolean swigCMemOwn;

    public VirgilPFSResponderPublicInfo(VirgilPFSPublicKey identityPublicKey, VirgilPFSPublicKey longTermPublicKey) {
        this(virgil_crypto_javaJNI.new_VirgilPFSResponderPublicInfo__SWIG_1(
                VirgilPFSPublicKey.getCPtr(identityPublicKey), identityPublicKey,
                VirgilPFSPublicKey.getCPtr(longTermPublicKey), longTermPublicKey), true);
    }

    public VirgilPFSResponderPublicInfo(VirgilPFSPublicKey identityPublicKey, VirgilPFSPublicKey longTermPublicKey,
            VirgilPFSPublicKey oneTimePublicKey) {
        this(virgil_crypto_javaJNI.new_VirgilPFSResponderPublicInfo__SWIG_0(
                VirgilPFSPublicKey.getCPtr(identityPublicKey), identityPublicKey,
                VirgilPFSPublicKey.getCPtr(longTermPublicKey), longTermPublicKey,
                VirgilPFSPublicKey.getCPtr(oneTimePublicKey), oneTimePublicKey), true);
    }

    protected VirgilPFSResponderPublicInfo(long cPtr, boolean cMemoryOwn) {
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
                virgil_crypto_javaJNI.delete_VirgilPFSResponderPublicInfo(swigCPtr);
            }
            swigCPtr = 0;
        }
    }

    public VirgilPFSPublicKey getIdentityPublicKey() {
        return new VirgilPFSPublicKey(
                virgil_crypto_javaJNI.VirgilPFSResponderPublicInfo_getIdentityPublicKey(swigCPtr, this), false);
    }

    public VirgilPFSPublicKey getLongTermPublicKey() {
        return new VirgilPFSPublicKey(
                virgil_crypto_javaJNI.VirgilPFSResponderPublicInfo_getLongTermPublicKey(swigCPtr, this), false);
    }

    public VirgilPFSPublicKey getOneTimePublicKey() {
        return new VirgilPFSPublicKey(
                virgil_crypto_javaJNI.VirgilPFSResponderPublicInfo_getOneTimePublicKey(swigCPtr, this), false);
    }

    protected void finalize() {
        delete();
    }

}
