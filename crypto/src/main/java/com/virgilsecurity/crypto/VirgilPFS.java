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

public class VirgilPFS implements java.lang.AutoCloseable {
    protected static long getCPtr(VirgilPFS obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    private transient long swigCPtr;

    protected transient boolean swigCMemOwn;

    public VirgilPFS() {
        this(virgil_crypto_javaJNI.new_VirgilPFS(), true);
    }

    protected VirgilPFS(long cPtr, boolean cMemoryOwn) {
        swigCMemOwn = cMemoryOwn;
        swigCPtr = cPtr;
    }

    @Override
    public void close() {
        delete();
    }

    public byte[] decrypt(VirgilPFSEncryptedMessage encryptedMessage) {
        return virgil_crypto_javaJNI.VirgilPFS_decrypt(swigCPtr, this,
                VirgilPFSEncryptedMessage.getCPtr(encryptedMessage), encryptedMessage);
    }

    public synchronized void delete() {
        if (swigCPtr != 0) {
            if (swigCMemOwn) {
                swigCMemOwn = false;
                virgil_crypto_javaJNI.delete_VirgilPFS(swigCPtr);
            }
            swigCPtr = 0;
        }
    }

    public VirgilPFSEncryptedMessage encrypt(byte[] data) {
        return new VirgilPFSEncryptedMessage(virgil_crypto_javaJNI.VirgilPFS_encrypt(swigCPtr, this, data), true);
    }

    public VirgilPFSSession getSession() {
        return new VirgilPFSSession(virgil_crypto_javaJNI.VirgilPFS_getSession(swigCPtr, this), true);
    }

    public void setSession(VirgilPFSSession session) {
        virgil_crypto_javaJNI.VirgilPFS_setSession(swigCPtr, this, VirgilPFSSession.getCPtr(session), session);
    }

    public VirgilPFSSession startInitiatorSession(VirgilPFSInitiatorPrivateInfo initiatorPrivateInfo,
            VirgilPFSResponderPublicInfo responderPublicInfo) {
        return new VirgilPFSSession(virgil_crypto_javaJNI.VirgilPFS_startInitiatorSession__SWIG_1(swigCPtr, this,
                VirgilPFSInitiatorPrivateInfo.getCPtr(initiatorPrivateInfo), initiatorPrivateInfo,
                VirgilPFSResponderPublicInfo.getCPtr(responderPublicInfo), responderPublicInfo), true);
    }

    public VirgilPFSSession startInitiatorSession(VirgilPFSInitiatorPrivateInfo initiatorPrivateInfo,
            VirgilPFSResponderPublicInfo responderPublicInfo, byte[] additionalData) {
        return new VirgilPFSSession(virgil_crypto_javaJNI.VirgilPFS_startInitiatorSession__SWIG_0(swigCPtr, this,
                VirgilPFSInitiatorPrivateInfo.getCPtr(initiatorPrivateInfo), initiatorPrivateInfo,
                VirgilPFSResponderPublicInfo.getCPtr(responderPublicInfo), responderPublicInfo, additionalData), true);
    }

    public VirgilPFSSession startResponderSession(VirgilPFSResponderPrivateInfo responderPrivateInfo,
            VirgilPFSInitiatorPublicInfo initiatorPublicInfo) {
        return new VirgilPFSSession(virgil_crypto_javaJNI.VirgilPFS_startResponderSession__SWIG_1(swigCPtr, this,
                VirgilPFSResponderPrivateInfo.getCPtr(responderPrivateInfo), responderPrivateInfo,
                VirgilPFSInitiatorPublicInfo.getCPtr(initiatorPublicInfo), initiatorPublicInfo), true);
    }

    public VirgilPFSSession startResponderSession(VirgilPFSResponderPrivateInfo responderPrivateInfo,
            VirgilPFSInitiatorPublicInfo initiatorPublicInfo, byte[] additionalData) {
        return new VirgilPFSSession(virgil_crypto_javaJNI.VirgilPFS_startResponderSession__SWIG_0(swigCPtr, this,
                VirgilPFSResponderPrivateInfo.getCPtr(responderPrivateInfo), responderPrivateInfo,
                VirgilPFSInitiatorPublicInfo.getCPtr(initiatorPublicInfo), initiatorPublicInfo, additionalData), true);
    }

    protected void finalize() {
        delete();
    }

}
