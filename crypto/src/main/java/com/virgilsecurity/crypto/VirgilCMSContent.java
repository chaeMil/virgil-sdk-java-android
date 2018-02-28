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

public class VirgilCMSContent extends VirgilAsn1Compatible implements java.lang.AutoCloseable {
    public final static class Type {
        public final static VirgilCMSContent.Type Data = new VirgilCMSContent.Type("Data",
                virgil_crypto_javaJNI.VirgilCMSContent_Type_Data_get());
        public final static VirgilCMSContent.Type SignedData = new VirgilCMSContent.Type("SignedData");
        public final static VirgilCMSContent.Type EnvelopedData = new VirgilCMSContent.Type("EnvelopedData");
        public final static VirgilCMSContent.Type DigestedData = new VirgilCMSContent.Type("DigestedData");
        public final static VirgilCMSContent.Type EncryptedData = new VirgilCMSContent.Type("EncryptedData");
        public final static VirgilCMSContent.Type AuthenticatedData = new VirgilCMSContent.Type("AuthenticatedData");
        public final static VirgilCMSContent.Type SignedAndEnvelopedData = new VirgilCMSContent.Type(
                "SignedAndEnvelopedData");
        public final static VirgilCMSContent.Type DataWithAttributes = new VirgilCMSContent.Type("DataWithAttributes");
        public final static VirgilCMSContent.Type EncryptedPrivateKeyInfo = new VirgilCMSContent.Type(
                "EncryptedPrivateKeyInfo");

        private static Type[] swigValues = { Data, SignedData, EnvelopedData, DigestedData, EncryptedData,
                AuthenticatedData, SignedAndEnvelopedData, DataWithAttributes, EncryptedPrivateKeyInfo };

        private static int swigNext = 0;

        public static Type swigToEnum(int swigValue) {
            if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
                return swigValues[swigValue];
            for (int i = 0; i < swigValues.length; i++)
                if (swigValues[i].swigValue == swigValue)
                    return swigValues[i];
            throw new IllegalArgumentException("No enum " + Type.class + " with value " + swigValue);
        }

        private final int swigValue;

        private final String swigName;

        private Type(String swigName) {
            this.swigName = swigName;
            this.swigValue = swigNext++;
        }

        private Type(String swigName, int swigValue) {
            this.swigName = swigName;
            this.swigValue = swigValue;
            swigNext = swigValue + 1;
        }

        private Type(String swigName, Type swigEnum) {
            this.swigName = swigName;
            this.swigValue = swigEnum.swigValue;
            swigNext = this.swigValue + 1;
        }

        public final int swigValue() {
            return swigValue;
        }

        public String toString() {
            return swigName;
        }
    }

    protected static long getCPtr(VirgilCMSContent obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    private transient long swigCPtr;

    public VirgilCMSContent() {
        this(virgil_crypto_javaJNI.new_VirgilCMSContent__SWIG_0(), true);
    }

    public VirgilCMSContent(VirgilCMSContent other) {
        this(virgil_crypto_javaJNI.new_VirgilCMSContent__SWIG_1(VirgilCMSContent.getCPtr(other), other), true);
    }

    protected VirgilCMSContent(long cPtr, boolean cMemoryOwn) {
        super(virgil_crypto_javaJNI.VirgilCMSContent_SWIGUpcast(cPtr), cMemoryOwn);
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
                virgil_crypto_javaJNI.delete_VirgilCMSContent(swigCPtr);
            }
            swigCPtr = 0;
        }
        super.delete();
    }

    public byte[] getContent() {
        return virgil_crypto_javaJNI.VirgilCMSContent_content_get(swigCPtr, this);
    }

    public VirgilCMSContent.Type getContentType() {
        return VirgilCMSContent.Type.swigToEnum(virgil_crypto_javaJNI.VirgilCMSContent_contentType_get(swigCPtr, this));
    }

    public void setContent(byte[] value) {
        virgil_crypto_javaJNI.VirgilCMSContent_content_set(swigCPtr, this, value);
    }

    public void setContentType(VirgilCMSContent.Type value) {
        virgil_crypto_javaJNI.VirgilCMSContent_contentType_set(swigCPtr, this, value.swigValue());
    }

    protected void finalize() {
        delete();
    }

}
