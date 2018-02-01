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

public class VirgilTinyCipher implements java.lang.AutoCloseable {
    public final static class PackageSize {
        public final static VirgilTinyCipher.PackageSize Min = new VirgilTinyCipher.PackageSize("Min",
                virgil_crypto_javaJNI.VirgilTinyCipher_Min_get());
        public final static VirgilTinyCipher.PackageSize Short_SMS = new VirgilTinyCipher.PackageSize("Short_SMS",
                virgil_crypto_javaJNI.VirgilTinyCipher_Short_SMS_get());
        public final static VirgilTinyCipher.PackageSize Long_SMS = new VirgilTinyCipher.PackageSize("Long_SMS",
                virgil_crypto_javaJNI.VirgilTinyCipher_Long_SMS_get());

        private static PackageSize[] swigValues = { Min, Short_SMS, Long_SMS };

        private static int swigNext = 0;

        public static PackageSize swigToEnum(int swigValue) {
            if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
                return swigValues[swigValue];
            for (int i = 0; i < swigValues.length; i++)
                if (swigValues[i].swigValue == swigValue)
                    return swigValues[i];
            throw new IllegalArgumentException("No enum " + PackageSize.class + " with value " + swigValue);
        }

        private final int swigValue;

        private final String swigName;

        private PackageSize(String swigName) {
            this.swigName = swigName;
            this.swigValue = swigNext++;
        }

        private PackageSize(String swigName, int swigValue) {
            this.swigName = swigName;
            this.swigValue = swigValue;
            swigNext = swigValue + 1;
        }

        private PackageSize(String swigName, PackageSize swigEnum) {
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

    protected static long getCPtr(VirgilTinyCipher obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    private transient long swigCPtr;

    protected transient boolean swigCMemOwn;

    public VirgilTinyCipher() {
        this(virgil_crypto_javaJNI.new_VirgilTinyCipher__SWIG_1(), true);
    }

    public VirgilTinyCipher(long packageSize) {
        this(virgil_crypto_javaJNI.new_VirgilTinyCipher__SWIG_0(packageSize), true);
    }

    protected VirgilTinyCipher(long cPtr, boolean cMemoryOwn) {
        swigCMemOwn = cMemoryOwn;
        swigCPtr = cPtr;
    }

    public void addPackage(byte[] arg0) {
        virgil_crypto_javaJNI.VirgilTinyCipher_addPackage(swigCPtr, this, arg0);
    }

    @Override
    public void close() {
        delete();
    }

    public byte[] decrypt(byte[] recipientPrivateKey) {
        return virgil_crypto_javaJNI.VirgilTinyCipher_decrypt__SWIG_1(swigCPtr, this, recipientPrivateKey);
    }

    public byte[] decrypt(byte[] recipientPrivateKey, byte[] recipientPrivateKeyPassword) {
        return virgil_crypto_javaJNI.VirgilTinyCipher_decrypt__SWIG_0(swigCPtr, this, recipientPrivateKey,
                recipientPrivateKeyPassword);
    }

    public synchronized void delete() {
        if (swigCPtr != 0) {
            if (swigCMemOwn) {
                swigCMemOwn = false;
                virgil_crypto_javaJNI.delete_VirgilTinyCipher(swigCPtr);
            }
            swigCPtr = 0;
        }
    }

    public void encrypt(byte[] data, byte[] recipientPublicKey) {
        virgil_crypto_javaJNI.VirgilTinyCipher_encrypt(swigCPtr, this, data, recipientPublicKey);
    }

    public void encryptAndSign(byte[] data, byte[] recipientPublicKey, byte[] senderPrivateKey) {
        virgil_crypto_javaJNI.VirgilTinyCipher_encryptAndSign__SWIG_1(swigCPtr, this, data, recipientPublicKey,
                senderPrivateKey);
    }

    public void encryptAndSign(byte[] data, byte[] recipientPublicKey, byte[] senderPrivateKey,
            byte[] senderPrivateKeyPassword) {
        virgil_crypto_javaJNI.VirgilTinyCipher_encryptAndSign__SWIG_0(swigCPtr, this, data, recipientPublicKey,
                senderPrivateKey, senderPrivateKeyPassword);
    }

    public byte[] getPackage(long index) {
        return virgil_crypto_javaJNI.VirgilTinyCipher_getPackage(swigCPtr, this, index);
    }

    public long getPackageCount() {
        return virgil_crypto_javaJNI.VirgilTinyCipher_getPackageCount(swigCPtr, this);
    }

    public boolean isPackagesAccumulated() {
        return virgil_crypto_javaJNI.VirgilTinyCipher_isPackagesAccumulated(swigCPtr, this);
    }

    public void reset() {
        virgil_crypto_javaJNI.VirgilTinyCipher_reset(swigCPtr, this);
    }

    public byte[] verifyAndDecrypt(byte[] senderPublicKey, byte[] recipientPrivateKey) {
        return virgil_crypto_javaJNI.VirgilTinyCipher_verifyAndDecrypt__SWIG_1(swigCPtr, this, senderPublicKey,
                recipientPrivateKey);
    }

    public byte[] verifyAndDecrypt(byte[] senderPublicKey, byte[] recipientPrivateKey,
            byte[] recipientPrivateKeyPassword) {
        return virgil_crypto_javaJNI.VirgilTinyCipher_verifyAndDecrypt__SWIG_0(swigCPtr, this, senderPublicKey,
                recipientPrivateKey, recipientPrivateKeyPassword);
    }

    protected void finalize() {
        delete();
    }

}
