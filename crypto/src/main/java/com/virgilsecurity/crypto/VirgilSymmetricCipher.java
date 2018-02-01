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

public class VirgilSymmetricCipher extends VirgilAsn1Compatible implements java.lang.AutoCloseable {
    public final static class Algorithm {
        public final static VirgilSymmetricCipher.Algorithm AES_128_CBC = new VirgilSymmetricCipher.Algorithm(
                "AES_128_CBC");
        public final static VirgilSymmetricCipher.Algorithm AES_128_GCM = new VirgilSymmetricCipher.Algorithm(
                "AES_128_GCM");
        public final static VirgilSymmetricCipher.Algorithm AES_256_CBC = new VirgilSymmetricCipher.Algorithm(
                "AES_256_CBC");
        public final static VirgilSymmetricCipher.Algorithm AES_256_GCM = new VirgilSymmetricCipher.Algorithm(
                "AES_256_GCM");

        private static Algorithm[] swigValues = { AES_128_CBC, AES_128_GCM, AES_256_CBC, AES_256_GCM };

        private static int swigNext = 0;

        public static Algorithm swigToEnum(int swigValue) {
            if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
                return swigValues[swigValue];
            for (int i = 0; i < swigValues.length; i++)
                if (swigValues[i].swigValue == swigValue)
                    return swigValues[i];
            throw new IllegalArgumentException("No enum " + Algorithm.class + " with value " + swigValue);
        }

        private final int swigValue;

        private final String swigName;

        private Algorithm(String swigName) {
            this.swigName = swigName;
            this.swigValue = swigNext++;
        }

        private Algorithm(String swigName, Algorithm swigEnum) {
            this.swigName = swigName;
            this.swigValue = swigEnum.swigValue;
            swigNext = this.swigValue + 1;
        }

        private Algorithm(String swigName, int swigValue) {
            this.swigName = swigName;
            this.swigValue = swigValue;
            swigNext = swigValue + 1;
        }

        public final int swigValue() {
            return swigValue;
        }

        public String toString() {
            return swigName;
        }
    }

    public final static class Padding {
        public final static VirgilSymmetricCipher.Padding PKCS7 = new VirgilSymmetricCipher.Padding("PKCS7",
                virgil_crypto_javaJNI.VirgilSymmetricCipher_Padding_PKCS7_get());
        public final static VirgilSymmetricCipher.Padding OneAndZeros = new VirgilSymmetricCipher.Padding(
                "OneAndZeros");
        public final static VirgilSymmetricCipher.Padding ZerosAndLen = new VirgilSymmetricCipher.Padding(
                "ZerosAndLen");
        public final static VirgilSymmetricCipher.Padding Zeros = new VirgilSymmetricCipher.Padding("Zeros");
        public final static VirgilSymmetricCipher.Padding None = new VirgilSymmetricCipher.Padding("None");

        private static Padding[] swigValues = { PKCS7, OneAndZeros, ZerosAndLen, Zeros, None };

        private static int swigNext = 0;

        public static Padding swigToEnum(int swigValue) {
            if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
                return swigValues[swigValue];
            for (int i = 0; i < swigValues.length; i++)
                if (swigValues[i].swigValue == swigValue)
                    return swigValues[i];
            throw new IllegalArgumentException("No enum " + Padding.class + " with value " + swigValue);
        }

        private final int swigValue;

        private final String swigName;

        private Padding(String swigName) {
            this.swigName = swigName;
            this.swigValue = swigNext++;
        }

        private Padding(String swigName, int swigValue) {
            this.swigName = swigName;
            this.swigValue = swigValue;
            swigNext = swigValue + 1;
        }

        private Padding(String swigName, Padding swigEnum) {
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

    protected static long getCPtr(VirgilSymmetricCipher obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    private transient long swigCPtr;

    public VirgilSymmetricCipher() {
        this(virgil_crypto_javaJNI.new_VirgilSymmetricCipher__SWIG_0(), true);
    }

    public VirgilSymmetricCipher(String name) {
        this(virgil_crypto_javaJNI.new_VirgilSymmetricCipher__SWIG_2(name), true);
    }

    public VirgilSymmetricCipher(VirgilSymmetricCipher.Algorithm algorithm) {
        this(virgil_crypto_javaJNI.new_VirgilSymmetricCipher__SWIG_1(algorithm.swigValue()), true);
    }

    protected VirgilSymmetricCipher(long cPtr, boolean cMemoryOwn) {
        super(virgil_crypto_javaJNI.VirgilSymmetricCipher_SWIGUpcast(cPtr), cMemoryOwn);
        swigCPtr = cPtr;
    }

    public long authTagLength() {
        return virgil_crypto_javaJNI.VirgilSymmetricCipher_authTagLength(swigCPtr, this);
    }

    public long blockSize() {
        return virgil_crypto_javaJNI.VirgilSymmetricCipher_blockSize(swigCPtr, this);
    }

    public void clear() {
        virgil_crypto_javaJNI.VirgilSymmetricCipher_clear(swigCPtr, this);
    }

    @Override
    public void close() {
        delete();
    }

    public byte[] crypt(byte[] input, byte[] iv) {
        return virgil_crypto_javaJNI.VirgilSymmetricCipher_crypt(swigCPtr, this, input, iv);
    }

    public synchronized void delete() {
        if (swigCPtr != 0) {
            if (swigCMemOwn) {
                swigCMemOwn = false;
                virgil_crypto_javaJNI.delete_VirgilSymmetricCipher(swigCPtr);
            }
            swigCPtr = 0;
        }
        super.delete();
    }

    public byte[] finish() {
        return virgil_crypto_javaJNI.VirgilSymmetricCipher_finish(swigCPtr, this);
    }

    public boolean isAuthMode() {
        return virgil_crypto_javaJNI.VirgilSymmetricCipher_isAuthMode(swigCPtr, this);
    }

    public boolean isDecryptionMode() {
        return virgil_crypto_javaJNI.VirgilSymmetricCipher_isDecryptionMode(swigCPtr, this);
    }

    public boolean isEncryptionMode() {
        return virgil_crypto_javaJNI.VirgilSymmetricCipher_isEncryptionMode(swigCPtr, this);
    }

    public boolean isSupportPadding() {
        return virgil_crypto_javaJNI.VirgilSymmetricCipher_isSupportPadding(swigCPtr, this);
    }

    public byte[] iv() {
        return virgil_crypto_javaJNI.VirgilSymmetricCipher_iv(swigCPtr, this);
    }

    public long ivSize() {
        return virgil_crypto_javaJNI.VirgilSymmetricCipher_ivSize(swigCPtr, this);
    }

    public long keyLength() {
        return virgil_crypto_javaJNI.VirgilSymmetricCipher_keyLength(swigCPtr, this);
    }

    public long keySize() {
        return virgil_crypto_javaJNI.VirgilSymmetricCipher_keySize(swigCPtr, this);
    }

    public String name() {
        return virgil_crypto_javaJNI.VirgilSymmetricCipher_name(swigCPtr, this);
    }

    public void reset() {
        virgil_crypto_javaJNI.VirgilSymmetricCipher_reset(swigCPtr, this);
    }

    public void setAuthData(byte[] authData) {
        virgil_crypto_javaJNI.VirgilSymmetricCipher_setAuthData(swigCPtr, this, authData);
    }

    public void setDecryptionKey(byte[] key) {
        virgil_crypto_javaJNI.VirgilSymmetricCipher_setDecryptionKey(swigCPtr, this, key);
    }

    public void setEncryptionKey(byte[] key) {
        virgil_crypto_javaJNI.VirgilSymmetricCipher_setEncryptionKey(swigCPtr, this, key);
    }

    public void setIV(byte[] iv) {
        virgil_crypto_javaJNI.VirgilSymmetricCipher_setIV(swigCPtr, this, iv);
    }

    public void setPadding(VirgilSymmetricCipher.Padding padding) {
        virgil_crypto_javaJNI.VirgilSymmetricCipher_setPadding(swigCPtr, this, padding.swigValue());
    }

    public byte[] update(byte[] input) {
        return virgil_crypto_javaJNI.VirgilSymmetricCipher_update(swigCPtr, this, input);
    }

    protected void finalize() {
        delete();
    }

}
