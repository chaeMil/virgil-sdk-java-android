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
 * This class handles information about Virgil Security key pair.
 * 
 * @author Andrii Iakovenko
 *
 */
public class VirgilKeyPair implements java.lang.AutoCloseable {
    /**
     * Type of the keypair.
     *
     * @author Andrii Iakovenko
     *
     */
    public final static class Type {

        /**
         * RSA 256 bit (not recommended)
         */
        public final static VirgilKeyPair.Type RSA_256 = new VirgilKeyPair.Type("RSA_256");

        /**
         * RSA 512 bit (not recommended)
         */
        public final static VirgilKeyPair.Type RSA_512 = new VirgilKeyPair.Type("RSA_512");

        /**
         * RSA 1024 bit (not recommended)
         */
        public final static VirgilKeyPair.Type RSA_1024 = new VirgilKeyPair.Type("RSA_1024");

        /**
         * RSA 2048 bit (not recommended)
         */
        public final static VirgilKeyPair.Type RSA_2048 = new VirgilKeyPair.Type("RSA_2048");

        /**
         * RSA 3072 bit.
         */
        public final static VirgilKeyPair.Type RSA_3072 = new VirgilKeyPair.Type("RSA_3072");

        /**
         * RSA 4096 bit.
         */
        public final static VirgilKeyPair.Type RSA_4096 = new VirgilKeyPair.Type("RSA_4096");

        /**
         * RSA 8192 bit.
         */
        public final static VirgilKeyPair.Type RSA_8192 = new VirgilKeyPair.Type("RSA_8192");

        /**
         * 192-bits NIST curve
         */
        public final static VirgilKeyPair.Type EC_SECP192R1 = new VirgilKeyPair.Type("EC_SECP192R1");

        /**
         * 224-bits NIST curve
         */
        public final static VirgilKeyPair.Type EC_SECP224R1 = new VirgilKeyPair.Type("EC_SECP224R1");

        /**
         * 256-bits NIST curve
         */
        public final static VirgilKeyPair.Type EC_SECP256R1 = new VirgilKeyPair.Type("EC_SECP256R1");

        /**
         * 384-bits NIST curve
         */
        public final static VirgilKeyPair.Type EC_SECP384R1 = new VirgilKeyPair.Type("EC_SECP384R1");

        /**
         * 521-bits NIST curve
         */
        public final static VirgilKeyPair.Type EC_SECP521R1 = new VirgilKeyPair.Type("EC_SECP521R1");

        /**
         * 256-bits Brainpool curve
         */
        public final static VirgilKeyPair.Type EC_BP256R1 = new VirgilKeyPair.Type("EC_BP256R1");

        /**
         * 384-bits Brainpool curve
         */
        public final static VirgilKeyPair.Type EC_BP384R1 = new VirgilKeyPair.Type("EC_BP384R1");

        /**
         * 512-bits Brainpool curve
         */
        public final static VirgilKeyPair.Type EC_BP512R1 = new VirgilKeyPair.Type("EC_BP512R1");

        /**
         * 192-bits "Koblitz" curve
         */
        public final static VirgilKeyPair.Type EC_SECP192K1 = new VirgilKeyPair.Type("EC_SECP192K1");

        /**
         * 224-bits "Koblitz" curve
         */
        public final static VirgilKeyPair.Type EC_SECP224K1 = new VirgilKeyPair.Type("EC_SECP224K1");

        /**
         * 256-bits "Koblitz" curve
         */
        public final static VirgilKeyPair.Type EC_SECP256K1 = new VirgilKeyPair.Type("EC_SECP256K1");

        /**
         * Curve25519 as ECP deprecated format.
         */
        public final static VirgilKeyPair.Type EC_CURVE25519 = new VirgilKeyPair.Type("EC_CURVE25519");

        /**
         * Curve25519.
         */
        public final static VirgilKeyPair.Type FAST_EC_X25519 = new VirgilKeyPair.Type("FAST_EC_X25519");

        /**
         * Ed25519.
         */
        public final static VirgilKeyPair.Type FAST_EC_ED25519 = new VirgilKeyPair.Type("FAST_EC_ED25519");

        private static Type[] swigValues = { RSA_256, RSA_512, RSA_1024, RSA_2048, RSA_3072, RSA_4096, RSA_8192,
                EC_SECP192R1, EC_SECP224R1, EC_SECP256R1, EC_SECP384R1, EC_SECP521R1, EC_BP256R1, EC_BP384R1,
                EC_BP512R1, EC_SECP192K1, EC_SECP224K1, EC_SECP256K1, EC_CURVE25519, FAST_EC_X25519, FAST_EC_ED25519 };

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
    /**
     * Check if given private key and it's password matches.
     * 
     * @param key
     *            Private key in DER or PEM format.
     * @param pwd
     *            Private key password.
     * @return {@code true} if private key and it's password matches.
     */
    public static boolean checkPrivateKeyPassword(byte[] key, byte[] pwd) {
        return virgil_crypto_javaJNI.VirgilKeyPair_checkPrivateKeyPassword(key, pwd);
    }

    /**
     * Decrypt the given private key and return result.
     * 
     * @param privateKey
     *            Encrypted Private Key.
     * @param privateKeyPassword
     *            Current Private Key password.
     * 
     * @return Plain (non encrypted) private key.
     */
    public static byte[] decryptPrivateKey(byte[] privateKey, byte[] privateKeyPassword) {
        return virgil_crypto_javaJNI.VirgilKeyPair_decryptPrivateKey(privateKey, privateKeyPassword);
    }

    /**
     * 
     * Encrypt the given private key and return result.
     * 
     * @param privateKey
     *            Private key in the plain text.
     * @param privateKeyPassword
     *            New Private Key password.
     * @return Encrypted private key in PKCS#8 format.
     */
    public static byte[] encryptPrivateKey(byte[] privateKey, byte[] privateKeyPassword) {
        return virgil_crypto_javaJNI.VirgilKeyPair_encryptPrivateKey(privateKey, privateKeyPassword);
    }

    /**
     * Extract public key from the private key.
     * 
     * 
     * @param privateKey
     *            Private key.
     * @param privateKeyPassword
     *            Private key password.
     * 
     * @return Public key.
     */
    public static byte[] extractPublicKey(byte[] privateKey, byte[] privateKeyPassword) {
        return virgil_crypto_javaJNI.VirgilKeyPair_extractPublicKey(privateKey, privateKeyPassword);
    }

    /**
     * Generate new key pair given type.
     * 
     * @param type
     *            the private key type to be generated.
     * @return generated key pair.
     */
    public static VirgilKeyPair generate(VirgilKeyPair.Type type) {
        return new VirgilKeyPair(virgil_crypto_javaJNI.VirgilKeyPair_generate__SWIG_1(type.swigValue()), true);
    }

    /**
     * Generate new key pair given type.
     * 
     * @param type
     *            the private key type to be generated.
     * @param pwd
     *            the private key password.
     * @return generated key pair.
     */
    public static VirgilKeyPair generate(VirgilKeyPair.Type type, byte[] pwd) {
        return new VirgilKeyPair(virgil_crypto_javaJNI.VirgilKeyPair_generate__SWIG_0(type.swigValue(), pwd), true);
    }

    /**
     * Generate new key pair of the same type based on the donor key pair.
     * 
     * 
     * @param donorKeyPair
     *            Public key or private key is used to determine the new key pair type.
     * @return generated key pair.
     */
    public static VirgilKeyPair generateFrom(VirgilKeyPair donorKeyPair) {
        return new VirgilKeyPair(virgil_crypto_javaJNI
                .VirgilKeyPair_generateFrom__SWIG_2(VirgilKeyPair.getCPtr(donorKeyPair), donorKeyPair), true);
    }

    /**
     * Generate new key pair of the same type based on the donor key pair.
     * 
     * 
     * @param donorKeyPair
     *            Public key or private key is used to determine the new key pair type.
     * @param donorPrivateKeyPassword
     *            Donor private key password, optional if public key is defined.
     * @return generated key pair.
     */
    public static VirgilKeyPair generateFrom(VirgilKeyPair donorKeyPair, byte[] donorPrivateKeyPassword) {
        return new VirgilKeyPair(virgil_crypto_javaJNI.VirgilKeyPair_generateFrom__SWIG_1(
                VirgilKeyPair.getCPtr(donorKeyPair), donorKeyPair, donorPrivateKeyPassword), true);
    }

    /**
     * Generate new key pair of the same type based on the donor key pair.
     * 
     * 
     * @param donorKeyPair
     *            Public key or private key is used to determine the new key pair type.
     * @param donorPrivateKeyPassword
     *            Donor private key password, optional if public key is defined.
     * @param newKeyPairPassword
     *            Private key password of the new key pair.
     * @return generated key pair.
     */
    public static VirgilKeyPair generateFrom(VirgilKeyPair donorKeyPair, byte[] donorPrivateKeyPassword,
            byte[] newKeyPairPassword) {
        return new VirgilKeyPair(virgil_crypto_javaJNI.VirgilKeyPair_generateFrom__SWIG_0(
                VirgilKeyPair.getCPtr(donorKeyPair), donorKeyPair, donorPrivateKeyPassword, newKeyPairPassword), true);
    }

    /**
     * Generate new key pair with recommended most safe type.
     * 
     * @return generated key pair.
     */
    public static VirgilKeyPair generateRecommended() {
        return new VirgilKeyPair(virgil_crypto_javaJNI.VirgilKeyPair_generateRecommended__SWIG_1(), true);
    }

    /**
     * Generate new key pair with recommended most safe type.
     * 
     * @param pwd
     *            Private key password.
     * @return generated key pair.
     */
    public static VirgilKeyPair generateRecommended(byte[] pwd) {
        return new VirgilKeyPair(virgil_crypto_javaJNI.VirgilKeyPair_generateRecommended__SWIG_0(pwd), true);
    }

    protected static long getCPtr(VirgilKeyPair obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    /**
     * Check if a public-private pair of keys matches.
     * 
     * 
     * @param publicKey
     *            Public key in DER or PEM format.
     * @param privateKey
     *            Private key in DER or PEM format.
     * @return {@code true} if keys matche.
     */
    public static boolean isKeyPairMatch(byte[] publicKey, byte[] privateKey) {
        return virgil_crypto_javaJNI.VirgilKeyPair_isKeyPairMatch__SWIG_1(publicKey, privateKey);
    }

    /**
     * Check if a public-private pair of keys matches.
     * 
     * 
     * @param publicKey
     *            Public key in DER or PEM format.
     * @param privateKey
     *            Private key in DER or PEM format.
     * @param privateKeyPassword
     *            Private key password if exists.
     * @return {@code true} if keys matche.
     */
    public static boolean isKeyPairMatch(byte[] publicKey, byte[] privateKey, byte[] privateKeyPassword) {
        return virgil_crypto_javaJNI.VirgilKeyPair_isKeyPairMatch__SWIG_0(publicKey, privateKey, privateKeyPassword);
    }

    /**
     * Check if given private key is encrypted.
     * 
     * 
     * @param privateKey
     *            Private key in DER or PEM format.
     * 
     * @return {@code true} - if private key is encrypted.
     */
    public static boolean isPrivateKeyEncrypted(byte[] privateKey) {
        return virgil_crypto_javaJNI.VirgilKeyPair_isPrivateKeyEncrypted(privateKey);
    }

    /**
     * Convert given private key to the DER format.
     * 
     * 
     * @param privateKey
     *            Private key to be converted.
     * 
     * @return Private key in the DER format.
     */
    public static byte[] privateKeyToDER(byte[] privateKey) {
        return virgil_crypto_javaJNI.VirgilKeyPair_privateKeyToDER__SWIG_1(privateKey);
    }

    /**
     * Convert given private key to the DER format.
     * 
     * 
     * @param privateKey
     *            Private key to be converted.
     * 
     * @param privateKeyPassword
     *            Private key password.
     * @return Private key in the DER format.
     */
    public static byte[] privateKeyToDER(byte[] privateKey, byte[] privateKeyPassword) {
        return virgil_crypto_javaJNI.VirgilKeyPair_privateKeyToDER__SWIG_0(privateKey, privateKeyPassword);
    }

    /**
     * Convert given private key to the PEM format.
     * 
     * 
     * @param privateKey
     *            Private key to be converted.
     * 
     * @return Private key in the PEM format.
     */
    public static byte[] privateKeyToPEM(byte[] privateKey) {
        return virgil_crypto_javaJNI.VirgilKeyPair_privateKeyToPEM__SWIG_1(privateKey);
    }

    /**
     * Convert given private key to the PEM format.
     * 
     * 
     * @param privateKey
     *            Private key to be converted.
     * 
     * @param privateKeyPassword
     *            Private key password.
     * @return Private key in the PEM format.
     */
    public static byte[] privateKeyToPEM(byte[] privateKey, byte[] privateKeyPassword) {
        return virgil_crypto_javaJNI.VirgilKeyPair_privateKeyToPEM__SWIG_0(privateKey, privateKeyPassword);
    }

    /**
     * Convert given public key to the DER format.
     * 
     * 
     * @param publicKey
     *            Public key to be converted.
     * 
     * @return Public key in the DER format.
     */
    public static byte[] publicKeyToDER(byte[] publicKey) {
        return virgil_crypto_javaJNI.VirgilKeyPair_publicKeyToDER(publicKey);
    }

    /**
     * Convert given public key to the PEM format.
     * 
     * @param publicKey
     *            Public key to be converted.
     * @return Public key in the PEM format.
     */
    public static byte[] publicKeyToPEM(byte[] publicKey) {
        return virgil_crypto_javaJNI.VirgilKeyPair_publicKeyToPEM(publicKey);
    }

    /**
     * <p>
     * Reset password for the given private key.
     * </p>
     * <p>
     * Re-encrypt given Private Key with a new password.
     * </p>
     * 
     * @param privateKey
     *            Private key that is encrypted with old password.
     * @param oldPassword
     *            Current Private Key password.
     * @param newPassword
     *            New Private Key password.
     * @return Private key that is encrypted with the new password.
     */
    public static byte[] resetPrivateKeyPassword(byte[] privateKey, byte[] oldPassword, byte[] newPassword) {
        return virgil_crypto_javaJNI.VirgilKeyPair_resetPrivateKeyPassword(privateKey, oldPassword, newPassword);
    }

    private transient long swigCPtr;

    protected transient boolean swigCMemOwn;

    /**
     * Create a new instance of {@code VirgilKeyPair}
     *
     * @param publicKey
     * @param privateKey
     */
    public VirgilKeyPair(byte[] publicKey, byte[] privateKey) {
        this(virgil_crypto_javaJNI.new_VirgilKeyPair__SWIG_0(publicKey, privateKey), true);
    }

    protected VirgilKeyPair(long cPtr, boolean cMemoryOwn) {
        swigCMemOwn = cMemoryOwn;
        swigCPtr = cPtr;
    }

    /**
     * Create a new instance of {@code VirgilKeyPair}
     *
     * @param other
     *            the source key pair.
     */
    public VirgilKeyPair(VirgilKeyPair other) {
        this(virgil_crypto_javaJNI.new_VirgilKeyPair__SWIG_1(VirgilKeyPair.getCPtr(other), other), true);
    }

    @Override
    public void close() {
        delete();
    }

    public synchronized void delete() {
        if (swigCPtr != 0) {
            if (swigCMemOwn) {
                swigCMemOwn = false;
                virgil_crypto_javaJNI.delete_VirgilKeyPair(swigCPtr);
            }
            swigCPtr = 0;
        }
    }

    protected void finalize() {
        delete();
    }

    /**
     * Provide access to the private key.
     * 
     * @return the private key.
     */
    public byte[] privateKey() {
        return virgil_crypto_javaJNI.VirgilKeyPair_privateKey(swigCPtr, this);
    }

    /**
     * Provide access to the public key.
     * 
     * @return the public key.
     */
    public byte[] publicKey() {
        return virgil_crypto_javaJNI.VirgilKeyPair_publicKey(swigCPtr, this);
    }

}
