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

public class VirgilAsymmetricCipher extends VirgilAsn1Compatible implements java.lang.AutoCloseable {
    public static boolean checkPrivateKeyPassword(byte[] key, byte[] pwd) {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_checkPrivateKeyPassword(key, pwd);
    }

    public static void checkPublicKey(byte[] key) {
        virgil_crypto_javaJNI.VirgilAsymmetricCipher_checkPublicKey(key);
    }

    public static byte[] computeShared(VirgilAsymmetricCipher publicContext, VirgilAsymmetricCipher privateContext) {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_computeShared(VirgilAsymmetricCipher.getCPtr(publicContext),
                publicContext, VirgilAsymmetricCipher.getCPtr(privateContext), privateContext);
    }

    public static boolean isKeyPairMatch(byte[] publicKey, byte[] privateKey) {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_isKeyPairMatch__SWIG_1(publicKey, privateKey);
    }

    public static boolean isKeyPairMatch(byte[] publicKey, byte[] privateKey, byte[] privateKeyPassword) {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_isKeyPairMatch__SWIG_0(publicKey, privateKey,
                privateKeyPassword);
    }

    public static boolean isPrivateKeyEncrypted(byte[] privateKey) {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_isPrivateKeyEncrypted(privateKey);
    }

    public static boolean isPublicKeyValid(byte[] key) {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_isPublicKeyValid(key);
    }

    protected static long getCPtr(VirgilAsymmetricCipher obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    private transient long swigCPtr;

    public VirgilAsymmetricCipher() {
        this(virgil_crypto_javaJNI.new_VirgilAsymmetricCipher(), true);
    }

    protected VirgilAsymmetricCipher(long cPtr, boolean cMemoryOwn) {
        super(virgil_crypto_javaJNI.VirgilAsymmetricCipher_SWIGUpcast(cPtr), cMemoryOwn);
        swigCPtr = cPtr;
    }

    @Override
    public void close() {
        delete();
    }

    public byte[] decrypt(byte[] in) {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_decrypt(swigCPtr, this, in);
    }

    public synchronized void delete() {
        if (swigCPtr != 0) {
            if (swigCMemOwn) {
                swigCMemOwn = false;
                virgil_crypto_javaJNI.delete_VirgilAsymmetricCipher(swigCPtr);
            }
            swigCPtr = 0;
        }
        super.delete();
    }

    public byte[] encrypt(byte[] in) {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_encrypt(swigCPtr, this, in);
    }

    public byte[] exportPrivateKeyToDER() {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_exportPrivateKeyToDER__SWIG_1(swigCPtr, this);
    }

    public byte[] exportPrivateKeyToDER(byte[] pwd) {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_exportPrivateKeyToDER__SWIG_0(swigCPtr, this, pwd);
    }

    public byte[] exportPrivateKeyToPEM() {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_exportPrivateKeyToPEM__SWIG_1(swigCPtr, this);
    }

    public byte[] exportPrivateKeyToPEM(byte[] pwd) {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_exportPrivateKeyToPEM__SWIG_0(swigCPtr, this, pwd);
    }

    public byte[] exportPublicKeyToDER() {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_exportPublicKeyToDER(swigCPtr, this);
    }

    public byte[] exportPublicKeyToPEM() {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_exportPublicKeyToPEM(swigCPtr, this);
    }

    public void genKeyPair(VirgilKeyPair.Type type) {
        virgil_crypto_javaJNI.VirgilAsymmetricCipher_genKeyPair(swigCPtr, this, type.swigValue());
    }

    public void genKeyPairFrom(VirgilAsymmetricCipher other) {
        virgil_crypto_javaJNI.VirgilAsymmetricCipher_genKeyPairFrom(swigCPtr, this,
                VirgilAsymmetricCipher.getCPtr(other), other);
    }

    public VirgilKeyPair.Type getKeyType() {
        return VirgilKeyPair.Type.swigToEnum(virgil_crypto_javaJNI.VirgilAsymmetricCipher_getKeyType(swigCPtr, this));
    }

    public byte[] getPublicKeyBits() {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_getPublicKeyBits(swigCPtr, this);
    }

    public long keyLength() {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_keyLength(swigCPtr, this);
    }

    public long keySize() {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_keySize(swigCPtr, this);
    }

    public void setKeyType(VirgilKeyPair.Type keyType) {
        virgil_crypto_javaJNI.VirgilAsymmetricCipher_setKeyType(swigCPtr, this, keyType.swigValue());
    }

    public void setPrivateKey(byte[] key) {
        virgil_crypto_javaJNI.VirgilAsymmetricCipher_setPrivateKey__SWIG_1(swigCPtr, this, key);
    }

    public void setPrivateKey(byte[] key, byte[] pwd) {
        virgil_crypto_javaJNI.VirgilAsymmetricCipher_setPrivateKey__SWIG_0(swigCPtr, this, key, pwd);
    }

    public void setPublicKey(byte[] key) {
        virgil_crypto_javaJNI.VirgilAsymmetricCipher_setPublicKey(swigCPtr, this, key);
    }

    public void setPublicKeyBits(byte[] bits) {
        virgil_crypto_javaJNI.VirgilAsymmetricCipher_setPublicKeyBits(swigCPtr, this, bits);
    }

    public byte[] sign(byte[] digest, int hashType) {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_sign(swigCPtr, this, digest, hashType);
    }

    public boolean verify(byte[] digest, byte[] sign, int hashType) {
        return virgil_crypto_javaJNI.VirgilAsymmetricCipher_verify(swigCPtr, this, digest, sign, hashType);
    }

    protected void finalize() {
        delete();
    }

}
