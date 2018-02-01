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
 * This class contains conversion utils for byte sequence.
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilByteArrayUtils implements java.lang.AutoCloseable {
    /**
     * Translate given byte array to the HEX string.
     * 
     * @param array
     *            The byte array.
     * @return The HEX string.
     */
    public static String bytesToHex(byte[] array) {
        return virgil_crypto_javaJNI.VirgilByteArrayUtils_bytesToHex__SWIG_1(array);
    }
    /**
     * Translate given byte array to the HEX string.
     * 
     * @param array
     *            The byte array.
     * @param formatted
     *            If {@code true}, endline will be inserted every 16 bytes, and all bytes will be separated with
     *            whitespaces.
     * @return The HEX string.
     */
    public static String bytesToHex(byte[] array, boolean formatted) {
        return virgil_crypto_javaJNI.VirgilByteArrayUtils_bytesToHex__SWIG_0(array, formatted);
    }

    /**
     * Represent given byte array as string.
     * 
     * @param array
     *            The byte array.
     * @return the string.
     */
    public static String bytesToString(byte[] array) {
        return virgil_crypto_javaJNI.VirgilByteArrayUtils_bytesToString(array);
    }

    protected static long getCPtr(VirgilByteArrayUtils obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    /**
     * Translate given HEX string to the byte array.
     * 
     * @param hexStr
     *            The HEX string.
     * @return The byte array.
     */
    public static byte[] hexToBytes(String hexStr) {
        return virgil_crypto_javaJNI.VirgilByteArrayUtils_hexToBytes(hexStr);
    }

    /**
     * Represents given JSON object as byte array in canonical form.
     * 
     * @param json
     *            the json string.
     * @return The byte array.
     */
    public static byte[] jsonToBytes(String json) {
        return virgil_crypto_javaJNI.VirgilByteArrayUtils_jsonToBytes(json);
    }

    /**
     * Represents given string as byte array.
     * 
     * @param str
     *            the string.
     * @return The byte array.
     */
    public static byte[] stringToBytes(String str) {
        return virgil_crypto_javaJNI.VirgilByteArrayUtils_stringToBytes(str);
    }

    private transient long swigCPtr;

    protected transient boolean swigCMemOwn;

    protected VirgilByteArrayUtils(long cPtr, boolean cMemoryOwn) {
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
                virgil_crypto_javaJNI.delete_VirgilByteArrayUtils(swigCPtr);
            }
            swigCPtr = 0;
        }
    }

    protected void finalize() {
        delete();
    }

}
