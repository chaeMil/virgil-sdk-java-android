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
 * Data object that represent ASN.1 structure.
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilCustomParams extends VirgilAsn1Compatible implements java.lang.AutoCloseable {
    protected static long getCPtr(VirgilCustomParams obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    private transient long swigCPtr;

    /**
     * Create a new instance of {@code VirgilCustomParams}
     *
     */
    public VirgilCustomParams() {
        this(virgil_crypto_javaJNI.new_VirgilCustomParams__SWIG_0(), true);
    }

    protected VirgilCustomParams(long cPtr, boolean cMemoryOwn) {
        super(virgil_crypto_javaJNI.VirgilCustomParams_SWIGUpcast(cPtr), cMemoryOwn);
        swigCPtr = cPtr;
    }

    /**
     * Create a new instance of {@code VirgilCustomParams}
     *
     * @param other
     *            the source custom parameters.
     */
    public VirgilCustomParams(VirgilCustomParams other) {
        this(virgil_crypto_javaJNI.new_VirgilCustomParams__SWIG_1(VirgilCustomParams.getCPtr(other), other), true);
    }

    /**
     * Remove all parameters.
     * 
     */
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

    protected void finalize() {
        delete();
    }

    /**
     * Get parameter of {@code byte array} type.
     * 
     * @param key
     *            The parameter key.
     * @return the parameter value.
     */
    public byte[] getData(byte[] key) {
        return virgil_crypto_javaJNI.VirgilCustomParams_getData(swigCPtr, this, key);
    }

    /**
     * Get parameter of {@code int} type.
     * 
     * @param key
     *            The parameter key.
     * @return the parameter value.
     */
    public int getInteger(byte[] key) {
        return virgil_crypto_javaJNI.VirgilCustomParams_getInteger(swigCPtr, this, key);
    }

    /**
     * Get parameter of {@code String} type.
     * 
     * @param key
     *            the parameter key.
     * @return the parameter value.
     */
    public byte[] getString(byte[] key) {
        return virgil_crypto_javaJNI.VirgilCustomParams_getString(swigCPtr, this, key);
    }

    /**
     * Define whether no one parameter is set.
     * 
     * @return {@code true} if no parameter set.
     */
    public boolean isEmpty() {
        return virgil_crypto_javaJNI.VirgilCustomParams_isEmpty(swigCPtr, this);
    }

    /**
     * Remove parameter of {@code byte array} type.
     * 
     * @param key
     *            The parameter key.
     */
    public void removeData(byte[] key) {
        virgil_crypto_javaJNI.VirgilCustomParams_removeData(swigCPtr, this, key);
    }

    /**
     * Remove parameter of {@code int} type.
     * 
     * @param key
     *            The parameter key.
     */
    public void removeInteger(byte[] key) {
        virgil_crypto_javaJNI.VirgilCustomParams_removeInteger(swigCPtr, this, key);
    }

    /**
     * Remove parameter of {@code String} type.
     * 
     * @param key
     *            the parameter key.
     */
    public void removeString(byte[] key) {
        virgil_crypto_javaJNI.VirgilCustomParams_removeString(swigCPtr, this, key);
    }

    /**
     * Set parameter of {@code byte array} type.
     * 
     * @param key
     *            The parameter key.
     * @param value
     *            The parameter value.
     */
    public void setData(byte[] key, byte[] value) {
        virgil_crypto_javaJNI.VirgilCustomParams_setData(swigCPtr, this, key, value);
    }

    /**
     * Set parameter of {@code int} type.
     * 
     * @param key
     *            The parameter key.
     * @param value
     *            The parameter value.
     */
    public void setInteger(byte[] key, int value) {
        virgil_crypto_javaJNI.VirgilCustomParams_setInteger(swigCPtr, this, key, value);
    }

    /**
     * Set parameter of {@code String} type.
     * 
     * @param key
     *            The parameter key.
     * @param value
     *            The parameter value.
     */
    public void setString(byte[] key, byte[] value) {
        virgil_crypto_javaJNI.VirgilCustomParams_setString(swigCPtr, this, key, value);
    }

}
