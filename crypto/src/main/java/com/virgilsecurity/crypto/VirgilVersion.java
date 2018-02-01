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
 * Provides information about Virgil library version.
 * 
 * @author Andrii Iakovenko
 *
 */
public class VirgilVersion implements java.lang.AutoCloseable {
    /**
     * @return version number in the format MMNNPP (Major, Minor, Patch).
     */
    public static long asNumber() {
        return virgil_crypto_javaJNI.VirgilVersion_asNumber();
    }
    /**
     * @return the version number as string.
     */
    public static String asString() {
        return virgil_crypto_javaJNI.VirgilVersion_asString();
    }

    /**
     * If current release contains some additional tag, like rc1, then version full name will be different from the
     * string returned by method asString(), i.e. 1.3.4-rc1, or 1.3.4-coolfeature, etc.
     * 
     * @return version full name.
     */
    public static String fullName() {
        return virgil_crypto_javaJNI.VirgilVersion_fullName();
    }

    protected static long getCPtr(VirgilVersion obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }

    /**
     * @return the major version number.
     */
    public static long majorVersion() {
        return virgil_crypto_javaJNI.VirgilVersion_majorVersion();
    }

    /**
     * @return the minor version number.
     */
    public static long minorVersion() {
        return virgil_crypto_javaJNI.VirgilVersion_minorVersion();
    }

    /**
     * @return the patch version number.
     */
    public static long patchVersion() {
        return virgil_crypto_javaJNI.VirgilVersion_patchVersion();
    }

    private transient long swigCPtr;

    protected transient boolean swigCMemOwn;

    /**
     * Create a new instance of {@code VirgilVersion}
     *
     */
    public VirgilVersion() {
        this(virgil_crypto_javaJNI.new_VirgilVersion(), true);
    }

    protected VirgilVersion(long cPtr, boolean cMemoryOwn) {
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
                virgil_crypto_javaJNI.delete_VirgilVersion(swigCPtr);
            }
            swigCPtr = 0;
        }
    }

    protected void finalize() {
        delete();
    }

}
