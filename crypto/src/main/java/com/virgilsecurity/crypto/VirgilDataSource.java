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
 * This is base class for input streams.
 * 
 * Defines interface that allows read data from the input stream.
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilDataSource implements java.lang.AutoCloseable {
    protected static long getCPtr(VirgilDataSource obj) {
        return (obj == null) ? 0 : obj.swigCPtr;
    }
    private transient long swigCPtr;

    protected transient boolean swigCMemOwn;

    /**
     * Create a new instance of {@code VirgilDataSource}
     *
     */
    public VirgilDataSource() {
        this(virgil_crypto_javaJNI.new_VirgilDataSource(), true);
        virgil_crypto_javaJNI.VirgilDataSource_director_connect(this, swigCPtr, swigCMemOwn, true);
    }

    protected VirgilDataSource(long cPtr, boolean cMemoryOwn) {
        swigCMemOwn = cMemoryOwn;
        swigCPtr = cPtr;
    }

    @Override
    public void close() throws java.io.IOException {
        delete();
    }

    public synchronized void delete() {
        if (swigCPtr != 0) {
            if (swigCMemOwn) {
                swigCMemOwn = false;
                virgil_crypto_javaJNI.delete_VirgilDataSource(swigCPtr);
            }
            swigCPtr = 0;
        }
    }

    protected void finalize() {
        delete();
    }

    /**
     * @return Return {@code true} if target source still contains unread data.
     * @throws java.io.IOException
     *             if an error occurred.
     */
    public boolean hasData() throws java.io.IOException {
        return virgil_crypto_javaJNI.VirgilDataSource_hasData(swigCPtr, this);
    }

    /**
     * @return Return next portion of read data from target source.
     * 
     * @throws java.io.IOException
     *             if an error occurred.
     */
    public byte[] read() throws java.io.IOException {
        return virgil_crypto_javaJNI.VirgilDataSource_read(swigCPtr, this);
    }

    protected void swigDirectorDisconnect() {
        swigCMemOwn = false;
        delete();
    }

    public void swigReleaseOwnership() {
        swigCMemOwn = false;
        virgil_crypto_javaJNI.VirgilDataSource_change_ownership(this, swigCPtr, false);
    }

    public void swigTakeOwnership() {
        swigCMemOwn = true;
        virgil_crypto_javaJNI.VirgilDataSource_change_ownership(this, swigCPtr, true);
    }

}
