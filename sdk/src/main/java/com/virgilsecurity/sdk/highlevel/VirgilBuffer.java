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
package com.virgilsecurity.sdk.highlevel;

import java.io.InputStream;

import com.virgilsecurity.sdk.exception.EmptyArgumentException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

/**
 * The {@linkplain VirgilBuffer} class provides a list of methods that simplify the work with an array of bytes.
 * 
 * @author Andrii Iakovenko
 *
 */
public class VirgilBuffer {

    private byte[] bytes;

    /**
     * @param bytes
     *            The byte array to be wrapped with buffer.
     */
    public VirgilBuffer(byte[] bytes) {
        if (bytes == null) {
            throw new NullArgumentException("bytes");
        } else if (bytes.length == 0) {
            throw new EmptyArgumentException("bytes");
        }
        this.bytes = bytes;
    }

    /**
     * Gets an array of bytes.
     * 
     * @return A byte array.
     */
    public byte[] getBytes() {
        return this.bytes;
    }

    /**
     * Allocates a new {@linkplain VirgilBuffer} using an array of bytes.
     * 
     * @param bytes
     *            An array of bytes to copy from.
     * @return A new instance of {@linkplain VirgilBuffer}.
     */
    public static VirgilBuffer from(byte[] bytes) {
        return new VirgilBuffer(bytes);
    }

    /**
     * Creates a new {@linkplain VirgilBuffer} containing the given string.
     * 
     * @param str
     *            String to encode.
     * @return A new instance of {@linkplain VirgilBuffer}.
     */
    public static VirgilBuffer from(String str) {
        return from(str, StringEncoding.UTF8);
    }

    /**
     * Creates a new {@linkplain VirgilBuffer} containing the given string. The encoding parameter identifies the
     * character encoding of string.
     * 
     * @param str
     *            String to encode.
     * @param encoding
     *            The encoding of string.
     * @return A new instance of {@linkplain VirgilBuffer}.
     */
    public static VirgilBuffer from(String str, StringEncoding encoding) {
        switch (encoding) {
        case UTF8:
            return new VirgilBuffer(ConvertionUtils.toBytes(str));
        case Base64:
            return new VirgilBuffer(ConvertionUtils.base64ToBytes(str));
        case Hex:
            return new VirgilBuffer(ConvertionUtils.hexToBytes(str));
        default:
            throw new IllegalArgumentException("String encoding type is not supported");
        }
    }

    /**
     * Creates a new {@linkplain VirgilBuffer} containing data read from the given stream.
     * 
     * @param inputStream
     *            The input data stream.
     * @return A new instance of {@linkplain VirgilBuffer}.
     */
    public static VirgilBuffer from(InputStream inputStream) {
        return from(ConvertionUtils.toString(inputStream), StringEncoding.UTF8);
    }

    /**
     * Creates a new {@linkplain VirgilBuffer} containing data read from the given stream. The encoding parameter
     * identifies the character encoding of stream data.
     * 
     * @param inputStream
     *            The input data stream.
     * @param encoding
     *            The encoding of string.
     * @return A new instance of {@linkplain VirgilBuffer}.
     */
    public static VirgilBuffer from(InputStream inputStream, StringEncoding encoding) {
        return from(ConvertionUtils.toString(inputStream), encoding);
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return toString(StringEncoding.UTF8);
    }

    /**
     * Decodes the current {@linkplain VirgilBuffer} to a string according to the specified character encoding in
     * {@code encoding} .
     * 
     * @param encoding
     *            The character encoding to decode to.
     * @return A {@linkplain String} that represents this instance.
     */
    public String toString(StringEncoding encoding) {
        switch (encoding) {
        case UTF8:
            return ConvertionUtils.toString(bytes);
        case Base64:
            return ConvertionUtils.toBase64String(bytes);
        case Hex:
            return ConvertionUtils.toHex(bytes);
        default:
            throw new IllegalArgumentException("String encoding type is not supported");
        }
    }

}
