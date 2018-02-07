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
package com.virgilsecurity.sdk.client.exceptions;

import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * Base exception class for all Virgil Services operations
 *
 * @author Andrii Iakovenko
 *
 */
public abstract class VirgilServiceException extends Exception {

    private static final long serialVersionUID = -1143173438484224903L;

    protected static final String ERROR_UNKNOWN = "Unknown error";

    private int errorCode = 0;
    private String message;

    /**
     * Create a new instance of {@code VirgilServiceException}
     */
    public VirgilServiceException() {
    }

    /**
     * Create a new instance of {@code VirgilServiceException}
     *
     * @param code
     *            The error code.
     */
    public VirgilServiceException(int code) {
        this.errorCode = code;
    }

    /**
     * Create a new instance of {@code VirgilServiceException}
     *
     * @param code
     *            The error code.
     * @param message
     *            The error message.
     */
    public VirgilServiceException(int code, String message) {
        this.errorCode = code;
        this.message = message;
    }

    /**
     * Create a new instance of {@code VirgilServiceException}
     *
     * @param code
     *            The error code.
     * @param cause
     *            The cause.
     */
    public VirgilServiceException(int code, Exception cause) {
        super(cause);

        this.errorCode = code;
    }

    /**
     * Create a new instance of {@code VirgilServiceException}
     *
     * @param cause
     *            The cause.
     */
    public VirgilServiceException(Exception cause) {
        super(cause);
        this.errorCode = -1;
    }

    /**
     * @return the error code.
     */
    public int getErrorCode() {
        return errorCode;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Throwable#getMessage()
     */
    @Override
    public String getMessage() {
        if (errorCode == -1)
            return super.getMessage();

        try {
            ResourceBundle bundle = ResourceBundle.getBundle(getMessageBundleName());
            String key = String.valueOf(this.errorCode);
            if (bundle.containsKey(key))
                return bundle.getString(key);

        } catch (MissingResourceException ignored) {
        }

        if (message != null)
            return message + ": " + errorCode;

        return ERROR_UNKNOWN + ": " + errorCode;
    }

    /**
     * @return The message bundle name
     */
    protected abstract String getMessageBundleName();

}
