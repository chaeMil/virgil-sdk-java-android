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

import java.util.HashMap;
import java.util.Map;

/**
 * Exception class for Virgil Identity Service operations.
 *
 * @author Andrii Iakovenko
 *
 */
public class VirgilIdentityServiceException extends VirgilServiceException {

    private static final long serialVersionUID = 6947954770582210688L;

    private static final Map<Integer, String> ERROR_MESSAGES;

    static {
        ERROR_MESSAGES = new HashMap<>();
        ERROR_MESSAGES.put(10000,
                "Internal application error. You know, shit happens, so do internal server errors.Just take a deep breath and try harder.");
        ERROR_MESSAGES.put(20300, "The Virgil access token was not specified or is invalid");
        ERROR_MESSAGES.put(20301, "The Virgil authenticator service responded with an error");
        ERROR_MESSAGES.put(20302, "The Virgil access token validation has failed on the Virgil Authenticator service");
        ERROR_MESSAGES.put(20303, "The application was not found for the acsses token");
        ERROR_MESSAGES.put(20400, "Request sign is invalid");
        ERROR_MESSAGES.put(20401, "Request sign header is missing");
        ERROR_MESSAGES.put(20500, "The Virgil Card is not available in this application");
        ERROR_MESSAGES.put(30000, "JSON specified as a request is invalid");
        ERROR_MESSAGES.put(30010, "A data inconsistency error");
        ERROR_MESSAGES.put(30100, "Global Virgil Card identity type is invalid, because it can be only an 'email'");
        ERROR_MESSAGES.put(30101, "Virgil Card scope must be either 'global' or 'application'");
        ERROR_MESSAGES.put(30102, "Virgil Card id validation failed");
        ERROR_MESSAGES.put(30103, "Virgil Card data parameter cannot contain more than 16 entries");
        ERROR_MESSAGES.put(30104,
                "Virgil Card info parameter cannot be empty if specified and must contain 'device' and/or 'device_name' key");
        ERROR_MESSAGES.put(30105,
                "Virgil Card info parameters length validation failed.The length cannot exceed 256 characters");
        ERROR_MESSAGES.put(30106,
                "Virgil Card data parameter must be an associative array(https://en.wikipedia.org/wiki/Associative_array)");
        ERROR_MESSAGES.put(30107,
                "A CSR parameter (card_sign_request or card_revoke_request) parameter is missing or is incorrect");
        ERROR_MESSAGES.put(30107,
                "A virgil_card object parameter was not found on create Virgil Card endpoint invocation");
        ERROR_MESSAGES.put(30111,
                "Virgil Card identities passed to search endpoint must be a list of non-empty strings");
        ERROR_MESSAGES.put(30112, "Virgil Card is_confirmed must be a boolean");
        ERROR_MESSAGES.put(30113, "Virgil Card identity type is invalid");
        ERROR_MESSAGES.put(30114, "Segregated Virgil Card custom identity value must be a not empty string");
        ERROR_MESSAGES.put(30115, "Virgil Card identity email is invalid");
        ERROR_MESSAGES.put(30116, "Virgil Card identity application is invalid");
        ERROR_MESSAGES.put(30117, "Public key length is invalid. It goes from 16 to 2048 bytes");
        ERROR_MESSAGES.put(30118, "Public key must be base64-encoded string");
        ERROR_MESSAGES.put(30119, "Virgil Card data parameter must be a key/value list of strings");
        ERROR_MESSAGES.put(30120, "Virgil Card data parameters must be strings");
        ERROR_MESSAGES.put(30121,
                "Virgil Card custom data entry value length validation failed.It mustn't exceed 256 characters");
        ERROR_MESSAGES.put(30122, "Identity validation token is invalid");
        ERROR_MESSAGES.put(30123, "SCR signs list parameter is missing or is invalid");
        ERROR_MESSAGES.put(30126,
                "SCR sign item signer card id is irrelevant and doesn't match Virgil Card id or Application Id");
        ERROR_MESSAGES.put(30127, "SCR sign item signed digest is invalid for the Virgil Card public key");
        ERROR_MESSAGES.put(30128, "SCR sign item signed digest is invalid for the application");
        ERROR_MESSAGES.put(30131,
                "Virgil Card id specified in the request body must match with the one passed in the URL");
        ERROR_MESSAGES.put(30134, "Virgil Card data parameters key must be aplphanumerical");
        ERROR_MESSAGES.put(30135, "Virgil Card validation token must be an object with value parameter");
        ERROR_MESSAGES.put(30136, "SCR sign item signed digest is invalid for the virgil identity service");
        ERROR_MESSAGES.put(30137,
                "Global Virigl Card cannot be created unconfirmed(which means that Virgil Identity service sign is mandatory)");
        ERROR_MESSAGES.put(30138, "Virigl Card with the same fingerprint exists already");
        ERROR_MESSAGES.put(30139, "Virigl Card revocation reason isn't specified or is invalid");
    }

    /**
     * Create a new instance of {@code VirgilIdentityServiceException}
     *
     * @param e
     *            the exception.
     */
    public VirgilIdentityServiceException(Exception e) {
        super(e);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.client.exceptions.VirgilServiceException#getMessage()
     */
    @Override
    public String getMessage() {
        String result = ERROR_MESSAGES.get(getErrorCode());
        if (result == null) {
            result = ERROR_UNKNOWN + ": " + getErrorCode();
        }
        return result;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.client.exceptions.VirgilServiceException# getMessageBundleName()
     */
    @Override
    protected String getMessageBundleName() {
        return "IdentityServiceMessages";
    }

}