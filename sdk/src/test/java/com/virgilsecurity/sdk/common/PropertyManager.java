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
 * (1) Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * (2) Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * (3) Neither the name of virgil nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
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

package com.virgilsecurity.sdk.common;

import org.apache.commons.lang.StringUtils;

public class PropertyManager {

/*    // -------------- DEV --------------
    protected final String APP_ID = getPropertyByName("APP_ID");
    protected final String ACCOUNT_ID = getPropertyByName("ACCOUNT_ID");

    protected final String APP_PRIVATE_KEY_PASSWORD = getPropertyByName("APP_PRIVATE_KEY_PASSWORD");

    protected final String API_PUBLIC_KEY = getPropertyByName("API_PUBLIC_KEY");
    protected final String API_PUBLIC_KEY_IDENTIFIER = getPropertyByName("API_PUBLIC_KEY_IDENTIFIER");
    protected final String API_PRIVATE_KEY_BASE64 = getPropertyByName("API_PRIVATE_KEY_BASE64"); // REPLACE \\n with \n

    protected final String SERVICE_CARD_ID = getPropertyByName("SERVICE_CARD_ID");
    protected final String SERVICE_PUBLIC_KEY_PEM_BASE64 = getPropertyByName("SERVICE_PUBLIC_KEY_PEM_BASE64");
    protected final String SERVICE_PUBLIC_KEY_DER_BASE64 = getPropertyByName("SERVICE_PUBLIC_KEY_DER_BASE64");

    protected final String CARDS_SERVICE_URL = getPropertyByName("CARDS_SERVICE_ADDRESS");*/

    // -------------- STAGE --------------
    protected final String APP_ID = getPropertyByName("STAGE_APP_ID");
    protected final String ACCOUNT_ID = getPropertyByName("STAGE_ACCOUNT_ID");

    protected final String APP_PRIVATE_KEY_PASSWORD = getPropertyByName("STAGE_APP_PRIVATE_KEY_PASSWORD");

    protected final String API_PUBLIC_KEY = getPropertyByName("STAGE_API_PUBLIC_KEY");
    protected final String API_PUBLIC_KEY_IDENTIFIER = getPropertyByName("STAGE_API_PUBLIC_KEY_IDENTIFIER");
    protected final String API_PRIVATE_KEY_BASE64 = getPropertyByName("STAGE_API_PRIVATE_KEY_BASE64"); // REPLACE \\n with \n

    protected final String SERVICE_CARD_ID = getPropertyByName("STAGE_SERVICE_CARD_ID");
    protected final String SERVICE_PUBLIC_KEY_PEM_BASE64 = getPropertyByName("STAGE_SERVICE_PUBLIC_KEY_PEM_BASE64");
    protected final String SERVICE_PUBLIC_KEY_DER_BASE64 = getPropertyByName("STAGE_SERVICE_PUBLIC_KEY_DER_BASE64");

    protected final String CARDS_SERVICE_URL = getPropertyByName("STAGE_CARDS_SERVICE_ADDRESS");

    public String getPropertyByName(String propertyName) {
        boolean isMacOs = System.getProperty("os.name")
                                .toLowerCase()
                                    .startsWith("mac os x");
        if (isMacOs) {
            if (StringUtils.isBlank(System.getenv(propertyName))) {
                return null;
            }

            return System.getenv(propertyName);
        } else {
            if (StringUtils.isBlank(System.getProperty(propertyName))) {
                return null;
            }

            return System.getProperty(propertyName);
        }
    }
}
