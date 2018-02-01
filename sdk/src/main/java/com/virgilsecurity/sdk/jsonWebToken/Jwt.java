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

package com.virgilsecurity.sdk.jsonWebToken;

import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.jsonWebToken.contract.AccessToken;

public class Jwt implements AccessToken {

    private JwtHeaderContent headerContent;
    private JwtBodyContent bodyContent;
    private byte[] signatureData;

    public Jwt(JwtHeaderContent headerContent,
               JwtBodyContent bodyContent) {
        if (headerContent != null)
            this.headerContent = headerContent;
        else
            throw new IllegalArgumentException("Jwt -> 'headerContent' should not be null");

        if (bodyContent != null)
            this.bodyContent = bodyContent;
        else
            throw new IllegalArgumentException("Jwt -> 'bodyContent' should not be null");
    }

    public Jwt(JwtHeaderContent headerContent,
               JwtBodyContent bodyContent,
               byte[] signatureData) {
        if (headerContent != null)
            this.headerContent = headerContent;
        else
            throw new IllegalArgumentException("Jwt -> 'headerContent' should not be null");

        if (bodyContent != null)
            this.bodyContent = bodyContent;
        else
            throw new IllegalArgumentException("Jwt -> 'bodyContent' should not be null");

        if (signatureData != null)
            this.signatureData = signatureData;
        else
            throw new IllegalArgumentException("Jwt -> 'signatureData' should not be null");
    }

    public Jwt(String jwtToken) {
        String[] jwtParts = jwtToken.split(".");

        if (jwtParts.length != 3)
            throw new IllegalArgumentException("Jwt -> 'jwtToken' has wrong format");

        headerContent = JwtParser.parseJwtHeaderContent(jwtParts[0]);
        bodyContent = JwtParser.parseJwtBodyContent(jwtParts[1]);
        signatureData = ConvertionUtils.toBase64Bytes(jwtParts[2]);
    }

    public JwtHeaderContent getHeaderContent() {
        return headerContent;
    }

    public JwtBodyContent getBodyContent() {
        return bodyContent;
    }

    public byte[] getSignatureData() {
        return signatureData;
    }

    public void setSignatureData(byte[] signatureData) {
        this.signatureData = signatureData;
    }

    @Override public String getIdentity() {
        return bodyContent.getIdentity();
    }

    public boolean isExpired() {
        return bodyContent.getExpiresAt().isExpired();
    }

    private String headerBase64url() {
        return ConvertionUtils.toBase64Url(ConvertionUtils.toBase64String(ConvertionUtils.captureSnapshot(headerContent)));
    }

    private String bodyBase64url() {
        return ConvertionUtils.toBase64Url(ConvertionUtils.toBase64String(ConvertionUtils.captureSnapshot(bodyContent)));
    }

    private String signatureBase64url() {
        return ConvertionUtils.toBase64Url(ConvertionUtils.toBase64String(signatureData));
    }

    public byte[] snapshotWithoutSignatures() {
        return (headerBase64url() + "." + bodyBase64url()).getBytes();
    }

    @Override
    public String toString() {
        if (signatureData != null)
            return headerBase64url() + "." + bodyBase64url() + "." + signatureBase64url();
        else
            return headerBase64url() + "." + bodyBase64url() + ".";
    }
}
