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
package com.virgilsecurity.sdk.client.requests;

/**
 * Unit tests for {@linkplain PublishCardRequest}
 *
 * @author Andrii Iakovenko
 *
 */
public class PublishCardRequestTest {
/*
    private static final String IDENTITY = "test@mail.com";
    private static final String IDENTITY_TYPE = GlobalCardIdentityType.APPLICATION.getRawKey();

    private Crypto crypto;
    private PublishCardRequest request;
    private CardInfoModel cardInfo;

    @Before
    public void setUp() {
        crypto = new VirgilCrypto();
        KeyPair keyPair = crypto.generateKeys();
        byte[] publicKey = crypto.exportPublicKey(keyPair.getPublicKey());

        cardInfo = new CardInfoModel();
        cardInfo.setDevice("Google Nexus 6");
        cardInfo.setDeviceName("MyDevice");

        request = new PublishCardRequest(IDENTITY, IDENTITY_TYPE, publicKey, cardInfo);
    }

    @Test
    public void export_import() {
        String exportedRequest = request.exportRequest();
        PublishCardRequest importedRequest = new PublishCardRequest(exportedRequest);

        assertArrayEquals(request.getSnapshot(), importedRequest.getSnapshot());
        assertArrayEquals(request.getRequestModel().getContentSnapshot(), importedRequest.getRequestModel().getContentSnapshot());
        assertEquals(request.getRequestModel().getMeta().getValidation(), request.getRequestModel().getMeta().getValidation());
        assertEquals(request.getSignatures(), importedRequest.getSignatures());
    }
*/
}
