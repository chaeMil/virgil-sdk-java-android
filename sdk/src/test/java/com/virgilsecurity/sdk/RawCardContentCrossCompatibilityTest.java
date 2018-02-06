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
package com.virgilsecurity.sdk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.virgilsecurity.sdk.cards.model.RawCardContent;
import com.virgilsecurity.sdk.cards.model.RawSignature;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;

/**
 * @author Andrii Iakovenko
 *
 */
public class RawCardContentCrossCompatibilityTest {

    private JsonObject sampleJson;

    @Before
    public void setup() {
        sampleJson = (JsonObject) new JsonParser().parse(new InputStreamReader(
                this.getClass().getClassLoader().getResourceAsStream("com/virgilsecurity/sdk/test_data.txt")));
    }

    @Test
    public void test_STC_1() throws IOException {
        // From string
        String rawCardString = sampleJson.get("STC-1.as_string").getAsString();
        assertNotNull(rawCardString);

        RawSignedModel rawCard1 = RawSignedModel.fromString(rawCardString);
        assertTrue(rawCard1.getSignatures().isEmpty());

        RawCardContent cardContent1 = new RawCardContent(rawCard1.getContentSnapshot());

        assertEquals("test", cardContent1.getIdentity());
        assertEquals("MCowBQYDK2VwAyEA6d9bQQFuEnU8vSmx9fDo0Wxec42JdNg4VR4FOr4/BUk=", cardContent1.getPublicKey());
        assertEquals("5.0", cardContent1.getVersion());
        assertEquals(1515686245, cardContent1.getCreatedAtTimestamp());
        assertNull(cardContent1.getPreviousCardId());

        // From json
        String rawCardJson = sampleJson.get("STC-1.as_json").getAsString();
        assertNotNull(rawCardJson);

        RawSignedModel rawCard2 = RawSignedModel.fromJson(rawCardJson);
        assertTrue(rawCard2.getSignatures().isEmpty());

        RawCardContent cardContent2 = new RawCardContent(rawCard2.getContentSnapshot());
        assertTrue(equals(cardContent1, cardContent2));

        // Snapshot
        byte[] snapshot1 = cardContent1.snapshot();
        assertNotNull(snapshot1);

        RawSignedModel newRawCard1 = new RawSignedModel(snapshot1, rawCard1.getSignatures());

        String exportedRawCardString = rawCard1.exportAsString();
        assertNotNull(exportedRawCardString);

        RawSignedModel newImportedRawCard1 = RawSignedModel.fromString(exportedRawCardString);
        assertNotNull(newImportedRawCard1);
        assertTrue(newImportedRawCard1.getSignatures().isEmpty());

        RawCardContent newCardContent1 = new RawCardContent(newImportedRawCard1.getContentSnapshot());
        assertTrue(equals(cardContent1, newCardContent1));

        // TODO maybe JSON Object???
        String exportedRawCardJson = newRawCard1.exportAsJson();
        assertNotNull(exportedRawCardJson);

        RawSignedModel newImportedRawCard2 = RawSignedModel.fromJson(exportedRawCardJson);
        assertNotNull(newImportedRawCard2);
        assertTrue(newImportedRawCard2.getSignatures().isEmpty());

        RawCardContent newCardContent2 = new RawCardContent(newImportedRawCard2.getContentSnapshot());
        assertTrue(equals(cardContent2, newCardContent2));

        // XCTAssert(exportedRawCardJson[@"previous_card_id"] == nil);
    }

    @Test
    public void test_STC_2() throws IOException {
        // From string
        String rawCardString = sampleJson.get("STC-2.as_string").getAsString();
        assertNotNull(rawCardString);

        RawSignedModel rawCard1 = RawSignedModel.fromString(rawCardString);
        assertEquals(3, rawCard1.getSignatures().size());
        for (RawSignature signature : rawCard1.getSignatures()) {
            switch (signature.getSigner()) {
            case "self":
                assertEquals(
                        "MFEwDQYJYIZIAWUDBAIDBQAEQNXguibY1cDCfnuJhTK+jX/Qv6v5i5TzqQs3e1fWlbisdUWYh+s10gsLkhf83wOqrm8ZXUCpjgkJn83TDaKYZQ8=",
                        signature.getSignature());
                assertNull(signature.getSnapshot());
                break;
            case "virgil":
                assertEquals(
                        "MFEwDQYJYIZIAWUDBAIDBQAEQNXguibY1cDCfnuJhTK+jX/Qv6v5i5TzqQs3e1fWlbisdUWYh+s10gsLkhf83wOqrm8ZXUCpjgkJn83TDaKYZQ8=",
                        signature.getSignature());
                assertNull(signature.getSnapshot());
                break;
            case "extra":
                assertEquals(
                        "MFEwDQYJYIZIAWUDBAIDBQAEQOGsh+lzM99RQB3NJOioriRfpCDyTdPC62uZi0MDYqgXVJMcxhRnRRMWzYC1BKAoUzCRc9W+cblEpCi2Ny0zpAU=",
                        signature.getSignature());
                assertNull(signature.getSnapshot());
                break;
            default:
                fail();
                break;
            }
        }

        RawCardContent cardContent1 = new RawCardContent(rawCard1.getContentSnapshot());

        assertEquals("test", cardContent1.getIdentity());
        assertEquals("MCowBQYDK2VwAyEA6d9bQQFuEnU8vSmx9fDo0Wxec42JdNg4VR4FOr4/BUk=", cardContent1.getPublicKey());
        assertEquals("5.0", cardContent1.getVersion());
        assertEquals(1515686245, cardContent1.getCreatedAtTimestamp());
        assertEquals("a666318071274adb738af3f67b8c7ec29d954de2cabfd71a942e6ea38e59fff9",
                cardContent1.getPreviousCardId());

        // From json
        String rawCardJson = sampleJson.get("STC-2.as_json").getAsString();
        assertNotNull(rawCardJson);

        RawSignedModel rawCard2 = RawSignedModel.fromJson(rawCardJson);
        assertEquals(3, rawCard2.getSignatures().size());
        verifyEquality(rawCard1.getSignatures(), rawCard2.getSignatures());

        RawCardContent cardContent2 = new RawCardContent(rawCard2.getContentSnapshot());
        assertTrue(equals(cardContent1, cardContent2));

        // Snapshot
        byte[] snapshot1 = cardContent1.snapshot();
        assertNotNull(snapshot1);

        RawSignedModel newRawCard1 = new RawSignedModel(snapshot1, rawCard1.getSignatures());

        String exportedRawCardString = rawCard1.exportAsString();
        assertNotNull(exportedRawCardString);

        RawSignedModel newImportedRawCard1 = RawSignedModel.fromString(exportedRawCardString);
        assertNotNull(newImportedRawCard1);
        assertEquals(3, newImportedRawCard1.getSignatures().size());
        verifyEquality(rawCard1.getSignatures(), newImportedRawCard1.getSignatures());

        RawCardContent newCardContent1 = new RawCardContent(newImportedRawCard1.getContentSnapshot());
        assertTrue(equals(cardContent1, newCardContent1));

        // TODO maybe JSON Object???
        String exportedRawCardJson = newRawCard1.exportAsJson();
        assertNotNull(exportedRawCardJson);

        RawSignedModel newImportedRawCard2 = RawSignedModel.fromJson(exportedRawCardJson);
        assertNotNull(newImportedRawCard2);
        assertEquals(3, newImportedRawCard2.getSignatures().size());
        verifyEquality(rawCard2.getSignatures(), newImportedRawCard2.getSignatures());

        RawCardContent newCardContent2 = new RawCardContent(newImportedRawCard2.getContentSnapshot());
        assertTrue(equals(cardContent2, newCardContent2));

        // XCTAssert(exportedRawCardJson[@"previous_card_id"] == nil);
    }

    private boolean equals(RawCardContent content1, RawCardContent content2) {
        return StringUtils.equals(content1.getIdentity(), content2.getIdentity())
                && StringUtils.equals(content1.getPublicKey(), content2.getPublicKey())
                && StringUtils.equals(content1.getVersion(), content2.getVersion())
                && content1.getCreatedAtTimestamp() == content2.getCreatedAtTimestamp()
                && StringUtils.equals(content1.getPreviousCardId(), content2.getPreviousCardId());
    }

    private boolean equals(RawSignature signature1, RawSignature signature2) {
        return StringUtils.equals(signature1.getSigner(), signature2.getSigner())
                && StringUtils.equals(signature1.getSignature(), signature2.getSignature())
                && StringUtils.equals(signature1.getSnapshot(), signature2.getSnapshot());
    }

    private void verifyEquality(List<RawSignature> signatures1, List<RawSignature> signatures2) {
        if (signatures1.size() != signatures2.size()) {
            fail("Signatures lists are differs by size");
        }
        for (int i = 0; i < signatures1.size(); i++) {
            if (!equals(signatures1.get(i), signatures2.get(i))) {
                fail("Signatures are not equals: " + i);
            }
        }
    }
}
