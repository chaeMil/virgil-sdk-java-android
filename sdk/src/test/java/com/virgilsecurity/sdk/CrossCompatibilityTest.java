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

import com.virgilsecurity.sdk.cards.Card;
import com.virgilsecurity.sdk.cards.CardManager;
import com.virgilsecurity.sdk.cards.ModelSigner;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.client.CardClient;
import com.virgilsecurity.sdk.cards.model.RawCardContent;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.common.ClassForSerialization;
import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jsonWebToken.Jwt;
import com.virgilsecurity.sdk.jsonWebToken.JwtGenerator;
import com.virgilsecurity.sdk.jsonWebToken.JwtVerifier;
import com.virgilsecurity.sdk.jsonWebToken.accessProviders.ConstAccessTokenProvider;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Calendar;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;

public class CrossCompatibilityTest {

    @Test
    public void importCardModelJson() throws IOException {
        String importedFromJson = readFile("t1_exported_as_json.txt");
        RawSignedModel cardModel = RawSignedModel.fromJson(importedFromJson);
        RawCardContent cardContent = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()));

        assertEquals(cardContent.getIdentity(), "test");
        assertEquals(ConvertionUtils.toBase64String(cardContent.getPublicKey()),
                     "MCowBQYDK2VwAyEA3J0Ivcs4/ahBafrn6mB4t+UI+IBhWjC/toVDrPJcCZk="); // TODO: 1/24/18 check strings equals
        assertEquals(cardContent.getVersion(), "5.0");
        assertEquals(cardContent.getCreatedAtTimestamp(), 1515686245);
        assertNull(cardContent.getPreviousCardId());
        assertEquals(cardModel.getSignatures().size(), 0);
    }

    @Test
    public void autoByteToBase64StringSerialization() { // FIXME: 1/29/18 Check where we can change String with byte[] in models - gson automatically will transform it
        ClassForSerialization classForSerialization =
                new ClassForSerialization("Petro", "Grigorovych".getBytes());

        String serialized = ConvertionUtils.serializeToJson(classForSerialization);

        Map<String, String> mapJson = ConvertionUtils.deserializeFromJson(serialized);
        String data = "";
        for (Map.Entry<String, String> entry : mapJson.entrySet())
            if (entry.getKey().equals("data"))
                data = mapJson.get(entry.getKey());

        assertEquals(ConvertionUtils.base64ToString(data), "Grigorovych");
    }

    @Test
    public void importExportJson() throws IOException {
        String importedFromJson = readFile("t1_exported_as_json.txt");
        RawSignedModel cardModel = RawSignedModel.fromJson(importedFromJson);
        String exportedAsJson = ConvertionUtils.serializeToJson(cardModel);

        assertEquals(importedFromJson, exportedAsJson);
    }

    @Test
    public void importCardModelString() throws IOException {
        String importedFromString = readFile("t1_exported_as_str.txt");
        RawSignedModel cardModel = RawSignedModel.fromJson(ConvertionUtils.base64ToString(importedFromString));
        RawCardContent cardContent = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()));

        assertEquals(cardContent.getIdentity(), "test");
        assertEquals(cardContent.getPublicKey(),
                     "MCowBQYDK2VwAyEA3J0Ivcs4/ahBafrn6mB4t+UI+IBhWjC/toVDrPJcCZk="); // TODO: 1/24/18 check strings equals
        assertEquals(cardContent.getVersion(), "5.0");
        assertEquals(cardContent.getCreatedAtTimestamp(), 1515686245);
        assertNull(cardContent.getPreviousCardId());
        assertEquals(cardModel.getSignatures().size(), 0);
    }

    @Test
    public void importExportString() throws IOException {
        String importedFromJson = readFile("t1_exported_as_json.txt");
        RawSignedModel cardModel = RawSignedModel.fromJson(importedFromJson);
        String exportedAsJson = ConvertionUtils.serializeToJson(cardModel);

        assertEquals(importedFromJson, exportedAsJson);
    }

    @Test
    public void importCardModelJsonFullSignatures() throws IOException {
        String importedFromJson = readFile("t2_exported_as_json.txt");
        RawSignedModel cardModel = RawSignedModel.fromJson(importedFromJson);
        RawCardContent cardContent = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()));

        assertEquals(cardContent.getIdentity(), "test");
        assertEquals(cardContent.getPublicKey(),
                     "MCowBQYDK2VwAyEA3J0Ivcs4/ahBafrn6mB4t+UI+IBhWjC/toVDrPJcCZk="); // TODO: 1/24/18 check strings equals
        assertEquals(cardContent.getVersion(), "5.0");
        assertEquals(cardContent.getCreatedAtTimestamp(), 1515686245);
        assertEquals(cardContent.getPreviousCardId(),
                     "a666318071274adb738af3f67b8c7ec29d954de2cabfd71a942e6ea38e59fff9");
        assertEquals(cardModel.getSignatures().size(), 3);

        assertEquals(cardModel.getSignatures().get(0).getSignature(),
                     "MFEwDQYJYIZIAWUDBAICBQAEQFfpZUY8aD0SzmU7rJh49bm4CD7wyTtYeTWLddJzJDS+0HpST3DulxMfBjQfWq5Y3upj49odzQNhOaATz3fF3gg=");
        assertEquals(cardModel.getSignatures().get(0).getSignerId(),
                     "e6fbcad760b3d89610a96230718a6c0522d0dbb1dd264273401d9634c1bb5be0");
        assertEquals(cardModel.getSignatures().get(0).getSignerType(),
                     "self");
        assertNull(cardModel.getSignatures().get(0).getSnapshot());

        assertEquals(cardModel.getSignatures().get(1).getSignature(),
                     "MFEwDQYJYIZIAWUDBAICBQAEQKLcj0Tx0dOTET6vmFmc+xk9BKOfsidoXdcl0BWr4hwL3SaEiQR3E2PT7VcVr6yIKMEneUmmlvL/mqbRCZ1dwQo=");
        assertEquals(cardModel.getSignatures().get(1).getSignerId(),
                     "5b748aa6890d90c4fe199300f8ff10b4e1fdfd50140774ca6b03adb121ee94e1");
        assertEquals(cardModel.getSignatures().get(1).getSignerType(),
                     "virgil");
        assertNull(cardModel.getSignatures().get(1).getSnapshot());

        assertEquals(cardModel.getSignatures().get(2).getSignature(),
                     "MFEwDQYJYIZIAWUDBAICBQAEQHqRoiTjhbbDZfYLsXexjdywiNOH2HlEe84yZaWKIo5AiKGTAVsE31JgSBCCNvBn5FBymNSpbtNGH3Td17xePAQ=");
        assertEquals(cardModel.getSignatures().get(2).getSignerId(),
                     "d729624f302f03f4cf83062bd24af9c44aa35b11670a155300bf3a8560dfa30f");
        assertEquals(cardModel.getSignatures().get(2).getSignerType(),
                     "extra");
        assertNull(cardModel.getSignatures().get(2).getSnapshot());
    }

    @Test
    public void importExportJsonFullSignatures() throws IOException {
        String importedFromJson = readFile("t2_exported_as_json.txt");
        RawSignedModel cardModel = RawSignedModel.fromJson(importedFromJson);
        String exportedAsJson = ConvertionUtils.serializeToJson(cardModel);

        assertEquals(importedFromJson, exportedAsJson);
    }

    @Test
    public void importCardModelStringFullSignatures() throws IOException {
        String importedFromString = readFile("t2_exported_as_str.txt");
        RawSignedModel cardModel = RawSignedModel.fromJson(ConvertionUtils.base64ToString(importedFromString));
        RawCardContent cardContent = RawCardContent.fromJson(new String(cardModel.getContentSnapshot()));

        assertEquals(cardContent.getIdentity(), "test");
        assertEquals(cardContent.getPublicKey(),
                     "MCowBQYDK2VwAyEA3J0Ivcs4/ahBafrn6mB4t+UI+IBhWjC/toVDrPJcCZk="); // TODO: 1/24/18 check strings equals
        assertEquals(cardContent.getVersion(), "5.0");
        assertEquals(cardContent.getCreatedAtTimestamp(), 1515686245);
        assertEquals(cardContent.getPreviousCardId(),
                     "a666318071274adb738af3f67b8c7ec29d954de2cabfd71a942e6ea38e59fff9");
        assertEquals(cardModel.getSignatures().size(), 3);

        assertEquals(cardModel.getSignatures().get(0).getSignature(),
                     "MFEwDQYJYIZIAWUDBAICBQAEQBZXfYW66lifuWn9rmVg6XWWLXmisVcOScL/ZeX68cdIFrtpfZN+nE+CKMSjQxQ6kDChPuijwSm17KTORth6dwM=");
        assertEquals(cardModel.getSignatures().get(0).getSignerId(),
                     "e6fbcad760b3d89610a96230718a6c0522d0dbb1dd264273401d9634c1bb5be0");
        assertEquals(cardModel.getSignatures().get(0).getSignerType(),
                     "self");
        assertNull(cardModel.getSignatures().get(0).getSnapshot());

        assertEquals(cardModel.getSignatures().get(1).getSignature(),
                     "MFEwDQYJYIZIAWUDBAICBQAEQMnSEhoPYG9ZURa22Cd1aClcSt6KPrOKST/jSr/TSx+KPmf+X9qKzSLJcT3fN1+ViDS4FdouqOOxmHo+75NsOQo=");
        assertEquals(cardModel.getSignatures().get(1).getSignerId(),
                     "85b229cf9dc183b1f90980900149f7200ae9667e938279cc130e4f71f47e94ef");
        assertEquals(cardModel.getSignatures().get(1).getSignerType(),
                     "virgil");
        assertNull(cardModel.getSignatures().get(1).getSnapshot());

        assertEquals(cardModel.getSignatures().get(2).getSignature(),
                     "MFEwDQYJYIZIAWUDBAICBQAEQNKnaa9I7BSR8wJUOCjE2XVS48XbBZqiQ3R2oynQ5YtHzC7o4wp1ZZRktR+ZTwhCKrLdwINRUqbwRvhrMygPwAE=");
        assertEquals(cardModel.getSignatures().get(2).getSignerId(),
                     "e0f7a620202a26891faa175d8a8552b7c81a7b7678247c02385dbb8f7112bc7b");
        assertEquals(cardModel.getSignatures().get(2).getSignerType(),
                     "extra");
        assertNull(cardModel.getSignatures().get(2).getSnapshot());
    }

    @Test
    public void parseSnapsot() {
        String snapshot = "eyJpZGVudGl0eSI6IlRFU1QiLCJwdWJsaWNfa2V5IjoiTUNvd0JRWURLMlZ3QXlFQVpUdHZkVmE2YnhLUENWcDZVW" +
                "nBwMFhJNDdhN3lNTlNNb2FYZ0R5VHQvak09IiwidmVyc2lvbiI6IjUuMCIsImNyZWF0ZWRfYXQiOjE1MTc5MDQ2NzN9";

        RawCardContent cardContent = ConvertionUtils.deserializeFromJson(ConvertionUtils.base64ToString(snapshot),
                                                                         RawCardContent.class);

        String serializedSnapshot = ConvertionUtils.toBase64String(ConvertionUtils.serializeToJson(cardContent));
        assertEquals(snapshot, serializedSnapshot);
    }

    @Test
    public void cardImportAsJson() throws IOException, CryptoException {
        CardCrypto cardCrypto = new VirgilCardCrypto();
        VirgilCardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
        Mockito.when(cardVerifier.verifyCard(Mockito.mock(Card.class))).thenReturn(true);

        CardManager cardManager = new CardManager(new ModelSigner(cardCrypto),
                                                  cardCrypto,
                                                  new ConstAccessTokenProvider(),
                                                  cardVerifier,
                                                  new CardClient(),
                                                  Mockito.mock(CardManager.SignCallback.class));

        String importedFromJson = readFile("t3_as_json.txt");
        Card card = cardManager.importCardAsJson(importedFromJson);

        assertEquals(card.getIdentifier(), "");
        assertEquals(card.getIdentity(), "test");
        assertNotNull(card.getPublicKey());
        assertEquals(card.getVersion(), "5.0");
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.YEAR, 2018);
        calendar.set(Calendar.MONTH, 1);
        calendar.set(Calendar.DAY_OF_MONTH, 11);
        calendar.set(Calendar.HOUR_OF_DAY, 15);
        calendar.set(Calendar.MINUTE, 57);
        calendar.set(Calendar.SECOND, 25);
        assertEquals(calendar.getTime().compareTo(card.getCreatedAt()), 0); // 0 is returned if dates are equal
        assertNull(card.getPreviousCardId());
        assertNull(card.getPreviousCard());
        assertTrue(card.getSignatures().isEmpty());
    }

    @Test
    public void cardImportAsString() throws IOException, CryptoException {
        CardCrypto cardCrypto = new VirgilCardCrypto();
        VirgilCardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
        Mockito.when(cardVerifier.verifyCard(Mockito.mock(Card.class))).thenReturn(true);

        CardManager cardManager = new CardManager(new ModelSigner(cardCrypto),
                                                  cardCrypto,
                                                  new ConstAccessTokenProvider(),
                                                  cardVerifier,
                                                  new CardClient(),
                                                  Mockito.mock(CardManager.SignCallback.class));

        String importedFromJson = readFile("t3_as_str.txt");
        Card card = cardManager.importCardAsJson(ConvertionUtils.base64ToString(importedFromJson));

        assertEquals(card.getIdentifier(), "");
        assertEquals(card.getIdentity(), "test");
        assertNotNull(card.getPublicKey());
        assertEquals(card.getVersion(), "5.0");
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.YEAR, 2018);
        calendar.set(Calendar.MONTH, 1);
        calendar.set(Calendar.DAY_OF_MONTH, 11);
        calendar.set(Calendar.HOUR_OF_DAY, 15);
        calendar.set(Calendar.MINUTE, 57);
        calendar.set(Calendar.SECOND, 25);
        assertEquals(calendar.getTime().compareTo(card.getCreatedAt()), 0); // 0 is returned if dates are equal
        assertNull(card.getPreviousCardId());
        assertNull(card.getPreviousCard());
        assertTrue(card.getSignatures().isEmpty());
    }
    // TODO: 1/30/18 test Card.parse

    @Test
    public void cardImportAsJsonFullSignatures() throws IOException, CryptoException {
        CardCrypto cardCrypto = new VirgilCardCrypto();
        VirgilCardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
        Mockito.when(cardVerifier.verifyCard(Mockito.mock(Card.class))).thenReturn(true);

        CardManager cardManager = new CardManager(new ModelSigner(cardCrypto),
                                                  cardCrypto,
                                                  new ConstAccessTokenProvider(),
                                                  cardVerifier,
                                                  new CardClient(),
                                                  Mockito.mock(CardManager.SignCallback.class));

        String importedFromJson = readFile("t4_as_json.txt");
        Card card = cardManager.importCardAsJson(importedFromJson);

        assertEquals(card.getIdentifier(), "");
        assertEquals(card.getIdentity(), "test");
        assertNotNull(card.getPublicKey());
        assertEquals(card.getVersion(), "5.0");
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.YEAR, 2018);
        calendar.set(Calendar.MONTH, 1);
        calendar.set(Calendar.DAY_OF_MONTH, 11);
        calendar.set(Calendar.HOUR_OF_DAY, 15);
        calendar.set(Calendar.MINUTE, 57);
        calendar.set(Calendar.SECOND, 25);
        assertEquals(calendar.getTime().compareTo(card.getCreatedAt()), 0); // 0 is returned if dates are equal
        assertNull(card.getPreviousCardId());
        assertNull(card.getPreviousCard());
        assertEquals(card.getSignatures().size(), 3);

        assertEquals(card.getSignatures().get(0).getSignature(),
                     "MFEwDQYJYIZIAWUDBAICBQAEQD/hFd+IvQ+gZWeyw2G8ajnlQmPPCtd8HwcuHqaUt0SYBkLOw9yN7btER0fw3ErLljtgVxasFfwuJhnginUc9Q4=");
        assertEquals(card.getSignatures().get(0).getSignerId(),
                     "665e7fa683538fe94701a012e92ffba9261de2504e235eed28076ae73a39ce61");
        assertEquals(card.getSignatures().get(0).getSignerType(),
                     "self");
        assertNull(card.getSignatures().get(0).getSnapshot());

        assertEquals(card.getSignatures().get(1).getSignature(),
                     "MFEwDQYJYIZIAWUDBAICBQAEQBa6lxRDHhiUYw+VxFr8S25GZ75YEg1yPFJtHpB0+2sZNCIlQnhrtEdfhmubP2wb8a5mMvdreaNqAFqe4UUVCg8=");
        assertEquals(card.getSignatures().get(1).getSignerId(),
                     "6493f2e1031e20923db2e3a463b84f8ba7666385b5d8f491393a10af7ed32da9");
        assertEquals(card.getSignatures().get(1).getSignerType(),
                     "virgil");
        assertNull(card.getSignatures().get(1).getSnapshot());

        assertEquals(card.getSignatures().get(2).getSignature(),
                     "MFEwDQYJYIZIAWUDBAICBQAEQJMl893Iki6qMN7nWgAIglMKJ2O4xdqhfC9w0FM6a3bd+J9plJz9DDSyRs++RjCkJ3xRcZbyA0SpI2TtKoEIzQ0=");
        assertEquals(card.getSignatures().get(2).getSignerId(),
                     "071c7e3db1a6ccd04de3a916823070dcbeef75af8283df8c9e60a8c80d711369");
        assertEquals(card.getSignatures().get(2).getSignerType(),
                     "extra");
        assertNull(card.getSignatures().get(2).getSnapshot());
    }

    @Test
    public void cardImportAsStringFullSignatures() throws IOException, CryptoException {
        CardCrypto cardCrypto = new VirgilCardCrypto();
        VirgilCardVerifier cardVerifier = Mockito.mock(VirgilCardVerifier.class);
        Mockito.when(cardVerifier.verifyCard(Mockito.mock(Card.class))).thenReturn(true);

        CardManager cardManager = new CardManager(new ModelSigner(cardCrypto),
                                                  cardCrypto,
                                                  new ConstAccessTokenProvider(),
                                                  cardVerifier,
                                                  new CardClient(),
                                                  Mockito.mock(CardManager.SignCallback.class));

        String importedFromJson = readFile("t4_as_str.txt");
        Card card = cardManager.importCardAsJson(ConvertionUtils.base64ToString(importedFromJson));

        assertEquals(card.getIdentifier(), "");
        assertEquals(card.getIdentity(), "test");
        assertNotNull(card.getPublicKey());
        assertEquals(card.getVersion(), "5.0");
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.YEAR, 2018);
        calendar.set(Calendar.MONTH, 1);
        calendar.set(Calendar.DAY_OF_MONTH, 11);
        calendar.set(Calendar.HOUR_OF_DAY, 15);
        calendar.set(Calendar.MINUTE, 57);
        calendar.set(Calendar.SECOND, 25);
        assertEquals(calendar.getTime().compareTo(card.getCreatedAt()), 0); // 0 is returned if dates are equal
        assertNull(card.getPreviousCardId());
        assertNull(card.getPreviousCard());
        assertEquals(card.getSignatures().size(), 3);

        assertEquals(card.getSignatures().get(0).getSignature(),
                     "MFEwDQYJYIZIAWUDBAICBQAEQD/hFd+IvQ+gZWeyw2G8ajnlQmPPCtd8HwcuHqaUt0SYBkLOw9yN7btER0fw3ErLljtgVxasFfwuJhnginUc9Q4=");
        assertEquals(card.getSignatures().get(0).getSignerId(),
                     "665e7fa683538fe94701a012e92ffba9261de2504e235eed28076ae73a39ce61");
        assertEquals(card.getSignatures().get(0).getSignerType(),
                     "self");
        assertNull(card.getSignatures().get(0).getSnapshot());

        assertEquals(card.getSignatures().get(1).getSignature(),
                     "MFEwDQYJYIZIAWUDBAICBQAEQBa6lxRDHhiUYw+VxFr8S25GZ75YEg1yPFJtHpB0+2sZNCIlQnhrtEdfhmubP2wb8a5mMvdreaNqAFqe4UUVCg8=");
        assertEquals(card.getSignatures().get(1).getSignerId(),
                     "6493f2e1031e20923db2e3a463b84f8ba7666385b5d8f491393a10af7ed32da9");
        assertEquals(card.getSignatures().get(1).getSignerType(),
                     "virgil");
        assertNull(card.getSignatures().get(1).getSnapshot());

        assertEquals(card.getSignatures().get(2).getSignature(),
                     "MFEwDQYJYIZIAWUDBAICBQAEQJMl893Iki6qMN7nWgAIglMKJ2O4xdqhfC9w0FM6a3bd+J9plJz9DDSyRs++RjCkJ3xRcZbyA0SpI2TtKoEIzQ0=");
        assertEquals(card.getSignatures().get(2).getSignerId(),
                     "071c7e3db1a6ccd04de3a916823070dcbeef75af8283df8c9e60a8c80d711369");
        assertEquals(card.getSignatures().get(2).getSignerType(),
                     "extra");
        assertNull(card.getSignatures().get(2).getSnapshot());
    }

    @Test
    public void verifyImportedJwt() throws IOException, CryptoException {
        final String apiPublicKey = "sdasda";
        final String apiPublicKeyIdentifier = "dsadsada";
        VirgilAccessTokenSigner accessTokenSigner = new VirgilAccessTokenSigner();
        VirgilCrypto crypto = new VirgilCrypto();
        JwtVerifier jwtVerifier = new JwtVerifier(crypto.importPublicKey(ConvertionUtils.base64ToBytes(apiPublicKey)),
                                                  apiPublicKeyIdentifier,
                                                  accessTokenSigner);

        String jwtImported = readFile("jwt.txt");
        Jwt jwt = new Jwt(jwtImported);

        assertTrue(jwtVerifier.verifyToken(jwt));
    }

    @Test
    public void verifyGeneratedJwt() throws IOException, CryptoException {
        final String apiPublicKey = "sdasda";
        final String apiPublicKeyIdentifier = "dsadsada";
        VirgilAccessTokenSigner accessTokenSigner = new VirgilAccessTokenSigner();
        VirgilCrypto crypto = new VirgilCrypto();
        JwtVerifier jwtVerifier = new JwtVerifier(crypto.importPublicKey(ConvertionUtils.base64ToBytes(apiPublicKey)),
                                                  apiPublicKeyIdentifier,
                                                  accessTokenSigner);

        JwtGenerator jwtGenerator = new JwtGenerator(Mockito.mock(PrivateKey.class),
                                                     "API_PUBLIC_KEY_IDENTIFIER",
                                                     accessTokenSigner,
                                                     "APP_ID",
                                                     TimeSpan.fromTime(1, TimeUnit.HOURS));
        Jwt jwt = jwtGenerator.generateToken("test");

        assertTrue(jwtVerifier.verifyToken(jwt));
    }

    private String readFile(String name) throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        String line;
        File file = new File("/Users/danylooliinyk/Downloads/", name);

        FileReader fileReader = new FileReader(file);
        BufferedReader buff = new BufferedReader(fileReader);

        while (((line = buff.readLine()) != null)) {
            stringBuilder.append(line);
        }

        buff.close();

        return stringBuilder.toString();
    }
}
