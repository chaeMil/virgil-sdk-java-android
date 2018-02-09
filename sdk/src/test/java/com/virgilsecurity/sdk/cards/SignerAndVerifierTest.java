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

package com.virgilsecurity.sdk.cards;

import com.virgilsecurity.sdk.CompatibilityDataProvider;
import com.virgilsecurity.sdk.cards.model.RawSignature;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.cards.validation.VerifierCredentials;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.cards.validation.WhiteList;
import com.virgilsecurity.sdk.client.CardClient;
import com.virgilsecurity.sdk.client.exceptions.SignatureNotUniqueException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.common.Generator;
import com.virgilsecurity.sdk.common.Mocker;
import com.virgilsecurity.sdk.common.PropertyManager;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.Jwt;
import com.virgilsecurity.sdk.jwt.accessProviders.CallbackJwtProvider;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;

import java.io.IOException;
import java.util.*;

import static com.virgilsecurity.sdk.CompatibilityDataProvider.STRING;
import static org.junit.Assert.*;

public class SignerAndVerifierTest extends PropertyManager {

    @Rule
    public final ExpectedException exception = ExpectedException.none();

    private static final String TEST_SIGNER_TYPE = "test_custom_type";
    private static final String TEST_KEY_ONE = "TEST_KEY_ONE";
    private static final String TEST_VALUE_ONE = "TEST_VALUE_ONE";
    private static final String TEST_KEY_TWO = "TEST_KEY_TWO";
    private static final String TEST_VALUE_TWO = "TEST_VALUE_TWO";

    private VirgilCrypto virgilCrypto;
    private VirgilCardCrypto cardCrypto;
    private ModelSigner modelSigner;
    private Mocker mocker;
    private VirgilCardVerifier verifier;
    private CardClient cardClient;
    private CardManager cardManager;
    private CompatibilityDataProvider dataProvider;

    @Before
    public void setUp() {
        virgilCrypto = new VirgilCrypto();
        cardCrypto = new VirgilCardCrypto();
        modelSigner = new ModelSigner(cardCrypto);
        mocker = new Mocker();
        verifier = new VirgilCardVerifier(cardCrypto);
        cardClient = new CardClient(CARDS_SERVICE_URL);
        cardManager = new CardManager(cardCrypto, Mockito.mock(AccessTokenProvider.class),
                                      Mockito.mock(ModelSigner.class), cardClient, verifier,
                                      new CardManager.SignCallback() {
                                          @Override
                                          public RawSignedModel onSign(
                                                  RawSignedModel rawSignedModel) {
                                              return rawSignedModel;
                                          }
                                      });
        dataProvider = new CompatibilityDataProvider();
    }

    @Test
    public void STC_8_self_signature() throws CryptoException {
        VirgilKeyPair keyPair = virgilCrypto.generateKeys();
        RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());
        modelSigner.selfSign(cardModel, keyPair.getPrivateKey());

        assertTrue(cardModel.getSignatures().size() == 1);
        assertNull(cardModel.getSignatures().get(0).getSnapshot());
        assertEquals(SignerType.SELF.getRawValue(), cardModel.getSignatures().get(0).getSigner());
        byte[] fingerprint = cardCrypto.generateSHA512(cardModel.getContentSnapshot());
        assertTrue(virgilCrypto.verifySignature(
                ConvertionUtils.base64ToBytes(cardModel.getSignatures().get(0).getSignature()),
                fingerprint, keyPair.getPublicKey()));

        exception.expect(SignatureNotUniqueException.class);
        modelSigner.selfSign(cardModel, keyPair.getPrivateKey());
    }

    @Test
    public void STC_8_custom_signature() throws CryptoException {
        VirgilKeyPair keyPair = virgilCrypto.generateKeys();
        RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());
        modelSigner.sign(cardModel, TEST_SIGNER_TYPE, keyPair.getPrivateKey());

        assertTrue(cardModel.getSignatures().size() == 1);
        assertNull(cardModel.getSignatures().get(0).getSnapshot());
        assertEquals(TEST_SIGNER_TYPE, cardModel.getSignatures().get(0).getSigner());
        byte[] fingerprint = cardCrypto.generateSHA512(cardModel.getContentSnapshot());
        assertTrue(virgilCrypto.verifySignature(
                ConvertionUtils.base64ToBytes(cardModel.getSignatures().get(0).getSignature()),
                fingerprint, keyPair.getPublicKey()));


        exception.expect(SignatureNotUniqueException.class);
        modelSigner.sign(cardModel, TEST_SIGNER_TYPE, keyPair.getPrivateKey());
    }

    @Test
    public void STC_8_two_signatures() throws CryptoException {
        VirgilKeyPair keyPairOne = virgilCrypto.generateKeys();
        RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPairOne.getPublicKey());
        modelSigner.selfSign(cardModel, keyPairOne.getPrivateKey());

        assertTrue(cardModel.getSignatures().size() == 1);

        VirgilKeyPair keyPairTwo = virgilCrypto.generateKeys();
        modelSigner.sign(cardModel, TEST_SIGNER_TYPE, keyPairTwo.getPrivateKey());

        assertTrue(cardModel.getSignatures().size() == 2);

        byte[] fingerprint = cardCrypto.generateSHA512(cardModel.getContentSnapshot());
        for (RawSignature rawSignature : cardModel.getSignatures()) {
            switch (rawSignature.getSigner()) {
                case "self":
                    assertNull(rawSignature.getSnapshot());
                    assertTrue(!rawSignature.getSignature().isEmpty());
                    assertTrue(virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(rawSignature.getSignature()),
                                                            fingerprint, keyPairOne.getPublicKey()));
                    break;
                case TEST_SIGNER_TYPE:
                    assertNull(rawSignature.getSnapshot());
                    assertTrue(!rawSignature.getSignature().isEmpty());
                    assertTrue(virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(rawSignature.getSignature()),
                                                            fingerprint, keyPairTwo.getPublicKey()));
                    break;
                default:
                    fail();
            }
        }

        exception.expect(SignatureNotUniqueException.class);
        modelSigner.sign(cardModel, TEST_SIGNER_TYPE, keyPairTwo.getPrivateKey());
    }

    @Test
    public void STC_9_self_signature() throws CryptoException {
        VirgilKeyPair keyPair = virgilCrypto.generateKeys();
        RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());
        Map<String, String> additionalData = new HashMap<>();
        additionalData.put(TEST_KEY_ONE, TEST_VALUE_ONE);
        additionalData.put(TEST_KEY_TWO, TEST_VALUE_TWO);
        modelSigner.selfSign(cardModel, additionalData, keyPair.getPrivateKey());

        assertTrue(cardModel.getSignatures().size() == 1);
        Map<String, String> additionalDataExported = ConvertionUtils
                .deserializeMapFromJson(ConvertionUtils.base64ToString(cardModel.getSignatures().get(0).getSnapshot()));
        assertEquals(TEST_VALUE_ONE, additionalDataExported.get(TEST_KEY_ONE));
        assertEquals(TEST_VALUE_TWO, additionalDataExported.get(TEST_KEY_TWO));

        assertEquals(SignerType.SELF.getRawValue(), cardModel.getSignatures().get(0).getSigner());
        byte[] combinedSnapshot = ConvertionUtils
                .concatenate(cardModel.getContentSnapshot(), ConvertionUtils.captureSnapshot(additionalData));
        byte[] fingerprint = cardCrypto.generateSHA512(combinedSnapshot);
        assertTrue(virgilCrypto.verifySignature(
                ConvertionUtils.base64ToBytes(cardModel.getSignatures().get(0).getSignature()),
                fingerprint, keyPair.getPublicKey()));

        exception.expect(SignatureNotUniqueException.class);
        modelSigner.selfSign(cardModel, keyPair.getPrivateKey());
    }

    @Test
    public void STC_9_custom_signature() throws CryptoException {
        VirgilKeyPair keyPair = virgilCrypto.generateKeys();
        RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());
        Map<String, String> additionalData = new HashMap<>();
        additionalData.put(TEST_KEY_ONE, TEST_VALUE_ONE);
        additionalData.put(TEST_KEY_TWO, TEST_VALUE_TWO);
        modelSigner.sign(cardModel, TEST_SIGNER_TYPE, additionalData, keyPair.getPrivateKey());

        assertTrue(cardModel.getSignatures().size() == 1);
        Map<String, String> additionalDataExported = ConvertionUtils
                .deserializeMapFromJson(ConvertionUtils.base64ToString(cardModel.getSignatures().get(0).getSnapshot()));
        assertEquals(TEST_VALUE_ONE, additionalDataExported.get(TEST_KEY_ONE));
        assertEquals(TEST_VALUE_TWO, additionalDataExported.get(TEST_KEY_TWO));

        assertEquals(TEST_SIGNER_TYPE, cardModel.getSignatures().get(0).getSigner());
        byte[] combinedSnapshot = ConvertionUtils
                .concatenate(cardModel.getContentSnapshot(), ConvertionUtils.captureSnapshot(additionalData));
        byte[] fingerprint = cardCrypto.generateSHA512(combinedSnapshot);
        assertTrue(virgilCrypto.verifySignature(
                ConvertionUtils.base64ToBytes(cardModel.getSignatures().get(0).getSignature()),
                fingerprint, keyPair.getPublicKey()));


        exception.expect(SignatureNotUniqueException.class);
        modelSigner.sign(cardModel, TEST_SIGNER_TYPE, keyPair.getPrivateKey());
    }

    @Test
    public void STC_9_two_signatures() throws CryptoException {
        VirgilKeyPair keyPairOne = virgilCrypto.generateKeys();
        RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPairOne.getPublicKey());
        Map<String, String> additionalData = new HashMap<>();
        additionalData.put(TEST_KEY_ONE, TEST_VALUE_ONE);
        additionalData.put(TEST_KEY_TWO, TEST_VALUE_TWO);
        modelSigner.selfSign(cardModel, additionalData, keyPairOne.getPrivateKey());

        assertTrue(cardModel.getSignatures().size() == 1);

        VirgilKeyPair keyPairTwo = virgilCrypto.generateKeys();
        modelSigner.sign(cardModel, TEST_SIGNER_TYPE, additionalData, keyPairTwo.getPrivateKey());

        assertTrue(cardModel.getSignatures().size() == 2);

        byte[] combinedSnapshot = ConvertionUtils
                .concatenate(cardModel.getContentSnapshot(), ConvertionUtils.captureSnapshot(additionalData));
        byte[] fingerprint = cardCrypto.generateSHA512(combinedSnapshot);
        for (RawSignature rawSignature : cardModel.getSignatures()) {
            switch (rawSignature.getSigner()) {
                case "self":
                    Map<String, String> additionalDataExportedOne = ConvertionUtils
                            .deserializeMapFromJson(ConvertionUtils.base64ToString(rawSignature.getSnapshot()));
                    assertEquals(TEST_VALUE_ONE, additionalDataExportedOne.get(TEST_KEY_ONE));
                    assertEquals(TEST_VALUE_TWO, additionalDataExportedOne.get(TEST_KEY_TWO));
                    assertTrue(!rawSignature.getSignature().isEmpty());
                    assertTrue(virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(rawSignature.getSignature()),
                                                            fingerprint, keyPairOne.getPublicKey()));
                    break;
                case TEST_SIGNER_TYPE:
                    Map<String, String> additionalDataExportedTwo = ConvertionUtils
                            .deserializeMapFromJson(ConvertionUtils.base64ToString(rawSignature.getSnapshot()));
                    assertEquals(TEST_VALUE_ONE, additionalDataExportedTwo.get(TEST_KEY_ONE));
                    assertEquals(TEST_VALUE_TWO, additionalDataExportedTwo.get(TEST_KEY_TWO));
                    assertTrue(!rawSignature.getSignature().isEmpty());
                    assertTrue(virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(rawSignature.getSignature()),
                                                            fingerprint, keyPairTwo.getPublicKey()));
                    break;
                default:
                    fail();
            }
        }

        exception.expect(SignatureNotUniqueException.class);
        modelSigner.sign(cardModel, TEST_SIGNER_TYPE, keyPairTwo.getPrivateKey());
    }

    @Test
    public void STC_10() throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(10, STRING));
        Card card = Card.parse(cardCrypto, rawSignedModel);

        VirgilPrivateKey privateKey = virgilCrypto.importPrivateKey(ConvertionUtils
                                                                            .base64ToBytes(dataProvider.getJsonByKey(10,
                                                                                                                     "private_key1_base64")));

        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false,
                                                                       Collections.<WhiteList>emptyList());
        assertTrue(virgilCardVerifier.verifyCard(card));

        virgilCardVerifier.setVerifySelfSignature(true);
        assertTrue(virgilCardVerifier.verifyCard(card));

//        virgilCardVerifier.setVerifyVirgilSignature(true); // FIXME: 2/8/18 enable when services are live
//        assertTrue(virgilCardVerifier.verifyCard(card));

        VirgilPublicKey publicKey = virgilCrypto.extractPublicKey(privateKey);
        List<VerifierCredentials> verifierCredentialsList = new ArrayList<>();
        verifierCredentialsList.add(new VerifierCredentials(SignerType.SELF.getRawValue(), publicKey.getRawKey()));
        WhiteList whiteListOne = new WhiteList(verifierCredentialsList);

        virgilCardVerifier.addWhiteList(whiteListOne);
        assertTrue(virgilCardVerifier.verifyCard(card));

        VirgilPublicKey publicKeyTwo = mocker.generatePublicKey();
        verifierCredentialsList.add(new VerifierCredentials(SignerType.SELF.getRawValue(), publicKeyTwo.getRawKey()));
        WhiteList whiteListTwo = new WhiteList(verifierCredentialsList);
        List<WhiteList> whiteLists = new ArrayList<>();
        whiteLists.add(whiteListTwo);

        virgilCardVerifier.setWhiteLists(whiteLists);
        assertTrue(virgilCardVerifier.verifyCard(card));

        VirgilPublicKey publicKeyThree = mocker.generatePublicKey();
        List<VerifierCredentials> verifierCredentialsListTwo = new ArrayList<>();
        List<VerifierCredentials> verifierCredentialsListThree = new ArrayList<>();
        verifierCredentialsListTwo
                .add(new VerifierCredentials(SignerType.SELF.getRawValue(), publicKey.getRawKey()));
        verifierCredentialsListTwo
                .add(new VerifierCredentials(SignerType.SELF.getRawValue(), publicKeyTwo.getRawKey()));
        verifierCredentialsListThree
                .add(new VerifierCredentials(SignerType.SELF.getRawValue(), publicKeyThree.getRawKey()));
        WhiteList whiteListThree = new WhiteList(verifierCredentialsListTwo);
        WhiteList whiteListFour = new WhiteList(verifierCredentialsListThree);
        List<WhiteList> whiteListsTwo = new ArrayList<>();
        whiteListsTwo.add(whiteListThree);
        whiteListsTwo.add(whiteListFour);

        virgilCardVerifier.setWhiteLists(whiteListsTwo);
        assertFalse(virgilCardVerifier.verifyCard(card));
    }

    @Test
    public void STC_11() throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(11, STRING));
        Card card = Card.parse(cardCrypto, rawSignedModel);
        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false,
                                                                       Collections.<WhiteList>emptyList());
        assertTrue(virgilCardVerifier.verifyCard(card));

        virgilCardVerifier.setVerifySelfSignature(true);
        assertFalse(virgilCardVerifier.verifyCard(card));
    }

    @Test
    public void STC_12() throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(12, STRING));
        Card card = Card.parse(cardCrypto, rawSignedModel);

        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false);
        assertTrue(virgilCardVerifier.verifyCard(card));

        virgilCardVerifier.setVerifyVirgilSignature(true);
        assertFalse(virgilCardVerifier.verifyCard(card));
    }

    @Test
    public void STC_14() throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(14, STRING));
        Card card = Card.parse(cardCrypto, rawSignedModel);
        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, true);
        assertFalse(virgilCardVerifier.verifyCard(card));
    }

    @Test
    public void STC_15() throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(15, STRING));
        Card card = Card.parse(cardCrypto, rawSignedModel);
        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, true, false);
        assertFalse(virgilCardVerifier.verifyCard(card));
    }

    @Test
    public void STC_16() throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(16, STRING));
        VirgilPublicKey publicKey = (VirgilPublicKey) cardCrypto
                .importPublicKey(ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(16, "public_key1_base64")));

        VirgilPublicKey publicKeyTwo = mocker.generatePublicKey();
        List<VerifierCredentials> verifierCredentialsList = new ArrayList<>();
        verifierCredentialsList.add(new VerifierCredentials(TEST_SIGNER_TYPE, publicKeyTwo.getRawKey()));
        WhiteList whiteListOne = new WhiteList(verifierCredentialsList);
        List<WhiteList> whiteLists = new ArrayList<>();
        whiteLists.add(whiteListOne);

        Card card = Card.parse(cardCrypto, rawSignedModel);
        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false,
                                                                       whiteLists);
        assertFalse(virgilCardVerifier.verifyCard(card));

        verifierCredentialsList.add(new VerifierCredentials("extra", publicKey.getRawKey()));

        assertTrue(virgilCardVerifier.verifyCard(card));
    }

    private static boolean reloaded;

    @Test
    public void STC_26() throws CryptoException, IOException {
        CallbackJwtProvider accessTokenProvider = new CallbackJwtProvider();
        String identity = Generator.identity();
        final Jwt jwt = mocker.generateAccessToken(identity);
        final Jwt jwtExpired = mocker.generateExpiredAccessToken(identity);
        accessTokenProvider.setGetTokenCallback(new CallbackJwtProvider.GetTokenCallback() {
            @Override
            public String onGetToken() {
                if (reloaded) {
                    return jwt.stringRepresentation();
                } else {
                    reloaded = true;
                    return jwtExpired.stringRepresentation();
                }
            }
        });

        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false);

        final CardManager cardManager = new CardManager(cardCrypto, accessTokenProvider,
                                                        Mockito.mock(ModelSigner.class), cardClient, virgilCardVerifier,
                                                        new CardManager.SignCallback() {
                                                            @Override
                                                            public RawSignedModel onSign(
                                                                    RawSignedModel rawSignedModel) {
                                                                return rawSignedModel;
                                                            }
                                                        });

        RawSignedModel rawSignedModel = mocker.generateCardModel(identity);
        Card card = null;
        try {
            card = cardManager.publishCard(rawSignedModel);
        } catch (VirgilServiceException e) {
            fail();
        }
        assertNotNull(card);

        try {
            cardManager.getCard(card.getIdentifier());
        } catch (VirgilServiceException e) {
            fail();
        }

        try {
            cardManager.searchCards(card.getIdentity());
        } catch (VirgilServiceException e) {
            fail();
        }
    }
}