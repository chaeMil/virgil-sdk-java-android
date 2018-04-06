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
import com.virgilsecurity.sdk.cards.CardManager.SignCallback;
import com.virgilsecurity.sdk.cards.model.RawSignature;
import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.cards.validation.CardVerifier;
import com.virgilsecurity.sdk.cards.validation.VerifierCredentials;
import com.virgilsecurity.sdk.cards.validation.VirgilCardVerifier;
import com.virgilsecurity.sdk.cards.validation.Whitelist;
import com.virgilsecurity.sdk.client.CardClient;
import com.virgilsecurity.sdk.client.exceptions.SignatureNotUniqueException;
import com.virgilsecurity.sdk.client.exceptions.VirgilServiceException;
import com.virgilsecurity.sdk.common.Generator;
import com.virgilsecurity.sdk.common.Mocker;
import com.virgilsecurity.sdk.common.PropertyManager;
import com.virgilsecurity.sdk.crypto.*;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.TokenContext;
import com.virgilsecurity.sdk.jwt.contract.AccessToken;
import com.virgilsecurity.sdk.jwt.contract.AccessTokenProvider;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import com.virgilsecurity.sdk.utils.StringUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;

import java.util.*;

import static com.virgilsecurity.sdk.CompatibilityDataProvider.STRING;
import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

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
        String url = getCardsServiceUrl();
        if (StringUtils.isBlank(url)) {
            cardClient = new CardClient();
        } else {
            cardClient = new CardClient(url);
        }
        cardManager = new CardManager(cardCrypto,
                                      Mockito.mock(AccessTokenProvider.class),
                                      verifier,
                                      cardClient,
                                      new CardManager.SignCallback() {
                                          @Override
                                          public RawSignedModel onSign(RawSignedModel rawSignedModel) {
                                              return rawSignedModel;
                                          }
                                      },
                                      false);
        dataProvider = new CompatibilityDataProvider();
    }

    @Test
    public void STC_8_selfSign_should_addValidSignature() throws CryptoException {
        VirgilKeyPair keyPair = virgilCrypto.generateKeys();
        RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());
        assertTrue(cardModel.getSignatures().isEmpty());

        modelSigner.selfSign(cardModel, keyPair.getPrivateKey());
        assertEquals(1, cardModel.getSignatures().size());

        RawSignature selfSignature = cardModel.getSignatures().get(0);
        assertEquals(SignerType.SELF.getRawValue(), selfSignature.getSigner());
        assertNull(selfSignature.getSnapshot());
        assertTrue(virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(selfSignature.getSignature()),
                cardModel.getContentSnapshot(), keyPair.getPublicKey()));
    }

    @Test
    public void STC_8_selfSignWithSignatureSnapshot_should_addValidSignature() throws CryptoException {
        VirgilKeyPair keyPair = virgilCrypto.generateKeys();
        RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());
        assertTrue(cardModel.getSignatures().isEmpty());

        byte[] signatureSnapshot = new byte[32];
        new Random().nextBytes(signatureSnapshot);

        modelSigner.selfSign(cardModel, keyPair.getPrivateKey(), signatureSnapshot);
        assertEquals(1, cardModel.getSignatures().size());

        RawSignature selfSignature = cardModel.getSignatures().get(0);
        assertEquals(SignerType.SELF.getRawValue(), selfSignature.getSigner());
        assertEquals(ConvertionUtils.toBase64String(signatureSnapshot), selfSignature.getSnapshot());

        byte[] extendedSnapshot = ConvertionUtils.concatenate(cardModel.getContentSnapshot(), signatureSnapshot);

        assertTrue(virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(selfSignature.getSignature()),
                extendedSnapshot, keyPair.getPublicKey()));
    }

    @Test(expected = SignatureNotUniqueException.class)
    public void STC_8_secondSelfSign_should_throwException() throws CryptoException {
        VirgilKeyPair keyPair = virgilCrypto.generateKeys();
        RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());
        assertTrue(cardModel.getSignatures().isEmpty());

        modelSigner.selfSign(cardModel, keyPair.getPrivateKey());
        modelSigner.selfSign(cardModel, keyPair.getPrivateKey());
    }

    @Test
    public void STC_8_extraSign_should_addValidSignature() throws CryptoException {
        VirgilKeyPair keyPair = virgilCrypto.generateKeys();
        RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());
        modelSigner.selfSign(cardModel, keyPair.getPrivateKey());

        VirgilKeyPair keyPair2 = virgilCrypto.generateKeys();
        modelSigner.sign(cardModel, "test_id", keyPair2.getPrivateKey());

        assertEquals(2, cardModel.getSignatures().size());
        RawSignature extraSignature = cardModel.getSignatures().get(1);
        assertEquals("test_id", extraSignature.getSigner());
        assertNull(extraSignature.getSnapshot());
        assertTrue(virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(extraSignature.getSignature()),
                cardModel.getContentSnapshot(), keyPair2.getPublicKey()));
    }

    @Test(expected = SignatureNotUniqueException.class)
    public void STC_8_secondExtraSign_should_throwException() throws CryptoException {
        VirgilKeyPair keyPair = virgilCrypto.generateKeys();
        RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());

        VirgilKeyPair keyPair2 = virgilCrypto.generateKeys();
        modelSigner.sign(cardModel, "test_id", keyPair2.getPrivateKey());
        modelSigner.sign(cardModel, "test_id", keyPair2.getPrivateKey());
    }

    @Test
    public void STC_9_selfSignWithSignatureSnapshot_should_addValidSignature() throws CryptoException {
        VirgilKeyPair keyPair = virgilCrypto.generateKeys();
        RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());

        byte[] signatureSnapshot = new byte[32];
        new Random().nextBytes(signatureSnapshot);

        modelSigner.selfSign(cardModel, keyPair.getPrivateKey(), signatureSnapshot);
        assertEquals(1, cardModel.getSignatures().size());

        RawSignature selfSignature = cardModel.getSignatures().get(0);
        assertEquals(SignerType.SELF.getRawValue(), selfSignature.getSigner());
        assertEquals(ConvertionUtils.toBase64String(signatureSnapshot), selfSignature.getSnapshot());

        byte[] extendedSnapshot = ConvertionUtils.concatenate(cardModel.getContentSnapshot(), signatureSnapshot);
        assertTrue(virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(selfSignature.getSignature()),
                extendedSnapshot, keyPair.getPublicKey()));
    }

    @Test
    public void STC_9_selfSignWithExtraFields_should_addValidSignature() throws CryptoException {
        VirgilKeyPair keyPair = virgilCrypto.generateKeys();
        RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());

        Map<String, String> additionalData = new HashMap<>();
        additionalData.put(TEST_KEY_ONE, TEST_VALUE_ONE);
        additionalData.put(TEST_KEY_TWO, TEST_VALUE_TWO);

        byte[] signatureSnapshot = ConvertionUtils.captureSnapshot(additionalData);
        modelSigner.selfSign(cardModel, keyPair.getPrivateKey(), additionalData);
        assertEquals(1, cardModel.getSignatures().size());

        RawSignature selfSignature = cardModel.getSignatures().get(0);
        assertEquals(SignerType.SELF.getRawValue(), selfSignature.getSigner());
        assertEquals(ConvertionUtils.toBase64String(signatureSnapshot), selfSignature.getSnapshot());

        byte[] extendedSnapshot = ConvertionUtils.concatenate(cardModel.getContentSnapshot(), signatureSnapshot);
        assertTrue(virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(selfSignature.getSignature()),
                extendedSnapshot, keyPair.getPublicKey()));
    }

    @Test
    public void STC_9_extraSignWithExtraFields_should_addValidSignature() throws CryptoException {
        VirgilKeyPair keyPair = virgilCrypto.generateKeys();
        RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());
        modelSigner.selfSign(cardModel, keyPair.getPrivateKey());

        Map<String, String> additionalData = new HashMap<>();
        additionalData.put(TEST_KEY_ONE, TEST_VALUE_ONE);
        additionalData.put(TEST_KEY_TWO, TEST_VALUE_TWO);

        byte[] signatureSnapshot = ConvertionUtils.captureSnapshot(additionalData);

        VirgilKeyPair keyPair2 = virgilCrypto.generateKeys();
        modelSigner.sign(cardModel, "test_id", keyPair2.getPrivateKey(), additionalData);

        assertEquals(2, cardModel.getSignatures().size());
        RawSignature extraSignature = cardModel.getSignatures().get(1);
        assertEquals("test_id", extraSignature.getSigner());
        assertEquals(ConvertionUtils.toBase64String(signatureSnapshot), extraSignature.getSnapshot());

        byte[] extendedSnapshot = ConvertionUtils.concatenate(cardModel.getContentSnapshot(), signatureSnapshot);
        assertTrue(virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(extraSignature.getSignature()),
                extendedSnapshot, keyPair2.getPublicKey()));
    }

    @Test
    public void STC_9_extraSignWithSignatureSnapshot_should_addValidSignature() throws CryptoException {
        VirgilKeyPair keyPair = virgilCrypto.generateKeys();
        RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());
        modelSigner.selfSign(cardModel, keyPair.getPrivateKey());

        byte[] signatureSnapshot = new byte[32];
        new Random().nextBytes(signatureSnapshot);

        VirgilKeyPair keyPair2 = virgilCrypto.generateKeys();
        modelSigner.sign(cardModel, "test_id", keyPair2.getPrivateKey(), signatureSnapshot);

        assertEquals(2, cardModel.getSignatures().size());
        RawSignature extraSignature = cardModel.getSignatures().get(1);
        assertEquals("test_id", extraSignature.getSigner());
        assertEquals(ConvertionUtils.toBase64String(signatureSnapshot), extraSignature.getSnapshot());

        byte[] extendedSnapshot = ConvertionUtils.concatenate(cardModel.getContentSnapshot(), signatureSnapshot);
        assertTrue(virgilCrypto.verifySignature(ConvertionUtils.base64ToBytes(extraSignature.getSignature()),
                extendedSnapshot, keyPair2.getPublicKey()));
    }

    @Test(expected = SignatureNotUniqueException.class)
    public void STC_9_secondExtraSignWithSignatureSnapshot_should_throwException() throws CryptoException {
        VirgilKeyPair keyPair = virgilCrypto.generateKeys();
        RawSignedModel cardModel = mocker.generateCardModelUnsigned(keyPair.getPublicKey());

        byte[] signatureSnapshot = new byte[32];
        new Random().nextBytes(signatureSnapshot);

        VirgilKeyPair keyPair2 = virgilCrypto.generateKeys();
        modelSigner.sign(cardModel, "test_id", keyPair2.getPrivateKey(), signatureSnapshot);
        modelSigner.sign(cardModel, "test_id", keyPair2.getPrivateKey(), signatureSnapshot);
    }

    @Test
    public void STC_10_emptyVerifier_should_verifyCard() throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(10, STRING));
        Card card = Card.parse(cardCrypto, rawSignedModel);

        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false,
                new ArrayList<Whitelist>());

        assertTrue("Card should be verified", virgilCardVerifier.verifyCard(card));
    }

    @Test
    public void STC_10_verifySelfSignWithEmptyWhiteList() throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(10, STRING));
        Card card = Card.parse(cardCrypto, rawSignedModel);

        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, true, false,
                new ArrayList<Whitelist>());

        assertTrue("Card should be verified", virgilCardVerifier.verifyCard(card));
    }

    @Test
    public void STC_10_verifyVirgilSignWithEmptyWhiteList() throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(10, STRING));
        Card card = Card.parse(cardCrypto, rawSignedModel);

        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, true,
                new ArrayList<Whitelist>());

        assertTrue("Card should be verified", virgilCardVerifier.verifyCard(card));
    }

    @Test
    public void STC_10_verifySelfAndVirgilSignWithEmptyWhiteList() throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(10, STRING));
        Card card = Card.parse(cardCrypto, rawSignedModel);

        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, true, true,
                new ArrayList<Whitelist>());

        assertTrue("Card should be verified", virgilCardVerifier.verifyCard(card));
    }

    @Test
    public void STC_10_whiteList1Key() throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(10, STRING));
        Card card = Card.parse(cardCrypto, rawSignedModel);

        VirgilPrivateKey privateKey1 = virgilCrypto
                .importPrivateKey(ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(10, "private_key1_base64")));
        VirgilPublicKey publicKey1 = virgilCrypto.extractPublicKey(privateKey1);

        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false,
                new ArrayList<Whitelist>());

        List<VerifierCredentials> verifierCredentialsList = new ArrayList<>();
        verifierCredentialsList.add(new VerifierCredentials("extra", publicKey1.getRawKey()));
        Whitelist whitelist1 = new Whitelist(verifierCredentialsList);
        virgilCardVerifier.addWhiteList(whitelist1);

        assertTrue("Card should be verified", virgilCardVerifier.verifyCard(card));
    }

    @Test
    public void STC_10_verifier_shouldNot_verifyCard_ifVerifierHasEmptyWhiteList() throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(10, STRING));
        Card card = Card.parse(cardCrypto, rawSignedModel);

        List<Whitelist> whitelists = new ArrayList<>();
        whitelists.add(new Whitelist(new ArrayList<VerifierCredentials>()));
        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false, whitelists);

        assertFalse("Card should NOT be verified", virgilCardVerifier.verifyCard(card));
    }

    @Test
    public void STC_10_verifier_shouldNot_verifyCard_ifMissedRequiredSelfSignature() throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(10, STRING));
        for (RawSignature signature : rawSignedModel.getSignatures()) {
            if (SignerType.SELF.getRawValue().equals(signature.getSigner())) {
                rawSignedModel.getSignatures().remove(signature);
                break;
            }
        }
        Card card = Card.parse(cardCrypto, rawSignedModel);

        List<Whitelist> whitelists = new ArrayList<>();
        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, true, false, whitelists);

        assertFalse("Card should NOT be verified", virgilCardVerifier.verifyCard(card));
    }

    @Test
    public void STC_10_verifier_shouldNot_verifyCard_ifWrongVirgilSignature() throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(10, STRING));
        for (RawSignature signature : rawSignedModel.getSignatures()) {
            if (SignerType.VIRGIL.getRawValue().equals(signature.getSigner())) {
                String sign = ConvertionUtils.toBase64String(this.virgilCrypto.generateSignature(
                        rawSignedModel.getContentSnapshot(), this.virgilCrypto.generateKeys().getPrivateKey()));
                signature.setSignature(sign);
                break;
            }
        }
        Card card = Card.parse(cardCrypto, rawSignedModel);

        List<Whitelist> whitelists = new ArrayList<>();
        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, true, whitelists);

        assertFalse("Card should NOT be verified", virgilCardVerifier.verifyCard(card));
    }

    @Test
    public void STC_10_verifier_shouldNot_verifyCard_ifWrongSelfSignature() throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(10, STRING));
        for (RawSignature signature : rawSignedModel.getSignatures()) {
            if (SignerType.SELF.getRawValue().equals(signature.getSigner())) {
                String sign = ConvertionUtils.toBase64String(this.virgilCrypto.generateSignature(
                        rawSignedModel.getContentSnapshot(), this.virgilCrypto.generateKeys().getPrivateKey()));
                signature.setSignature(sign);
                break;
            }
        }
        Card card = Card.parse(cardCrypto, rawSignedModel);

        List<Whitelist> whitelists = new ArrayList<>();
        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, true, false, whitelists);

        assertFalse("Card should NOT be verified", virgilCardVerifier.verifyCard(card));
    }

    @Test
    public void STC_10_verifier_shouldNot_verifyCard_ifCardDoesntHaveSignatureFromAtLeastOneWhiteList()
            throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(10, STRING));
        Card card = Card.parse(cardCrypto, rawSignedModel);

        VirgilPrivateKey privateKey1 = virgilCrypto
                .importPrivateKey(ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(10, "private_key1_base64")));
        VirgilPublicKey publicKey1 = virgilCrypto.extractPublicKey(privateKey1);
        VirgilPublicKey publicKey2 = this.virgilCrypto.generateKeys().getPublicKey();

        List<VerifierCredentials> verifierCredentialsList1 = new ArrayList<>();
        verifierCredentialsList1.add(new VerifierCredentials("extra1", publicKey1.getRawKey()));
        verifierCredentialsList1.add(new VerifierCredentials("extra2", publicKey2.getRawKey()));
        Whitelist whitelist1 = new Whitelist(verifierCredentialsList1);
        List<Whitelist> whitelists = new ArrayList<>();
        whitelists.add(whitelist1);
        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false, whitelists);

        assertFalse("Card should NOT be verified", virgilCardVerifier.verifyCard(card));
    }

    @Test
    public void STC_10_verifier_should_verifyCard_ifCardHasAtLeastOneSignatureFromWhiteList() throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(10, STRING));
        Card card = Card.parse(cardCrypto, rawSignedModel);

        VirgilPrivateKey privateKey1 = virgilCrypto
                .importPrivateKey(ConvertionUtils.base64ToBytes(dataProvider.getJsonByKey(10, "private_key1_base64")));
        VirgilPublicKey publicKey1 = virgilCrypto.extractPublicKey(privateKey1);

        VirgilKeyPair keyPair2 = this.virgilCrypto.generateKeys();
        VirgilPrivateKey privateKey2 = keyPair2.getPrivateKey();
        VirgilPublicKey publicKey2 = keyPair2.getPublicKey();

        VirgilKeyPair keyPair3 = this.virgilCrypto.generateKeys();
        VirgilPrivateKey privateKey3 = keyPair3.getPrivateKey();
        VirgilPublicKey publicKey3 = keyPair3.getPublicKey();

        List<VerifierCredentials> verifierCredentialsList1 = new ArrayList<>();
        verifierCredentialsList1.add(new VerifierCredentials("extra", publicKey1.getRawKey()));
        verifierCredentialsList1.add(new VerifierCredentials("extra2", publicKey2.getRawKey()));
        Whitelist whitelist1 = new Whitelist(verifierCredentialsList1);

        List<VerifierCredentials> verifierCredentialsList2 = new ArrayList<>();
        verifierCredentialsList2.add(new VerifierCredentials("extra3", publicKey3.getRawKey()));
        Whitelist whitelist2 = new Whitelist(verifierCredentialsList2);

        List<Whitelist> whitelists = new ArrayList<>();
        whitelists.add(whitelist1);
        whitelists.add(whitelist2);
        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false, whitelists);

        assertTrue("Card should be verified", virgilCardVerifier.verifyCard(card));
    }

    @Test
    public void STC_11() throws CryptoException {
        RawSignedModel rawSignedModel = RawSignedModel.fromString(dataProvider.getTestDataAs(11, STRING));
        Card card = Card.parse(cardCrypto, rawSignedModel);
        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false,
                Collections.<Whitelist> emptyList());
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
        Whitelist whitelistOne = new Whitelist(verifierCredentialsList);
        List<Whitelist> whitelists = new ArrayList<>();
        whitelists.add(whitelistOne);

        Card card = Card.parse(cardCrypto, rawSignedModel);
        VirgilCardVerifier virgilCardVerifier = new VirgilCardVerifier(cardCrypto, false, false, whitelists);
        assertFalse(virgilCardVerifier.verifyCard(card));

        verifierCredentialsList.add(new VerifierCredentials("extra", publicKey.getRawKey()));

        assertTrue(virgilCardVerifier.verifyCard(card));
    }

    @Test
    public void STC_26() throws CryptoException, VirgilServiceException {
        AccessTokenProvider accessTokenProvider = Mockito.mock(AccessTokenProvider.class);
        CardVerifier cardVerifier = new VirgilCardVerifier(this.cardCrypto, false, false);
        String cardsServiceUrl = getCardsServiceUrl();

        CardClient cardClient;
        if (StringUtils.isBlank(cardsServiceUrl)) {
            cardClient = new CardClient();
        } else {
            cardClient = new CardClient(cardsServiceUrl);
        }
        SignCallback signCallback = Mockito.mock(SignCallback.class);

        String identity = Generator.identity();
        RawSignedModel rawSignedModel = mocker.generateCardModel(identity);
        AccessToken expiredToken = mocker.generateExpiredAccessToken(identity);
        AccessToken token = mocker.generateAccessToken(identity);
        when(accessTokenProvider.getToken(Mockito.any(TokenContext.class))).thenReturn(expiredToken, token);
        when(signCallback.onSign(Mockito.any(RawSignedModel.class))).thenReturn(rawSignedModel);

        CardManager cardManager = new CardManager(this.cardCrypto,
                                                  accessTokenProvider,
                                                  cardVerifier,
                                                  cardClient,
                                                  signCallback,
                                                  true);

        Card card = cardManager.publishCard(rawSignedModel);
        assertNotNull(card);

        Card loadedCard = cardManager.getCard(card.getIdentifier());
        assertNotNull(loadedCard);

        List<Card> foundCards = cardManager.searchCards(card.getIdentity());
        assertNotNull(foundCards);
        assertEquals(1, foundCards.size());
    }
}