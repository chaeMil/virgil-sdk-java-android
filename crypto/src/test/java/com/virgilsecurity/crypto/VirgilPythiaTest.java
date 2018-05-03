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
package com.virgilsecurity.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.lang.ArrayUtils;
import org.junit.Before;
import org.junit.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

/**
 * @author Andrii Iakovenko
 *
 */
public class VirgilPythiaTest {

    private JsonObject sampleJson;
    private VirgilPythia pythia;
    private byte[] pythiaSecret;
    private byte[] pythiaScopeSecret;

    @Before
    public void setup() throws CryptoException {
        sampleJson = (JsonObject) new JsonParser().parse(new InputStreamReader(
                this.getClass().getClassLoader().getResourceAsStream("com/virgilsecurity/crypto/pythia-crypto.json")));
        this.pythiaSecret = getBytes("kPythiaSecret");
        this.pythiaScopeSecret = getBytes("kPythiaScopeSecret");

        // YTC-1
        this.pythia = new VirgilPythia();
    }

    @Test
    public void computeTransformationKeyPair() {
        byte[] transformationKeyID = getBytes("kTransformationKeyID");

        VirgilPythiaTransformationKeyPair transformationKeyPair = this.pythia
                .computeTransformationKeyPair(transformationKeyID, this.pythiaSecret, this.pythiaScopeSecret);

        assertNotNull(transformationKeyPair);
        assertArrayEquals(getHexBytes("kTransformationPrivateKey"), transformationKeyPair.privateKey());
        assertArrayEquals(getHexBytes("kTransformationPublicKey"), transformationKeyPair.publicKey());
    }

    @Test
    public void blind() {
        // YTC-3
        byte[] transformationKeyID = getBytes("kTransformationKeyID");
        byte[] kPassword = getBytes("kPassword");
        byte[] kTweek = getBytes("kTweek");
        byte[] kDeblindedPassword = getHexBytes("kDeblindedPassword");

        Set<VirgilPythiaBlindResult> blindResults = new HashSet<>();
        for (int i = 0; i < 10; i++) {
            VirgilPythiaTransformationKeyPair transformationKeyPair = this.pythia
                    .computeTransformationKeyPair(transformationKeyID, this.pythiaSecret, this.pythiaScopeSecret);
            VirgilPythiaBlindResult blindResult = pythia.blind(kPassword);

            // blindResult should be different on each iteration
            for (VirgilPythiaBlindResult res : blindResults) {
                if (ArrayUtils.isEquals(res.blindedPassword(), blindResult.blindedPassword())
                        && ArrayUtils.isEquals(res.blindingSecret(), blindResult.blindingSecret())) {
                    fail();
                }
            }
            blindResults.add(blindResult);

            VirgilPythiaTransformResult transformResult = pythia.transform(blindResult.blindedPassword(), kTweek,
                    transformationKeyPair.privateKey());
            assertNotNull(transformResult);

            byte[] deblindResult = pythia.deblind(transformResult.transformedPassword(), blindResult.blindingSecret());
            assertArrayEquals(kDeblindedPassword, deblindResult);
        }
    }

    @Test
    public void prove() {
        // YTC-4
        byte[] transformationKeyID = getBytes("kTransformationKeyID");
        byte[] kPassword = getBytes("kPassword");
        byte[] kTweek = getBytes("kTweek");

        VirgilPythiaTransformationKeyPair transformationKeyPair = this.pythia
                .computeTransformationKeyPair(transformationKeyID, this.pythiaSecret, this.pythiaScopeSecret);
        VirgilPythiaBlindResult blindResult = pythia.blind(kPassword);
        VirgilPythiaTransformResult transformResult = pythia.transform(blindResult.blindedPassword(), kTweek,
                transformationKeyPair.privateKey());
        VirgilPythiaProveResult proveResult = pythia.prove(transformResult.transformedPassword(),
                blindResult.blindedPassword(), transformResult.transformedTweak(), transformationKeyPair);
        boolean verifyResult = pythia.verify(transformResult.transformedPassword(), blindResult.blindedPassword(),
                kTweek, transformationKeyPair.publicKey(), proveResult.proofValueC(), proveResult.proofValueU());
        assertTrue(verifyResult);
    }

    @Test
    public void updateDeblindedWithToken() {
        // YTC-5
        byte[] transformationKeyID = getBytes("kTransformationKeyID");
        byte[] kPassword = getBytes("kPassword");
        byte[] kTweek = getBytes("kTweek");
        byte[] kNewTransformationPrivateKey = getHexBytes("kNewTransformationPrivateKey");
        byte[] kNewTransformationPublicKey = getHexBytes("kNewTransformationPublicKey");
        byte[] kUpdateToken = getHexBytes("kUpdateToken");
        byte[] kNewDeblinded = getHexBytes("kNewDeblinded");

        VirgilPythiaTransformationKeyPair transformationKeyPair = this.pythia
                .computeTransformationKeyPair(transformationKeyID, this.pythiaSecret, this.pythiaScopeSecret);
        VirgilPythiaBlindResult blindResult = pythia.blind(kPassword);
        VirgilPythiaTransformResult transformResult = pythia.transform(blindResult.blindedPassword(), kTweek,
                transformationKeyPair.privateKey());
        byte[] deblindResult = pythia.deblind(transformResult.transformedPassword(), blindResult.blindingSecret());

        VirgilPythiaTransformationKeyPair newTransformationKeyPair = this.pythia.computeTransformationKeyPair(
                transformationKeyID, getBytes("kNewPythiaSecret"), getBytes("kNewPythiaScopeSecret"));
        assertArrayEquals(kNewTransformationPrivateKey, newTransformationKeyPair.privateKey());
        assertArrayEquals(kNewTransformationPublicKey, newTransformationKeyPair.publicKey());

        byte[] passwordUpdateTokenResult = pythia.getPasswordUpdateToken(transformationKeyPair.privateKey(),
                newTransformationKeyPair.privateKey());
        assertArrayEquals(kUpdateToken, passwordUpdateTokenResult);

        byte[] updatedDeblindPasswordResult = pythia.updateDeblindedWithToken(deblindResult, passwordUpdateTokenResult);
        VirgilPythiaTransformResult newTransformResult = pythia.transform(blindResult.blindedPassword(), kTweek,
                newTransformationKeyPair.privateKey());
        byte[] newDeblindResult = pythia.deblind(newTransformResult.transformedPassword(),
                blindResult.blindingSecret());
        assertArrayEquals(kNewDeblinded, updatedDeblindPasswordResult);
        assertArrayEquals(kNewDeblinded, newDeblindResult);
    }

    private byte[] getBytes(String key) {
        return this.sampleJson.get(key).getAsString().getBytes(StandardCharsets.UTF_8);
    }

    private byte[] getHexBytes(String key) {
        return DatatypeConverter.parseHexBinary(this.sampleJson.get(key).getAsString());
    }

}
