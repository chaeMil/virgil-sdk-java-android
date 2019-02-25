/*
 * Copyright (c) 2015-2019, Virgil Security, Inc.
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

package com.virgilsecurity.sdk.jwt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.virgilsecurity.sdk.FakeDataFactory;
import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.AccessTokenSigner;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for {@link JwtGenerator}.
 * 
 * @author Andrii Iakovenko
 *
 */
public class JwtGeneratorTest {

  private FakeDataFactory fake;
  private AccessTokenSigner signer;
  private JwtGenerator generator;
  private String identity;

  @Test
  public void generateToken_autohandle_of_expireAt() throws CryptoException, InterruptedException {
    FakeDataFactory fake = new FakeDataFactory();
    VirgilAccessTokenSigner signer = new VirgilAccessTokenSigner();

    String appId = fake.getApplicationId();
    PrivateKey privateKey = fake.getApiPrivateKey();
    final String apiPublicKeyId = fake.getApiPublicKeyId();

    JwtGenerator generator = new JwtGenerator(appId, privateKey, apiPublicKeyId,
        TimeSpan.fromTime(2, TimeUnit.SECONDS), signer);

    Jwt jwt = generator.generateToken(this.identity);
    assertFalse(jwt.isExpired());
    Thread.sleep(3 * 1000);
    assertTrue(jwt.isExpired());

    Jwt jwt2 = generator.generateToken(this.identity);
    assertFalse(jwt2.isExpired());
    Thread.sleep(3 * 1000);
    assertTrue(jwt2.isExpired());
  }

  @Test
  public void generateToken_byIdentity() throws CryptoException {
    Jwt jwt = this.generator.generateToken(this.identity);

    assertNotNull(jwt);
    assertEquals(this.identity, jwt.getIdentity());
    assertTrue(signer.verifyTokenSignature(jwt.getSignatureData(),
        ConvertionUtils.toBytes(jwt.unsigned()), fake.getApiPublicKey()));
  }

  @Test
  public void generateToken_byIdentity_nullIdentity() throws CryptoException {
    Jwt jwt = this.generator.generateToken(null);

    assertNotNull(jwt);
    assertNull(jwt.getIdentity());
    assertTrue(signer.verifyTokenSignature(jwt.getSignatureData(),
        ConvertionUtils.toBytes(jwt.unsigned()), fake.getApiPublicKey()));
  }

  @Before
  public void setup() throws CryptoException {
    this.fake = new FakeDataFactory();
    this.signer = new VirgilAccessTokenSigner();
    this.generator = new JwtGenerator(fake.getApplicationId(), fake.getApiPrivateKey(),
        fake.getApiPublicKeyId(), TimeSpan.fromTime(10, TimeUnit.MINUTES), signer);

    this.identity = fake.getIdentity();
  }

}
