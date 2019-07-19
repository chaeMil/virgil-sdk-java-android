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

import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.AccessTokenSigner;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.utils.Base64Url;
import com.virgilsecurity.sdk.utils.ConvertionUtils;

import java.util.Date;
import java.util.Map;

/**
 * The {@link JwtGenerator} class is used for generation of {@link Jwt} with provided tools and
 * data.
 */
public class JwtGenerator {

  private final PrivateKey apiKey;
  private final String apiPublicKeyIdentifier;
  private final AccessTokenSigner accessTokenSigner;
  private final String appId;
  private final TimeSpan ttl;

  /**
   * Instantiates a new Jwt generator.
   *
   * @param appId                  the application identifier
   * @param apiKey                 the api private key
   * @param apiPublicKeyIdentifier the api public key identifier
   * @param ttl                    the lifetime of token - when it expires at
   * @param accessTokenSigner      the access token signer
   */
  public JwtGenerator(String appId, PrivateKey apiKey, String apiPublicKeyIdentifier, TimeSpan ttl,
                      AccessTokenSigner accessTokenSigner) {
    this.appId = appId;
    this.apiKey = apiKey;
    this.apiPublicKeyIdentifier = apiPublicKeyIdentifier;
    this.ttl = ttl;
    this.accessTokenSigner = accessTokenSigner;
  }

  /**
   * Generate token jwt.
   *
   * @param identity the identity
   * @return the generated Jwt
   * @throws CryptoException if issue occurred while generating token signature
   */
  public Jwt generateToken(String identity) throws CryptoException {
    JwtHeaderContent jwtHeaderContent = new JwtHeaderContent(apiPublicKeyIdentifier);
    JwtBodyContent jwtBodyContent = new JwtBodyContent(appId, identity, ttl, new Date());

    Jwt jwtToken = new Jwt(jwtHeaderContent, jwtBodyContent);
    byte[] signature = this.accessTokenSigner
        .generateTokenSignature(ConvertionUtils.toBytes(jwtToken.unsigned()), apiKey);
    return new Jwt(jwtToken.stringRepresentation() + "." + Base64Url.encode(signature));
  }

  /**
   * Generate token jwt.
   *
   * @param identity       the identity
   * @param additionalData the additional data associated with token
   * @return the generated Jwt
   * @throws CryptoException if issue occurred while generating token signature
   */
  public Jwt generateToken(String identity, Map<String, String> additionalData)
      throws CryptoException {
    JwtHeaderContent jwtHeaderContent = new JwtHeaderContent(apiPublicKeyIdentifier);
    JwtBodyContent jwtBodyContent = new JwtBodyContent(appId, identity, additionalData, ttl,
        new Date());

    Jwt jwtToken = new Jwt(jwtHeaderContent, jwtBodyContent);
    byte[] signature = this.accessTokenSigner
        .generateTokenSignature(ConvertionUtils.toBytes(jwtToken.unsigned()), apiKey);
    return new Jwt(jwtToken.stringRepresentation() + "." + Base64Url.encode(signature));
  }
}
