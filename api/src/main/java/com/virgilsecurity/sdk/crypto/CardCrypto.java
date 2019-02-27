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

package com.virgilsecurity.sdk.crypto;

import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;

/**
 * The {@link CardCrypto} interface defines a list of methods that provide a signature generation
 * and signature verification methods.
 */
public interface CardCrypto {

  /**
   * Exports the {@code publicKey} into material representation.
   *
   * @param publicKey
   *          The public key.
   * @return Public key in material representation of {@code byte[]}.
   * @throws CryptoException
   *           if problems occurred while exporting key
   */
  byte[] exportPublicKey(PublicKey publicKey) throws CryptoException;

  /**
   * Generates the fingerprint(512-bit hash) for the specified {@code data}.
   *
   * @param data
   *          The input data for which to compute the fingerprint.
   * @return The fingerprint for specified data.
   * @throws CryptoException
   *           if problems occurred while generating hash
   */
  byte[] generateSHA512(byte[] data) throws CryptoException;

  /**
   * Generates the digital signature for the specified {@code data} using the specified
   * {@link PrivateKey}
   *
   * @param data
   *          The input data for which to compute the signature.
   * @param privateKey
   *          The private key.
   * @return The digital signature for the specified data.
   * @throws CryptoException
   *           if problems occurred while generating signature.
   */
  byte[] generateSignature(byte[] data, PrivateKey privateKey) throws CryptoException;

  /**
   * Imports the public key from its material representation.
   *
   * @param data
   *          The public key material representation bytes.
   * @return The instance of {@link PublicKey} imported.
   * @throws CryptoException
   *           if problems occurred while importing key
   */
  PublicKey importPublicKey(byte[] data) throws CryptoException;

  /**
   * Verifies that a digital signature is valid by checking the {@code signature}, with provided
   * {@code publicKey} and {@code data}.
   *
   * @param signature
   *          The digital signature for the {@code data}.
   * @param data
   *          The input data for which the {@code signature} has been generated.
   * @param publicKey
   *          The {@link PublicKey}.
   * @return {@code true} if signature is valid, {@code false} otherwise.
   * @throws CryptoException
   *           if problems occurred while verifying signature.
   */
  boolean verifySignature(byte[] signature, byte[] data, PublicKey publicKey)
      throws CryptoException;
}
