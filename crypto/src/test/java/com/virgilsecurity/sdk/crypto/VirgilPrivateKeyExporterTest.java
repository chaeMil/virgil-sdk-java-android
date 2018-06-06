/*
 * Copyright (c) 2018, Virgil Security, Inc.
 *
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of virgil nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.exception.NullArgumentException;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/**
 * Unit tests for {@link VirgilPrivateKeyExporter}.
 * 
 * @author Andrii Iakovenko
 *
 */
@RunWith(Parameterized.class)
public class VirgilPrivateKeyExporterTest {

  private VirgilCrypto crypto;
  private VirgilPrivateKey privateKey;

  @Parameter(0)
  public VirgilPrivateKeyExporter exporter;
  @Parameter(1)
  public String password;

  @Parameters(name = "{index}: password={1}")
  public static Collection<Object[]> params() {
    return Arrays.asList(new Object[][] { { new VirgilPrivateKeyExporter(), null },
        { new VirgilPrivateKeyExporter(new VirgilCrypto()), null },
        { new VirgilPrivateKeyExporter(new VirgilCrypto(), null), null },
        { new VirgilPrivateKeyExporter(new VirgilCrypto(), "PASSWORD"), "PASSWORD" } });
  }

  @Test
  public void exportPrivateKey() throws CryptoException {
    byte[] exportedKeyData = exporter.exportPrivateKey(privateKey);
    assertNotNull(exportedKeyData);
  }

  @Test
  public void importPrivateKey() throws CryptoException {
    byte[] exportedKeyData = exporter.exportPrivateKey(privateKey);

    VirgilPrivateKey importedKey = (VirgilPrivateKey) exporter.importPrivateKey(exportedKeyData);
    assertNotNull(importedKey);
    assertEquals(privateKey, importedKey);
  }

  @Test(expected = CryptoException.class)
  public void importPrivateKey_invalidData() throws CryptoException {
    exporter.importPrivateKey("wrong_data".getBytes());
  }

  @Test(expected = NullArgumentException.class)
  public void importPrivateKey_null() throws CryptoException {
    exporter.importPrivateKey(null);
  }

  @Before
  public void setup() throws CryptoException {
    this.crypto = new VirgilCrypto();
    this.privateKey = this.crypto.generateKeys().getPrivateKey();
  }

}
