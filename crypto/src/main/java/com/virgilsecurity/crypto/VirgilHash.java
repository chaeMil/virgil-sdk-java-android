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

public class VirgilHash extends VirgilAsn1Compatible implements java.lang.AutoCloseable {
  private transient long swigCPtr;

  protected VirgilHash(long cPtr, boolean cMemoryOwn) {
    super(virgil_crypto_javaJNI.VirgilHash_SWIGUpcast(cPtr), cMemoryOwn);
    swigCPtr = cPtr;
  }

  protected static long getCPtr(VirgilHash obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        virgil_crypto_javaJNI.delete_VirgilHash(swigCPtr);
      }
      swigCPtr = 0;
    }
    super.delete();
  }

  @Override
  public void close() {
    delete();
  }

  public VirgilHash() {
    this(virgil_crypto_javaJNI.new_VirgilHash__SWIG_0(), true);
  }

  public VirgilHash(VirgilHash.Algorithm alg) {
    this(virgil_crypto_javaJNI.new_VirgilHash__SWIG_1(alg.swigValue()), true);
  }

  public VirgilHash(String name) {
    this(virgil_crypto_javaJNI.new_VirgilHash__SWIG_2(name), true);
  }

  public String name() {
    return virgil_crypto_javaJNI.VirgilHash_name(swigCPtr, this);
  }

  public VirgilHash.Algorithm algorithm() {
    return VirgilHash.Algorithm.swigToEnum(virgil_crypto_javaJNI.VirgilHash_algorithm(swigCPtr, this));
  }

  public int type() {
    return virgil_crypto_javaJNI.VirgilHash_type(swigCPtr, this);
  }

  public long size() {
    return virgil_crypto_javaJNI.VirgilHash_size(swigCPtr, this);
  }

  public byte[] hash(byte[] data) {
    return virgil_crypto_javaJNI.VirgilHash_hash(swigCPtr, this, data);
  }

  public void start() {
    virgil_crypto_javaJNI.VirgilHash_start(swigCPtr, this);
  }

  public void update(byte[] data) {
    virgil_crypto_javaJNI.VirgilHash_update(swigCPtr, this, data);
  }

  public byte[] finish() {
    return virgil_crypto_javaJNI.VirgilHash_finish(swigCPtr, this);
  }

  public byte[] hmac(byte[] key, byte[] data) {
    return virgil_crypto_javaJNI.VirgilHash_hmac(swigCPtr, this, key, data);
  }

  public void hmacStart(byte[] key) {
    virgil_crypto_javaJNI.VirgilHash_hmacStart(swigCPtr, this, key);
  }

  public void hmacReset() {
    virgil_crypto_javaJNI.VirgilHash_hmacReset(swigCPtr, this);
  }

  public void hmacUpdate(byte[] data) {
    virgil_crypto_javaJNI.VirgilHash_hmacUpdate(swigCPtr, this, data);
  }

  public byte[] hmacFinish() {
    return virgil_crypto_javaJNI.VirgilHash_hmacFinish(swigCPtr, this);
  }

  public VirgilHash(VirgilHash rhs) {
    this(virgil_crypto_javaJNI.new_VirgilHash__SWIG_3(VirgilHash.getCPtr(rhs), rhs), true);
  }

  public final static class Algorithm {
    public final static VirgilHash.Algorithm MD5 = new VirgilHash.Algorithm("MD5");
    public final static VirgilHash.Algorithm SHA1 = new VirgilHash.Algorithm("SHA1");
    public final static VirgilHash.Algorithm SHA224 = new VirgilHash.Algorithm("SHA224");
    public final static VirgilHash.Algorithm SHA256 = new VirgilHash.Algorithm("SHA256");
    public final static VirgilHash.Algorithm SHA384 = new VirgilHash.Algorithm("SHA384");
    public final static VirgilHash.Algorithm SHA512 = new VirgilHash.Algorithm("SHA512");

    public final int swigValue() {
      return swigValue;
    }

    public String toString() {
      return swigName;
    }

    public static Algorithm swigToEnum(int swigValue) {
      if (swigValue < swigValues.length && swigValue >= 0 && swigValues[swigValue].swigValue == swigValue)
        return swigValues[swigValue];
      for (int i = 0; i < swigValues.length; i++)
        if (swigValues[i].swigValue == swigValue)
          return swigValues[i];
      throw new IllegalArgumentException("No enum " + Algorithm.class + " with value " + swigValue);
    }

    private Algorithm(String swigName) {
      this.swigName = swigName;
      this.swigValue = swigNext++;
    }

    private Algorithm(String swigName, int swigValue) {
      this.swigName = swigName;
      this.swigValue = swigValue;
      swigNext = swigValue+1;
    }

    private Algorithm(String swigName, Algorithm swigEnum) {
      this.swigName = swigName;
      this.swigValue = swigEnum.swigValue;
      swigNext = this.swigValue+1;
    }

    private static Algorithm[] swigValues = { MD5, SHA1, SHA224, SHA256, SHA384, SHA512 };
    private static int swigNext = 0;
    private final int swigValue;
    private final String swigName;
  }

}
