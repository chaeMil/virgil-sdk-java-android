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

public class VirgilAsn1Reader implements java.lang.AutoCloseable {
  protected static long getCPtr(VirgilAsn1Reader obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }
  private transient long swigCPtr;

  protected transient boolean swigCMemOwn;

  public VirgilAsn1Reader() {
    this(virgil_crypto_javaJNI.new_VirgilAsn1Reader__SWIG_0(), true);
  }

  public VirgilAsn1Reader(byte[] data) {
    this(virgil_crypto_javaJNI.new_VirgilAsn1Reader__SWIG_1(data), true);
  }

  protected VirgilAsn1Reader(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  @Override
  public void close() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        virgil_crypto_javaJNI.delete_VirgilAsn1Reader(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  protected void finalize() {
    delete();
  }

  public boolean readBool() {
    return virgil_crypto_javaJNI.VirgilAsn1Reader_readBool(swigCPtr, this);
  }

  public long readContextTag(short tag) {
    return virgil_crypto_javaJNI.VirgilAsn1Reader_readContextTag(swigCPtr, this, tag);
  }

  public byte[] readData() {
    return virgil_crypto_javaJNI.VirgilAsn1Reader_readData(swigCPtr, this);
  }

  public int readInteger() {
    return virgil_crypto_javaJNI.VirgilAsn1Reader_readInteger(swigCPtr, this);
  }

  public void readNull() {
    virgil_crypto_javaJNI.VirgilAsn1Reader_readNull(swigCPtr, this);
  }

  public byte[] readOctetString() {
    return virgil_crypto_javaJNI.VirgilAsn1Reader_readOctetString(swigCPtr, this);
  }

  public String readOID() {
    return virgil_crypto_javaJNI.VirgilAsn1Reader_readOID(swigCPtr, this);
  }

  public long readSequence() {
    return virgil_crypto_javaJNI.VirgilAsn1Reader_readSequence(swigCPtr, this);
  }

  public long readSet() {
    return virgil_crypto_javaJNI.VirgilAsn1Reader_readSet(swigCPtr, this);
  }

  public byte[] readUTF8String() {
    return virgil_crypto_javaJNI.VirgilAsn1Reader_readUTF8String(swigCPtr, this);
  }

  public void reset(byte[] data) {
    virgil_crypto_javaJNI.VirgilAsn1Reader_reset(swigCPtr, this, data);
  }

}
