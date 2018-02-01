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

public class VirgilPFSInitiatorPrivateInfo implements java.lang.AutoCloseable {
  protected static long getCPtr(VirgilPFSInitiatorPrivateInfo obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }
  private transient long swigCPtr;

  protected transient boolean swigCMemOwn;

  protected VirgilPFSInitiatorPrivateInfo(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  public VirgilPFSInitiatorPrivateInfo(VirgilPFSPrivateKey identityPrivateKey, VirgilPFSPrivateKey ephemeralPrivateKey) {
    this(virgil_crypto_javaJNI.new_VirgilPFSInitiatorPrivateInfo(VirgilPFSPrivateKey.getCPtr(identityPrivateKey), identityPrivateKey, VirgilPFSPrivateKey.getCPtr(ephemeralPrivateKey), ephemeralPrivateKey), true);
  }

  @Override
  public void close() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        virgil_crypto_javaJNI.delete_VirgilPFSInitiatorPrivateInfo(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  protected void finalize() {
    delete();
  }

  public VirgilPFSPrivateKey getEphemeralPrivateKey() {
    return new VirgilPFSPrivateKey(virgil_crypto_javaJNI.VirgilPFSInitiatorPrivateInfo_getEphemeralPrivateKey(swigCPtr, this), false);
  }

  public VirgilPFSPrivateKey getIdentityPrivateKey() {
    return new VirgilPFSPrivateKey(virgil_crypto_javaJNI.VirgilPFSInitiatorPrivateInfo_getIdentityPrivateKey(swigCPtr, this), false);
  }

}
