/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 3.0.8
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package com.virgilsecurity.crypto;

public class VirgilPFSResponderPublicInfo implements java.lang.AutoCloseable {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected VirgilPFSResponderPublicInfo(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(VirgilPFSResponderPublicInfo obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        virgil_crypto_javaJNI.delete_VirgilPFSResponderPublicInfo(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  @Override
  public void close() {
    delete();
  }

  public VirgilPFSResponderPublicInfo(VirgilPFSPublicKey identityPublicKey, VirgilPFSPublicKey longTermPublicKey, VirgilPFSPublicKey oneTimePublicKey) {
    this(virgil_crypto_javaJNI.new_VirgilPFSResponderPublicInfo__SWIG_0(VirgilPFSPublicKey.getCPtr(identityPublicKey), identityPublicKey, VirgilPFSPublicKey.getCPtr(longTermPublicKey), longTermPublicKey, VirgilPFSPublicKey.getCPtr(oneTimePublicKey), oneTimePublicKey), true);
  }

  public VirgilPFSResponderPublicInfo(VirgilPFSPublicKey identityPublicKey, VirgilPFSPublicKey longTermPublicKey) {
    this(virgil_crypto_javaJNI.new_VirgilPFSResponderPublicInfo__SWIG_1(VirgilPFSPublicKey.getCPtr(identityPublicKey), identityPublicKey, VirgilPFSPublicKey.getCPtr(longTermPublicKey), longTermPublicKey), true);
  }

  public VirgilPFSPublicKey getIdentityPublicKey() {
    return new VirgilPFSPublicKey(virgil_crypto_javaJNI.VirgilPFSResponderPublicInfo_getIdentityPublicKey(swigCPtr, this), false);
  }

  public VirgilPFSPublicKey getLongTermPublicKey() {
    return new VirgilPFSPublicKey(virgil_crypto_javaJNI.VirgilPFSResponderPublicInfo_getLongTermPublicKey(swigCPtr, this), false);
  }

  public VirgilPFSPublicKey getOneTimePublicKey() {
    return new VirgilPFSPublicKey(virgil_crypto_javaJNI.VirgilPFSResponderPublicInfo_getOneTimePublicKey(swigCPtr, this), false);
  }

}
