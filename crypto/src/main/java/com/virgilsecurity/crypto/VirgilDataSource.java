/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 3.0.8
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package com.virgilsecurity.crypto;

public class VirgilDataSource implements java.lang.AutoCloseable {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected VirgilDataSource(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(VirgilDataSource obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        virgil_crypto_javaJNI.delete_VirgilDataSource(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  protected void swigDirectorDisconnect() {
    swigCMemOwn = false;
    delete();
  }

  public void swigReleaseOwnership() {
    swigCMemOwn = false;
    virgil_crypto_javaJNI.VirgilDataSource_change_ownership(this, swigCPtr, false);
  }

  public void swigTakeOwnership() {
    swigCMemOwn = true;
    virgil_crypto_javaJNI.VirgilDataSource_change_ownership(this, swigCPtr, true);
  }

  @Override
  public void close() throws java.io.IOException {
    delete();
  }

  public boolean hasData() throws java.io.IOException {
    return virgil_crypto_javaJNI.VirgilDataSource_hasData(swigCPtr, this);
  }

  public byte[] read() throws java.io.IOException {
    return virgil_crypto_javaJNI.VirgilDataSource_read(swigCPtr, this);
  }

  public VirgilDataSource() {
    this(virgil_crypto_javaJNI.new_VirgilDataSource(), true);
    virgil_crypto_javaJNI.VirgilDataSource_director_connect(this, swigCPtr, swigCMemOwn, true);
  }

}
