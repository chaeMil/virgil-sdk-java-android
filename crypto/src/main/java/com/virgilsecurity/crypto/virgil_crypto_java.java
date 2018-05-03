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

public class virgil_crypto_java implements virgil_crypto_javaConstants {
  public static int virgil_pythia_blind(SWIGTYPE_p_pythia_buf_t password, SWIGTYPE_p_pythia_buf_t blinded_password, SWIGTYPE_p_pythia_buf_t blinding_secret) {
    return virgil_crypto_javaJNI.virgil_pythia_blind(SWIGTYPE_p_pythia_buf_t.getCPtr(password), SWIGTYPE_p_pythia_buf_t.getCPtr(blinded_password), SWIGTYPE_p_pythia_buf_t.getCPtr(blinding_secret));
  }

  public static int virgil_pythia_deblind(SWIGTYPE_p_pythia_buf_t transformed_password, SWIGTYPE_p_pythia_buf_t blinding_secret, SWIGTYPE_p_pythia_buf_t deblinded_password) {
    return virgil_crypto_javaJNI.virgil_pythia_deblind(SWIGTYPE_p_pythia_buf_t.getCPtr(transformed_password), SWIGTYPE_p_pythia_buf_t.getCPtr(blinding_secret), SWIGTYPE_p_pythia_buf_t.getCPtr(deblinded_password));
  }

  public static int virgil_pythia_compute_transformation_key_pair(SWIGTYPE_p_pythia_buf_t transformation_key_id, SWIGTYPE_p_pythia_buf_t pythia_secret, SWIGTYPE_p_pythia_buf_t pythia_scope_secret, SWIGTYPE_p_pythia_buf_t transformation_private_key, SWIGTYPE_p_pythia_buf_t transformation_public_key) {
    return virgil_crypto_javaJNI.virgil_pythia_compute_transformation_key_pair(SWIGTYPE_p_pythia_buf_t.getCPtr(transformation_key_id), SWIGTYPE_p_pythia_buf_t.getCPtr(pythia_secret), SWIGTYPE_p_pythia_buf_t.getCPtr(pythia_scope_secret), SWIGTYPE_p_pythia_buf_t.getCPtr(transformation_private_key), SWIGTYPE_p_pythia_buf_t.getCPtr(transformation_public_key));
  }

  public static int virgil_pythia_transform(SWIGTYPE_p_pythia_buf_t blinded_password, SWIGTYPE_p_pythia_buf_t tweak, SWIGTYPE_p_pythia_buf_t transformation_private_key, SWIGTYPE_p_pythia_buf_t transformed_password, SWIGTYPE_p_pythia_buf_t transformed_tweak) {
    return virgil_crypto_javaJNI.virgil_pythia_transform(SWIGTYPE_p_pythia_buf_t.getCPtr(blinded_password), SWIGTYPE_p_pythia_buf_t.getCPtr(tweak), SWIGTYPE_p_pythia_buf_t.getCPtr(transformation_private_key), SWIGTYPE_p_pythia_buf_t.getCPtr(transformed_password), SWIGTYPE_p_pythia_buf_t.getCPtr(transformed_tweak));
  }

  public static int virgil_pythia_prove(SWIGTYPE_p_pythia_buf_t transformed_password, SWIGTYPE_p_pythia_buf_t blinded_password, SWIGTYPE_p_pythia_buf_t transformed_tweak, SWIGTYPE_p_pythia_buf_t transformation_private_key, SWIGTYPE_p_pythia_buf_t transformation_public_key, SWIGTYPE_p_pythia_buf_t proof_value_c, SWIGTYPE_p_pythia_buf_t proof_value_u) {
    return virgil_crypto_javaJNI.virgil_pythia_prove(SWIGTYPE_p_pythia_buf_t.getCPtr(transformed_password), SWIGTYPE_p_pythia_buf_t.getCPtr(blinded_password), SWIGTYPE_p_pythia_buf_t.getCPtr(transformed_tweak), SWIGTYPE_p_pythia_buf_t.getCPtr(transformation_private_key), SWIGTYPE_p_pythia_buf_t.getCPtr(transformation_public_key), SWIGTYPE_p_pythia_buf_t.getCPtr(proof_value_c), SWIGTYPE_p_pythia_buf_t.getCPtr(proof_value_u));
  }

  public static int virgil_pythia_verify(SWIGTYPE_p_pythia_buf_t transformed_password, SWIGTYPE_p_pythia_buf_t blinded_password, SWIGTYPE_p_pythia_buf_t tweak, SWIGTYPE_p_pythia_buf_t transformation_public_key, SWIGTYPE_p_pythia_buf_t proof_value_c, SWIGTYPE_p_pythia_buf_t proof_value_u, SWIGTYPE_p_int verified) {
    return virgil_crypto_javaJNI.virgil_pythia_verify(SWIGTYPE_p_pythia_buf_t.getCPtr(transformed_password), SWIGTYPE_p_pythia_buf_t.getCPtr(blinded_password), SWIGTYPE_p_pythia_buf_t.getCPtr(tweak), SWIGTYPE_p_pythia_buf_t.getCPtr(transformation_public_key), SWIGTYPE_p_pythia_buf_t.getCPtr(proof_value_c), SWIGTYPE_p_pythia_buf_t.getCPtr(proof_value_u), SWIGTYPE_p_int.getCPtr(verified));
  }

  public static int virgil_pythia_get_password_update_token(SWIGTYPE_p_pythia_buf_t previous_transformation_private_key, SWIGTYPE_p_pythia_buf_t new_transformation_private_key, SWIGTYPE_p_pythia_buf_t password_update_token) {
    return virgil_crypto_javaJNI.virgil_pythia_get_password_update_token(SWIGTYPE_p_pythia_buf_t.getCPtr(previous_transformation_private_key), SWIGTYPE_p_pythia_buf_t.getCPtr(new_transformation_private_key), SWIGTYPE_p_pythia_buf_t.getCPtr(password_update_token));
  }

  public static int virgil_pythia_update_deblinded_with_token(SWIGTYPE_p_pythia_buf_t deblinded_password, SWIGTYPE_p_pythia_buf_t password_update_token, SWIGTYPE_p_pythia_buf_t updated_deblinded_password) {
    return virgil_crypto_javaJNI.virgil_pythia_update_deblinded_with_token(SWIGTYPE_p_pythia_buf_t.getCPtr(deblinded_password), SWIGTYPE_p_pythia_buf_t.getCPtr(password_update_token), SWIGTYPE_p_pythia_buf_t.getCPtr(updated_deblinded_password));
  }

}
