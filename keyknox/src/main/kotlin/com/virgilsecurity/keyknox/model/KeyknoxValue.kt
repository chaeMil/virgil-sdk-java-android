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

package com.virgilsecurity.keyknox.model

import java.util.*

/**
 * Class represents value stored in Keyknox cloud.
 */
open class KeyknoxValue(val meta: ByteArray? = null, val value: ByteArray? = null, val version: String, val keyknoxHash: ByteArray? = null) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DecryptedKeyknoxValue

        if (!Arrays.equals(meta, other.meta)) return false
        if (!Arrays.equals(value, other.value)) return false
        if (version != other.version) return false
        if (!Arrays.equals(keyknoxHash, other.keyknoxHash)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = meta?.let { Arrays.hashCode(it) } ?: 0
        result = 31 * result + (value?.let { Arrays.hashCode(it) } ?: 0)
        result = 31 * result + version.hashCode()
        result = 31 * result + (keyknoxHash?.let { Arrays.hashCode(it) } ?: 0)
        return result
    }
}

/**
 * Decrypted value stored in Keyknox cloud.
 *
 */
class DecryptedKeyknoxValue(meta: ByteArray?, value: ByteArray?, version: String, keyknoxHash: ByteArray? = null) :
        KeyknoxValue(meta, value, version, keyknoxHash) {

    constructor(keyknoxValue: KeyknoxValue) : this(keyknoxValue.meta, keyknoxValue.value, keyknoxValue.version, keyknoxValue.keyknoxHash) {

    }
}

/**
 * Encrypted value stored in Keyknox cloud.
 *
 */
class EncryptedKeyknoxValue(meta: ByteArray?, value: ByteArray?, version: String, keyknoxHash: ByteArray? = null) :
        KeyknoxValue(meta, value, version, keyknoxHash) {

    constructor(keyknoxValue: KeyknoxValue) : this(keyknoxValue.meta, keyknoxValue.value, keyknoxValue.version, keyknoxValue.keyknoxHash) {

    }
}
