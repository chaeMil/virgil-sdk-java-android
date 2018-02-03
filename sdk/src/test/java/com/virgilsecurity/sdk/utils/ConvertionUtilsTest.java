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
package com.virgilsecurity.sdk.utils;

import com.virgilsecurity.sdk.cards.model.RawSignedModel;
import com.virgilsecurity.sdk.common.ClassForSerialization;
import com.virgilsecurity.sdk.crypto.VirgilPublicKey;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@linkplain ConvertionUtils}.
 *
 * @author Andrii Iakovenko
 * @author Danylo Oliinyk
 *
 */
public class ConvertionUtilsTest {

	private static final String TEXT = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

	@Test
	public void base64String() {
		String base64string = ConvertionUtils.toBase64String(TEXT);
		String str = ConvertionUtils.base64ToString(base64string);

		assertEquals(TEXT, str);
	}

	@Test
	public void base64ByteArray() {
		byte[] base64bytes = ConvertionUtils.toBase64Bytes(TEXT);
		String str = ConvertionUtils.base64ToString(base64bytes);

		assertEquals(TEXT, str);
	}

	@Test
	public void toBytes() {
		byte[] bytes = ConvertionUtils.toBytes(TEXT);
		String str = ConvertionUtils.toString(bytes);
		assertEquals(TEXT, str);
	}

	@Test
	public void toHEX() {
		byte[] bytes = ConvertionUtils.toBytes(TEXT);
		String str = ConvertionUtils.toHex(bytes);
		bytes = ConvertionUtils.hexToBytes(str);
		str = ConvertionUtils.toString(bytes);
		assertEquals(TEXT, str);
	}

	@Test
	public void serialization() throws IOException, ClassNotFoundException {

		ClassForSerialization classForSerialization = new ClassForSerialization("Gregory", "Gilbert".getBytes());

		assertEquals(classForSerialization.getName(), "Gregory");
        assertEquals(new String(classForSerialization.getData()), "Gilbert");

		String serializedObject = ConvertionUtils.serializeObject(classForSerialization);

		System.out.println(serializedObject);

		ClassForSerialization deserializedClassForSerialization = (ClassForSerialization) ConvertionUtils.deserializeObject(serializedObject);

        assertEquals(deserializedClassForSerialization.getName(), "Gregory");
        assertEquals(new String(deserializedClassForSerialization.getData()), "Gilbert");
	}

	@Test
	public void deSerializationJson() {
		String rawJson = "{ \"id\": \"12345\", \"content_snapshot\":\"AQIDBAU=\" }";
		RawSignedModel cardModel = ConvertionUtils.deserializeFromJson(rawJson, RawSignedModel.class);

		Assert.assertTrue(Arrays.equals(cardModel.getContentSnapshot(), ConvertionUtils.base64ToBytes("AQIDBAU=")));
	}

	@Test
	public void deSerializationHashMap() {
		Map<String, String> additionalData = new HashMap<>();
		additionalData.put("Info", "best");
		additionalData.put("Hello", "Buddy");

		String hashMapSerialized = ConvertionUtils.serializeToJson(additionalData);
		Map<String, String> deserializeFromJson = ConvertionUtils.deserializeFromJson(hashMapSerialized);

		assertEquals(additionalData, deserializeFromJson);
	}

	@Test
	public void byteEquals() {
		String hello = "Hello";
		byte[] bArr1 = hello.getBytes();
		byte[] bArr2 = hello.getBytes();

		assertTrue(Arrays.equals(bArr1, bArr2));
	}

	@Test
	public void base64UrlConvertion() {
		String raw = "This is the best string ever!";
		String rawToB64 = ConvertionUtils.toBase64String(raw);

		String encodedBase64Url = ConvertionUtils.toBase64Url(rawToB64);
		String decodedBase64Url = ConvertionUtils.fromBase64Url(encodedBase64Url);

		String base64toRaw = ConvertionUtils.base64ToString(decodedBase64Url);

		assertEquals(raw, base64toRaw);
	}

	@Test
	public void backslashJsonSerialization() {
		String hello = "MCowBQYDK2VwAyEAr0rjTWlCLJ8q9em0og33grHEh/3vmqp0IewosUaVnQg=";
        String serializedToJson = ConvertionUtils.serializeToJson(hello);

        assertEquals(hello, serializedToJson.replace("\"", ""));
	}
}
