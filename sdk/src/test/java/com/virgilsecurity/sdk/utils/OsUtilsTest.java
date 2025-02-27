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

package com.virgilsecurity.sdk.utils;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * OsUtilsTest class.
 */
public class OsUtilsTest {

  private static final String ANDROID_OS_NAME = "android";
  private static final String LINUX_OS_NAME = "linux";
  private static final String WINDOWS_OS_NAME = "windows";
  private static final String MACOS_OS_NAME = "mac os";
  private static final String VIRGIL_AGENT_MACOS = "darwin";
  private static final String UNKNOWN_OS = "unknown";


  @Test public void test_os_type() {
    Class androidClass = null;
    try {
      androidClass = Class.forName("android.os.Build");
    } catch (ClassNotFoundException e) {
      // Leave androidClass as null
    }

    if (androidClass != null) {
      assertEquals(ANDROID_OS_NAME, OsUtils.getOsAgentName());
      return;
    }

    String osName = System.getProperty("os.name").toLowerCase();

    if (osName.startsWith(LINUX_OS_NAME)) {
      assertEquals(LINUX_OS_NAME, OsUtils.getOsAgentName());
    } else if (osName.startsWith(WINDOWS_OS_NAME)) {
      assertEquals(WINDOWS_OS_NAME, OsUtils.getOsAgentName());
    } else if (osName.startsWith(MACOS_OS_NAME)) {
      assertEquals(VIRGIL_AGENT_MACOS, OsUtils.getOsAgentName());
    } else {
      assertEquals(UNKNOWN_OS, OsUtils.getOsAgentName());
    }
  }
}
