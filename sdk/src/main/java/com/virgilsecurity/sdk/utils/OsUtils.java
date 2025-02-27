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

/**
 * OsUtils class.
 */
public class OsUtils {

  /**
   * Get current Operation System (OS).
   *
   * @return the OS Name that is currently running the application.
   */
  public static String getOsAgentName() {
    if (isAndroidOs()) {
      return OsNames.ANDROID_OS_NAME.agentName;
    }

    String currentOsName = System.getProperty("os.name").toLowerCase();

    for (OsNames osName : OsNames.values()) {
      if (currentOsName.startsWith(osName.name)) {
        return osName.agentName;
      }
    }

    return OsNames.UNKNOWN_OS.agentName;
  }

  /**
   * Checks whether the current OS is android.
   *
   * @return *true* if current OS is android, *false* otherwise.
   */
  private static boolean isAndroidOs() {
    try {
      Class.forName("android.os.Build");
    } catch (ClassNotFoundException e) {
      return false;
    }

    return true;
  }

  /**
   * Enum with names of OSs to filter the *os.name* system property, and return values
   * for virgil-agent.
   */
  private enum OsNames {
    ANDROID_OS_NAME("android"),
    LINUX_OS_NAME("linux"),
    WINDOWS_OS_NAME("windows"),
    MACOS_OS_NAME("mac os", "darwin"),
    UNKNOWN_OS("unknown");

    private final String name;
    private final String agentName;

    OsNames(String name) {
      this.name = name;
      this.agentName = name;
    }

    OsNames(String name, String loggedName) {
      this.name = name;
      this.agentName = loggedName;
    }

    @Override public String toString() {
      return name;
    }

  }
}
