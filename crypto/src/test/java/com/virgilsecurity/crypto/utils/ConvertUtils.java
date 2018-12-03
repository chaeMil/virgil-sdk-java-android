package com.virgilsecurity.crypto.utils;

public class ConvertUtils {

  /**
   * Decode HEX string to byte array.
   *
   * @param value
   *          The string to be converted.
   * @return the byte array.
   */
  public static byte[] hexToBytes(String value) {
    final int len = value.length();

    // "111" is not a valid hex encoding.
    if (len % 2 != 0) {
      throw new IllegalArgumentException("hexBinary needs to be even-length: " + value);
    }

    byte[] out = new byte[len / 2];

    for (int i = 0; i < len; i += 2) {
      int h = hexToBin(value.charAt(i));
      int l = hexToBin(value.charAt(i + 1));
      if (h == -1 || l == -1) {
        throw new IllegalArgumentException("contains illegal character for hexBinary: " + value);
      }

      out[i / 2] = (byte) (h * 16 + l);
    }

    return out;
  }

  private static int hexToBin(char ch) {
    if ('0' <= ch && ch <= '9') {
      return ch - '0';
    }
    if ('A' <= ch && ch <= 'F') {
      return ch - 'A' + 10;
    }
    if ('a' <= ch && ch <= 'f') {
      return ch - 'a' + 10;
    }
    return -1;
  }

}
