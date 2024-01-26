package main.java;

import java.util.List;

public interface EncryptDecrypt {
    List<Integer> encrypt(String message, String key);

    String decrypt(List<Integer> encryptedMessage, String key);

    String decryptWithKeyLength(List<Integer> encryptedMessage, int keyLength);
}
