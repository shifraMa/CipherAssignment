package main.java;

import java.util.ArrayList;
import java.util.List;

public class EncryptDecryptImpl implements EncryptDecrypt {

    @Override
    public List<Integer> encrypt(String message, String key) {

        List<Integer> encrypted = new ArrayList<>(message.length());
        for (int i = 0; i < message.length(); i++) {
            int o = ((int) message.charAt(i) ^ (int) key.charAt(i % (key.length() - 1))) + '0';
            encrypted.add(o);
        }
        return encrypted;
    }

    @Override
    public String decrypt(List<Integer> encryptedMessage, String key) {
        StringBuilder decrypted = new StringBuilder();
        for (int i = 0; i < encryptedMessage.size(); i++) {
            decrypted.append((char) ((encryptedMessage.get(i) - 48) ^ (int) key.charAt(i % (key.length() - 1))));
        }
        return decrypted.toString();
    }

    @Override
    public String decryptWithKeyLength(List<Integer> encryptedMessage, int keyLength) {
        StringBuilder key = new StringBuilder();
        List<List<Integer>> keyBlocks = splitToKeyBlocks(encryptedMessage, keyLength);
        for (List<Integer> keyBlock : keyBlocks) {
            key.append(xorDecodeBytes(keyBlock));
        }
        return decrypt(encryptedMessage, key.toString());
    }

    private String xorDecodeBytes(List<Integer> partialInputBlock) {
        int score, greatestScore = 0, key = 0;
        for (int n = 0; n < 256; n++) {
            String decryptedBlock = decryptSingleKey(partialInputBlock.stream().mapToInt(i -> i).toArray(), (char) n);
            score = assignScore(decryptedBlock);
            if (score > greatestScore) {
                greatestScore = score;
                key = n;
            }
        }
        return Character.toString((char) key);
    }

    private String decryptSingleKey(int[] input, char key) {
        StringBuilder decrypted = new StringBuilder();
        for (int j : input) {
            decrypted.append((char) ((j - 48) ^ (int) key));
        }
        return decrypted.toString();
    }


    private List<List<Integer>> splitToKeyBlocks(List<Integer> encryptedInput, int keySize) {
        List<List<Integer>> keyBlocks = new ArrayList<>();
        int ind = 0, block;

        for (int i = 0; i < keySize; i++) {
            keyBlocks.add(new ArrayList<>());
        }

        while (ind != encryptedInput.size()) {
            block = ind % keySize;
            keyBlocks.get(block).add(encryptedInput.get(ind));
            ind++;
        }

        return keyBlocks;
    }

    private int assignScore(String keyBlock) {
        List<Character> freq = List.of(' ', 'e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l', 'u');
        int score = 0;
        for (int i = 0; i < keyBlock.length(); i++) {
            if (freq.contains(Character.toLowerCase(keyBlock.charAt(i)))) {
                score += 1;
            }
        }
        return score;
    }
}
