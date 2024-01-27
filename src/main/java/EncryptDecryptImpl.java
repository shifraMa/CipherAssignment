package main.java;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class EncryptDecryptImpl implements EncryptDecrypt {

    @Override
    public List<Integer> encrypt(String message, String key) {
        return IntStream.range(0, message.length())
                .map(i -> xor(message.charAt(i), key.charAt(i % (key.length() - 1))) + '0')
                .boxed()
                .toList();
    }

    @Override
    public String decrypt(List<Integer> encryptedMessage, String key) {
        return IntStream.range(0, encryptedMessage.size())
                .map(i -> (char) (xor((encryptedMessage.get(i) - 48), key.charAt(i % (key.length() - 1)))))
                .mapToObj(ch -> Character.toString((char) ch))
                .collect(Collectors.joining(""));
    }

    private static int xor(int messageByte, int keyByte) {
        return messageByte ^ keyByte;
    }

    @Override
    public String decryptWithKeyLength(List<Integer> encryptedMessage, int keyLength) {
        StringBuilder key = new StringBuilder();
        List<List<Integer>> keyBlocks = splitToKeyBlocks(encryptedMessage, keyLength);
        key.append(keyBlocks
                .stream()
                .map(this::xorDecodeBytes)
                .collect(Collectors.joining("")
                ));
        return decrypt(encryptedMessage, key.toString());
    }

    private String xorDecodeBytes(List<Integer> partialInputBlock) {
        int score, greatestScore = 0, key = 0;
        for (int n = 0; n < 256; n++) {
            String decryptedBlock = decryptSingleKey(partialInputBlock, (char) n);
            score = assignScore(decryptedBlock);
            if (score > greatestScore) {
                greatestScore = score;
                key = n;
            }
        }
        return Character.toString((char) key);
    }

    private String decryptSingleKey(List<Integer> input, char key) {
        return input.stream()
                .map(in -> (char) ((in - 48) ^ (int) key))
                .map(String::valueOf)
                .collect(Collectors.joining());
    }


    private List<List<Integer>> splitToKeyBlocks(List<Integer> encryptedInput, int keySize) {
        List<List<Integer>> keyBlocks = new ArrayList<>();
        AtomicInteger block = new AtomicInteger();

        IntStream.range(0, keySize)
                .forEach(i -> keyBlocks.add(new ArrayList<>()));
        IntStream.range(0, encryptedInput.size())
                .forEach(i -> {
                    block.set(i % keySize);
                    keyBlocks.get(block.get()).add(encryptedInput.get(i));
                });
        return keyBlocks;
    }

    private int assignScore(String keyBlock) {
        List<Character> freq = List.of(' ', 'e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l', 'u');
        AtomicInteger score = new AtomicInteger();
        keyBlock.chars()
                .forEach(c -> {
                    if (freq.contains(Character.toLowerCase((char) c))) {
                        score.addAndGet(1);
                    }
                });
        return score.get();
    }
}
