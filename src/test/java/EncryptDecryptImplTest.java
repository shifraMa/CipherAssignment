package test.java;

import main.java.EncryptDecryptImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class EncryptDecryptImplTest {

    EncryptDecryptImpl tested;
    private final String MESSAGE = "and also, whenever applying the standard statistical techniques to break such a cipher there is an assumption that the character distribution of the underlying plaintext is very close to the character distribution of the relevant language in general. This is correct only approximately, and becomes less accurate the shorter the plaintext (/ciphertext) is. This is why even if you implement the cracking algorithm 100% correctly, it may still give you a wrong key as the most likely key. –Amit";
    private final String KEY = "123";
    private final List<Integer> ENCRYPTED_MESSAGE = List.of(128,140,133,66,128,142,114,141,77,66,118,138,132,140,132,116,132,112,65,131,113,114,141,123,136,140,134,66,117,138,132,66,114,118,128,140,133,131,115,134,65,113,117,131,117,139,114,118,136,129,128,142,65,118,132,129,137,140,136,115,116,135,114,66,117,141,65,128,115,135,128,137,65,113,116,129,137,66,128,66,130,139,113,138,132,112,65,118,137,135,115,135,65,139,114,66,128,140,65,131,114,113,116,143,113,118,136,141,143,66,117,138,128,118,65,118,137,135,65,129,137,131,115,131,130,118,132,112,65,134,136,113,117,112,136,128,116,118,136,141,143,66,142,132,65,118,137,135,65,119,143,134,132,112,141,123,136,140,134,66,113,142,128,139,143,118,132,122,117,66,136,113,65,116,132,112,120,66,130,142,142,113,132,66,117,141,65,118,137,135,65,129,137,131,115,131,130,118,132,112,65,134,136,113,117,112,136,128,116,118,136,141,143,66,142,132,65,118,137,135,65,112,132,142,132,116,128,140,117,66,141,131,143,133,116,131,134,135,65,139,143,66,134,135,143,135,115,131,141,76,65,150,137,139,114,66,136,113,65,129,142,112,115,135,130,118,65,141,143,142,120,66,128,114,113,112,142,122,136,143,128,118,132,142,120,78,65,131,143,134,65,128,132,129,142,143,132,113,65,142,132,113,114,66,128,129,130,119,115,131,117,135,65,118,137,135,65,113,137,141,115,118,132,112,65,118,137,135,65,114,141,131,136,140,117,135,121,118,65,74,78,129,136,114,137,135,115,118,132,122,117,75,65,139,114,76,65,150,137,139,114,66,136,113,65,117,137,123,65,135,119,135,143,66,136,132,65,123,142,119,65,139,140,114,141,135,140,135,143,118,65,118,137,135,65,129,115,131,130,137,136,140,134,66,128,142,134,141,115,139,117,138,140,66,48,50,49,71,65,129,142,112,115,135,130,118,141,123,77,66,136,118,65,143,128,123,65,113,117,139,141,142,65,133,136,116,132,66,120,141,116,66,128,66,118,112,142,140,134,66,138,135,120,66,128,113,65,118,137,135,65,143,142,113,117,66,141,139,138,135,141,123,65,137,132,123,79,66,8274,163,140,139,117);

    @BeforeEach
    void setUp() {
        tested = new EncryptDecryptImpl();
    }

    @Test
    public void whenSendingMessageWithKeyThenMessageEncrypted(){
        assertEquals(tested.encrypt(MESSAGE, KEY), ENCRYPTED_MESSAGE);
    }
    @Test
    public void whenSendingEmptyMessageWithKeyThenDoesNotFail(){
        assertEquals(tested.encrypt("", KEY), List.of());
    }
    @Test
    public void whenSendingMessageShorterThenKeyWithKeyThenDoesNotFail(){
        assertEquals(tested.encrypt("A", KEY), List.of(160));
    }

    @Test
    public void whenSendingMessageCheckWithWrongKeyThenShouldFail(){
        String key = "abc";
        assertNotEquals(tested.encrypt(MESSAGE, key), ENCRYPTED_MESSAGE);
    }

    @Test
    public void whenSendingEncryptedMessageWithKeyThenDecryptAsSupposed(){
        var decryptedMessage = tested.decrypt(ENCRYPTED_MESSAGE, KEY);
        assertEquals(decryptedMessage, MESSAGE);
    }

    @Test
    public void whenSendingEmptyEncryptedMessageWithKeyThenShouldNotFail(){
        var decryptedMessage = tested.decrypt(List.of(), KEY);
        assertEquals(decryptedMessage, "");
    }

    @Test
    public void whenSendingEncryptedMessageShorterThenKeyWithKeyThenShouldNotFail(){
        var decryptedMessage = tested.decrypt(List.of(160), KEY);
        assertEquals(decryptedMessage, "A");
    }

    @Test
    public void whenSendingEncryptedMessageWithOtherKeyThenDecryptDifferent(){
        var key = "abc";
        var decryptedMessage = tested.decrypt(ENCRYPTED_MESSAGE, key);
        assertNotEquals(decryptedMessage, MESSAGE);
    }

    @Test
    public void whenSendingEncryptedMessageWithKeyLengthThenDecryptMessage(){
        var decryptedMessage = tested.decryptWithKeyLength(ENCRYPTED_MESSAGE, KEY.length());
        assertEquals(decryptedMessage, MESSAGE);
    }

    @Test
    public void whenSendingEncryptedMessageWithIncorrectKeyLengthThenDecryptMessageIncorrect(){
        var decryptedMessage = tested.decryptWithKeyLength(ENCRYPTED_MESSAGE, KEY.length()+1);
        assertNotEquals(decryptedMessage, MESSAGE);
    }

    @Test
    public void whenSendingShortEncryptedMessageKeyLengthThenDecryptMessage(){
        var shortEncryptedMessage = List.of(101,58,56,65,113,59,66,114,48,114,70,61,63,54,52,64,113,52,68,62,61,114,65,62,52,51,66,55,113,63,48,57,52,114,56,70,113,65,48,52,52);
        var shortDecryptedMessage = "This is a wonder full please make it safe";
        var decryptedMessage = tested.decryptWithKeyLength(shortEncryptedMessage, KEY.length());
        assertEquals(decryptedMessage, shortDecryptedMessage);
    }

    @Test
    public void whenSendingEmptyEncryptedMessageKeyLengthThenDecryptMessage(){
        var decryptedMessage = tested.decryptWithKeyLength(List.of(), KEY.length());
        assertEquals(decryptedMessage, "");
    }
}