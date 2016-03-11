package VAtool;

import java.security.Key;
import java.security.MessageDigest; 
import java.util.Arrays; 
import javax.crypto.KeyGenerator; 
import javax.crypto.SecretKey; 
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import javax.crypto.spec.IvParameterSpec; 

 
import javax.crypto.Cipher; 
import javax.crypto.spec.IvParameterSpec; 
import javax.crypto.spec.SecretKeySpec; 
 
 
public class AES { 
	private static final String ALGO = "AES";
	static String IV = "AAAAAAAAAAAAAAAA"; 
	static String plaintext = "test text 123\0\0\0"; /*Note null padding*/ 
	static String encryptionKey = "0123456789abcdef"; 
 
	public static String encrypt(String Data) throws Exception {
		Key key = generateKey();
		Cipher c = Cipher.getInstance(ALGO);
		c.init(Cipher.ENCRYPT_MODE, key);
		byte[] encVal = c.doFinal(Data.getBytes());
		String encryptedValue = DatatypeConverter.printBase64Binary(encVal);
		return encryptedValue;
   }

	private static Key generateKey() throws Exception{
		byte[] keyValue = encryptionKey.getBytes("UTF-8");
		MessageDigest sha = MessageDigest.getInstance("SHA-1");
		keyValue = sha.digest(keyValue);
		keyValue = Arrays.copyOf(keyValue, 16); // use only first 128 bit       
		Key key = new SecretKeySpec(keyValue, ALGO);
		return key;

	}
 
	public static String decrypt(String encryptedData) throws Exception {
	    Key key = generateKey();
	    Cipher c = Cipher.getInstance(ALGO);
	    c.init(Cipher.DECRYPT_MODE, key);      
	    byte[] decordedValue = DatatypeConverter.parseBase64Binary(encryptedData);
	    byte[] decValue = c.doFinal(decordedValue);
	    String decryptedValue = new String(decValue);
	    return decryptedValue;
    }
 } 
