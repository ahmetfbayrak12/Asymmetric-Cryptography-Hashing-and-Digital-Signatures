
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class licensemanager
{

    public licensemanager()
    {
        System.out.println("LicenseManager service started...");
    }
    
	// This function takes encrypted plaintext from client and then decrypt it with its private key.
	// After decryption, server hash the decrypted plaintext with MD5 and sign this hashed text using SHA256withRSA.
	// And finally, this function creates license.txt and puts digital signature to in it and send it back to client.
    public void create_license(byte [] plaintext, String private_key_file) throws Exception
    {
        main main_obj_lm = new main();
    	
        System.out.println("Server -- Server is being requested...");
        String output15 = new String(plaintext, StandardCharsets.UTF_8);  // byte array to string
        System.out.println("Server -- Incoming Encrypted Text: " + output15);

        PrivateKey lm_private_key = private_key_reader(private_key_file);		// takes private key
        byte [] decrypted_plain_text = decrypt(lm_private_key, plaintext);		// decrypt the upcoming encrypted text
        String output1 = new String(decrypted_plain_text, StandardCharsets.UTF_8);  // byte array to string

        System.out.println("Server -- Decrypted Text: " + output1);

        // hash with MD5
        MessageDigest md = MessageDigest.getInstance("MD5");
        // md.reset();
        // md.update(decrypted_plain_text);
        byte[] thedigest = md.digest(decrypted_plain_text);

        System.out.println("Server -- MD5fied Plain License Text: " +bytesToHex(thedigest));

        /* print the hash
        BigInteger no = new BigInteger(1, thedigest);
        String hashtext = no.toString(16);
        while (hashtext.length() < 32) {
            hashtext = "0" + hashtext;
        }
        System.out.println("Hash with MD5: " + hashtext );
        */
        
        // Digital Signature via Sha256withRSA
        Signature rsaSha256Signature = Signature.getInstance("SHA256withRSA");
        rsaSha256Signature.initSign(lm_private_key);
        rsaSha256Signature.update(thedigest);
        byte[] signed2 = rsaSha256Signature.sign();
        String s123 = Base64.getEncoder().encodeToString(signed2);
        String output3 = new String(signed2);  // byte array to string
        System.out.println("Server -- Digital Signature: " + output3);
        
        FileOutputStream fout = new FileOutputStream("license.txt");
        fout.write(signed2);
        fout.close();
    }
    
    // reads private key from file and creates it
    private PrivateKey private_key_reader(String filename)
            throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
    
    // reads private key from file and creates it
    private PrivateKey getPrivateKey(String filename) throws Exception 
    {
        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf =
                KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
    
    // RSA decryption algorithm
    private byte[] decrypt(PrivateKey key, byte[] ciphertext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }

    // converts byte array to hexadecimal string
    public String bytesToHex(byte[] bytes) {
        final char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
