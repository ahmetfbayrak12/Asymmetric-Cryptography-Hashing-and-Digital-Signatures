
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;


import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;

public class main
{
    public static PublicKey my_public_key= null;


    // To run this code, you have to give arguments: First argument is private key file and the second argument is public key file
    // Example of giving an argument is: private.key public.key
    
    public static void main(String[] args) throws Exception
    {
        main main_obj = new main();
    	
        String username = "Selman";
        String serial_number = "0H6U-23BJ-YR84";
        //String mac_address = "0C-54-15-5B-0A-FE";
        String mac_address = main_obj.get_mac_address();		// getting mac address of client
        String disk_serial_number = "-633475686";
        String motherboard_ID = "Standard";

        String plain_text = username + "$" + serial_number + "$" + mac_address + "$" +disk_serial_number + "$" +motherboard_ID;

        my_public_key = main_obj.public_key_reader(args[1]);		// create and read public key

        // check if license is already exist
        File tempFile = new File("license.txt");
        boolean license_exists = tempFile.exists();

        if(license_exists)  // if there is a license text already, verify it
        {
            boolean isVerified = false;
            isVerified = main_obj.verify_digital_signature(plain_text.getBytes("UTF-8"), 0);
            if(!isVerified)		// if license is not verified, create new verified one
            {
                main_obj.prepare_for_creating_license(username, serial_number, mac_address, disk_serial_number, motherboard_ID, args[0]);
            }
        }
        else    // create license
        {
            main_obj.prepare_for_creating_license(username, serial_number, mac_address, disk_serial_number, motherboard_ID, args[0]);
        }
    }

    // RSA encryption function
    private byte[] encrypt(PublicKey key, byte[] plaintext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    // reads public key from file and creates it
    private PublicKey public_key_reader(String filename)
            throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    // verify the current license.txt. If the license is verified, returns true otherwise returns false.
    // If the license.txt is just created then send second parameter 1. If the license.txt was already exist then send second parameter 0.
    private boolean verify_digital_signature(byte [] plaintext, int old_or_new) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException 
    {
        main main_obj_verify = new main();
        boolean isVerified = false;

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(my_public_key);		// verification with public key
        MessageDigest md = MessageDigest.getInstance("MD5");		// hashing with MD5
        byte[] thedigest = md.digest(plaintext);

        signature.update(thedigest);

        byte[] verified_signature = Files.readAllBytes(Paths.get("license.txt"));		// get digital signature from license.txt

        try
        {
            isVerified = signature.verify(verified_signature);
            if(isVerified)
            {
                if(old_or_new == 0)		// current license is correct
                {
                    System.out.println("Succeed. The license is correct.");
                }
                else		// the license which is just created is correct
                {
                    System.out.println("Client -- Succeed. The License file content is secured and signed by the server");
                }
            }
            else		// license is not verified
            {
                System.out.println("The license file has been broken!!");
            }
        }
        catch (Exception SignatureException)
        {
            System.out.println("The license file has been broken!!");
        }
        return isVerified;
    }

    // this function is the starting function of creating license for client side
    private void prepare_for_creating_license(String username, String serial_number, String mac_address, String disk_serial_number, String motherboard_ID, String private_key_file) throws Exception 
    {
        main main_obj_fn = new main();

        System.out.println("Client started...");

        System.out.println("My MAC: " + mac_address);
        System.out.println("My DiskID: " + disk_serial_number);
        System.out.println("My Motherboard ID: " + motherboard_ID);

        String plain_text = username + "$" + serial_number + "$" + mac_address + "$" +disk_serial_number + "$" +motherboard_ID;

        licensemanager license_manager_obj_fn = new licensemanager();

        byte[] encrypted_plain_text = main_obj_fn.encrypt(my_public_key , plain_text.getBytes("UTF-8"));         // encrypt the plaintext with RSA
        String output1 = new String(encrypted_plain_text, StandardCharsets.UTF_8);  // byte array to string
        System.out.println("Client -- Raw Licence Text: " + plain_text);
        System.out.println("Client -- Encrypted License Text: " + output1);

        MessageDigest md = MessageDigest.getInstance("MD5");        // hash with MD5
        byte[] thedigest = md.digest(plain_text.getBytes("UTF-8"));

        System.out.println("Client -- MD5fied Plain License Text: " + license_manager_obj_fn.bytesToHex(thedigest));

        license_manager_obj_fn.create_license(encrypted_plain_text, private_key_file);
        boolean isVerified = main_obj_fn.verify_digital_signature(plain_text.getBytes("UTF-8"), 1);
        if(!isVerified)		// if the license.txt is not verified then create a verified one
        {
            main_obj_fn.prepare_for_creating_license(username, serial_number, mac_address, disk_serial_number, motherboard_ID, private_key_file);
        }
    }

    // returns mac address of current hardware
    private String get_mac_address()
    {
    	InetAddress ip;
		StringBuilder sb = new StringBuilder();

    	try {
    			
    		ip = InetAddress.getLocalHost();
    		
    		NetworkInterface network = NetworkInterface.getByInetAddress(ip);
    			
    		byte[] mac = network.getHardwareAddress();
    			
    			
    		for (int i = 0; i < mac.length; i++) {
    			sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));		
    		}
    			
    	} catch (UnknownHostException e) {
    		
    		e.printStackTrace();
    		
    	} catch (SocketException e){
    			
    		e.printStackTrace();
    			
    	}
    	return sb.toString();
    }
}
