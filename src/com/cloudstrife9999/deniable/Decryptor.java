package com.cloudstrife9999.deniable;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Decryptor {
    
    private Decryptor() {}
    
    public static byte[] decrypt(byte[] ctx, byte[] key, byte[] iv) {
	Key k = new SecretKeySpec(key, "AES");
	
	return decrypt(ctx, k, iv);
    }
    
    public static byte[] decrypt(String ctx, byte[] key, byte[] iv) {
	byte[] ciphertext = ctx.getBytes();
	
	return decrypt(ciphertext, key, iv);
    }
    
    public static byte[] decrypt(byte[] ctx, Key key, byte[] iv) {
	if(ctx.length != 0) {
	    return decryptHelper(ctx, key, iv);
	}
	else {
	    return new byte[]{};
	}
    }
    
    private static byte[] decryptHelper(byte[] ctx, Key key, byte[] iv) {
	try {	    
	    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
	    IvParameterSpec ivParam = new IvParameterSpec(iv);
	    cipher.init(Cipher.DECRYPT_MODE, key, ivParam);
	    
	    return cipher.doFinal(ctx);
	}
	catch(Exception e) {
	    throw new IllegalArgumentException(e);
	}
    }

    public static byte[] decrypt(String ctx, Key key, byte[] iv) {
	byte[] ciphertext = ctx.getBytes();
	
	return decrypt(ciphertext, key, iv);
    }
    
    public static String decryptAsString(byte[] ctx, byte[] key, byte[] iv) {
	if(ctx.length != 0) {
	    byte[] plaintext = decrypt(ctx, key, iv);
		
	    return new String(plaintext);
	}
	else {
	    return "";
	}
    }
    
    public static String decryptAsString(String ctx, byte[] key, byte[] iv) {
	if(ctx.length() != 0) {
	    byte[] plaintext = decrypt(ctx, key, iv);
		
	    return new String(plaintext);
	}
	else {
	    return "";
	}
    }
    
    public static String decryptAsString(byte[] ctx, Key key, byte[] iv) {
	if(ctx.length != 0) {
	    byte[] plaintext = decrypt(ctx, key, iv);
		
	    return new String(plaintext);
	}
	else {
	    return "";
	}
    }
    
    public static String decryptAsString(String ctx, Key key, byte[] iv) {
	if(ctx.length() != 0) {
	    byte[] plaintext = decrypt(ctx, key, iv);
		
	    return new String(plaintext);
	}
	else {
	    return "";
	}
    }
}