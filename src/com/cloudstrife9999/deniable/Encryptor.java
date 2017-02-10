package com.cloudstrife9999.deniable;

import java.security.Key;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Encryptor {
    
    private Encryptor(){}
    
    public static byte[] encrypt(byte[] ptx, byte[] key, byte[] iv) {
	Key k = new SecretKeySpec(key, "AES");
	
	return encrypt(ptx, k, iv);
    }
    
    public static byte[] encrypt(String ptx, byte[] key, byte[] iv) {
	byte[] plaintext = ptx.getBytes();
	
	return encrypt(plaintext, key, iv);
    }
    
    public static byte[] encrypt(byte[] ptx, Key key, byte[] iv) {
	try {
	    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
	    IvParameterSpec ivParam = new IvParameterSpec(iv);
	    cipher.init(Cipher.ENCRYPT_MODE, key, ivParam);
	    
	    return cipher.doFinal(ptx);
	}
	catch(Exception e) {
	    throw new IllegalArgumentException(e);
	}
    }
    
    public static byte[] encrypt(String ptx, Key key, byte[] iv) {
	byte[] plaintext = ptx.getBytes();
	
	return encrypt(plaintext, key, iv);
    }
    
    public static String encryptAsBase64(byte[] ptx, byte[] key, byte[] iv) {
	byte[] ctx = encrypt(ptx, key, iv);
	
	if(ctx.length != 0) {
	    return Base64.getEncoder().encodeToString(ctx);
	}
	else {
	    return "";
	}
    }
    
    public static String encryptAsBase64(String ptx, byte[] key, byte[] iv) {
	byte[] ctx = encrypt(ptx, key, iv);
	
	if(ctx.length != 0) {
	    return Base64.getEncoder().encodeToString(ctx);
	}
	else {
	    return "";
	}
    }
    
    public static String encryptAsBase64(byte[] ptx, Key key, byte[] iv) {
	byte[] ctx = encrypt(ptx, key, iv);
	
	if(ctx.length != 0) {
	    return Base64.getEncoder().encodeToString(ctx);
	}
	else {
	    return "";
	}
    }
    
    public static String encryptAsBase64(String ptx, Key key, byte[] iv) {
	byte[] ctx = encrypt(ptx, key, iv);
	
	if(ctx.length != 0) {
	    return Base64.getEncoder().encodeToString(ctx);
	}
	else {
	    return "";
	}
    }
}