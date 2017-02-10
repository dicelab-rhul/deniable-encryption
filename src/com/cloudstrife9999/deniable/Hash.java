package com.cloudstrife9999.deniable;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class Hash {
    
    private Hash() {}
    
    public static byte[] getDigest(byte[] ptx) {
	try {
	    byte[] tmp = ptx;
	    
	    for(int i = 0; i < 3000; i++) {
		tmp = digest(tmp);
	    }
	    
	    return tmp;
	}
	catch(NoSuchAlgorithmException | NoSuchProviderException e) {
	    throw new IllegalArgumentException(e);
	}
    }

    private static byte[] digest(byte[] ptx) throws NoSuchAlgorithmException, NoSuchProviderException {
	MessageDigest digest = MessageDigest.getInstance("SHA3-512", "BC");
	digest.update(ptx);
	
	return digest.digest();
    }
}