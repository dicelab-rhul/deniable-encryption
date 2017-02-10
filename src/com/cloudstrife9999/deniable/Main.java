package com.cloudstrife9999.deniable;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

public class Main {

    private Main(){}
    
    public static void main(String[] args) {
	try {
	    Security.addProvider(new BouncyCastleProvider());
	    Mode mode = checkArgs(args);
	    start(mode, args);
	}
	catch(Exception e) {
	    printError();
	    
	    throw new IllegalArgumentException(e);
	}
    }
    
    private static void start(Mode mode, String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
	switch(mode) {
	case BAD_ARGUMENTS:
	    printError();
	    break;
	case ENCRYPT:
	    String ctx = encrypt(args[3], args[5]);
	    storeCtx(ctx, args[7]);
	    break;
	case DECRYPT:
	    String ptx = decrypt(args[3], args[5]);
	    System.out.println("Decrypted: password = '" + args[5] + "', plaintext = '" + ptx + "'.");
	    break;
	case MERGE:
	    merge(args[3], args[5], args[7]);
	    break;
	default:
	    printError("Unknown command");
	    break;
	}
    }

    private static void merge(String realPath, String fakePath, String outputPath) {
	try(FileInputStream realInput = new FileInputStream(realPath); FileInputStream fakeInput = new FileInputStream(fakePath); FileOutputStream output = new FileOutputStream(outputPath);) {
	    int realInputLength = realInput.available();
	    byte[] realInputBytes = new byte[realInputLength];
	    
	    if(realInput.read(realInputBytes) != realInputLength) {
		throw new IllegalArgumentException("Bad number of bytes from real file");
	    }
	    
	    byte[] real = Base64.decode(realInputBytes);
	    
	    int fakeInputLength = fakeInput.available();
	    byte[] fakeInputBytes = new byte[fakeInputLength];
	    
	    if(fakeInput.read(fakeInputBytes) != fakeInputLength) {
		throw new IllegalArgumentException("Bad number of bytes from fake file");
	    }
	    
	    byte[] fake = Base64.decode(fakeInputBytes);
	    
	    byte[] length = new byte[4];
	    ((ByteBuffer) ByteBuffer.allocate(length.length).putInt(real.length).flip()).get(length);
	    
	    byte[] merged = new byte[length.length + real.length + fake.length];
	    System.arraycopy(length, 0, merged, 0, length.length);
	    System.arraycopy(real, 0, merged, length.length, real.length);
	    System.arraycopy(fake, 0, merged, length.length + real.length, fake.length);
	    
	    String toStore = Base64.toBase64String(merged);
	    
	    output.write(toStore.getBytes());
	    output.flush();
	}
	catch(Exception e) {
	    throw new IllegalArgumentException(e);
	}
    }

    private static String decrypt(String inputPath, String password) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException{
	try(FileInputStream input = new FileInputStream(inputPath)) {
	    byte[] longKey = generateLongKey(password);
	    
	    if(longKey.length != 48) {
		throw new IllegalArgumentException();
	    }
	    
	    int length = input.available();
	    byte[] temp = new byte[length];
	    
	    if(input.read(temp) != length) {
		throw new IllegalArgumentException("Bad number of bytes from file.");
	    }
	    
	    String base64Ctx = new String(temp);
	    byte[] ctx = Base64.decode(base64Ctx);
	    
	    return decrypt(ctx, longKey);
	}
	catch(Exception e) {
	    throw new IllegalArgumentException(e);
	}
    }

    private static String decrypt(byte[] ctx, byte[] longKey) {
	byte[] key = new byte[(longKey.length/3) * 2];
	byte[] iv = new byte[longKey.length/3];
	
	System.arraycopy(longKey, 0, key, 0, key.length);
	System.arraycopy(longKey, key.length, iv, 0, iv.length);
	
	byte[] selectedCtx = fetchCtx(ctx, key);
	
	return Decryptor.decryptAsString(selectedCtx, key, iv);
    }

    private static byte[] fetchCtx(byte[] ctx, byte[] key) {
	byte[] lengthBytes = new byte[4];
	System.arraycopy(ctx, 0, lengthBytes, 0, lengthBytes.length);
	
	int length = ((ByteBuffer) ByteBuffer.allocate(4).put(lengthBytes).flip()).getInt();
	byte[] firstHalf = new byte[length];
	byte[] secondHalf = new byte[ctx.length - length - 4];
	
	System.arraycopy(ctx, 4, firstHalf, 0, length);
	System.arraycopy(ctx, length + 4, secondHalf, 0, secondHalf.length);
	
	byte[] firstKeyHash = new byte[64];
	byte[] secondKeyHash = new byte[64];
	
	System.arraycopy(firstHalf, 0, firstKeyHash, 0, firstKeyHash.length);
	System.arraycopy(secondHalf, 0, secondKeyHash, 0, secondKeyHash.length);
	
	byte[] keyHash = Hash.getDigest(key);
	byte[] toDecrypt;
	
	if(Arrays.equals(firstKeyHash, keyHash)) {
	    toDecrypt = new byte[firstHalf.length - firstKeyHash.length];
	    System.arraycopy(firstHalf, firstKeyHash.length, toDecrypt, 0, toDecrypt.length);
	}
	else if(Arrays.equals(secondKeyHash, keyHash)) {
	    toDecrypt = new byte[secondHalf.length - secondKeyHash.length];
	    System.arraycopy(secondHalf, secondKeyHash.length, toDecrypt, 0, toDecrypt.length);
	}
	else {
	    throw new IllegalArgumentException();
	}
	
	return toDecrypt;
    }

    private static String encrypt(String ptx, String password) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
	byte[] longKey = generateLongKey(password);
	byte[] key = new byte[32];
	byte[] iv = new byte[16];
	
	if(longKey.length != 48) {
	    throw new IllegalArgumentException();
	}
	
	System.arraycopy(longKey, 0, key, 0, key.length);
	System.arraycopy(longKey, key.length, iv, 0, iv.length);
	
	byte[] baseCtx = Encryptor.encrypt(ptx, key, iv);
	byte[] keyHash = Hash.getDigest(key);
	
	byte[] toStore = new byte[baseCtx.length + keyHash.length];
	System.arraycopy(keyHash, 0, toStore, 0, keyHash.length);
	System.arraycopy(baseCtx, 0, toStore, keyHash.length, baseCtx.length);
	
	return Base64.toBase64String(toStore);
    }

    private static byte[] generateLongKey(String password) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
	SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "BC");
	int iterations = 1000;
        char[] chars = password.toCharArray();
        byte[] salt = Hash.getDigest(password.getBytes());
        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 32 * 8 + 16 * 8);
        
        return factory.generateSecret(spec).getEncoded();
    }

    private static void storeCtx(String ctx, String path) {
	try(FileOutputStream output = new FileOutputStream(path)) {
	    output.write(ctx.getBytes());
	    output.flush();
	}
	catch(Exception e) {
	    throw new IllegalArgumentException(e);
	}
    }

    private static void printError() {
	System.out.println("Usage #1: java -jar deniable.jar --mode encrypt --ptx <ptx> --pwd <pwd> --output <ctx-output-file-path>");
	System.out.println("Usage #2: java -jar deniable.jar --mode merge --real-path <real-ctx-file-path> --fake-path <fake-ctx-file-path> --output <merged-ctx-output-file-path>");
	System.out.println("Usage #3: java -jar deniable.jar --mode decrypt --input-file <merged-ctx-output-file-path> --pwd <pwd>");
    }
    
    private static void printError(String message) {
	System.out.println(message);
	printError();
    }

    private static Mode checkArgs(String[] args) {
	if(args.length < 2) {	    
	    return Mode.BAD_ARGUMENTS;
	}
	
	if(!"--mode".equals(args[0])) {
	    return Mode.BAD_ARGUMENTS;
	}
	
	return checkArgsHelper(args);
    }

    private static Mode checkArgsHelper(String[] args) {
	if("encrypt".equals(args[1])) {
	    return checkEncryptArguments(args);
	}
	else if("decrypt".equals(args[1])) {
	    return checkDecryptArguments(args);
	}
	else if("merge".equals(args[1])) {
	    return checkMergeArguments(args);
	}
	else {
	    return Mode.BAD_ARGUMENTS;
	}
    }

    private static Mode checkMergeArguments(String[] args) {
	if(args.length < 8) {
	    return Mode.BAD_ARGUMENTS;
	}
	
	try {
	    checkStringContent(args[2], "--real-path");
	    checkStringMinimumLength(args[3], 1);
	    checkStringContent(args[4], "--fake-path");
	    checkStringMinimumLength(args[5], 1);
	    checkStringContent(args[6], "--output");
	    checkStringMinimumLength(args[7], 1);
	    
	    return Mode.MERGE;
	}
	catch(Exception e) {
	    throw new IllegalArgumentException(e);
	}
    }

    private static Mode checkDecryptArguments(String[] args) {
	if(args.length < 6) {
	    return Mode.BAD_ARGUMENTS;
	}
	
	try {
	    checkStringContent(args[2], "--input-file");
	    checkStringMinimumLength(args[3], 1);
	    checkStringContent(args[4], "--pwd");
	    checkStringMinimumLength(args[5], 1);
	    
	    return Mode.DECRYPT;
	}
	catch(Exception e) {
	    throw new IllegalArgumentException(e);
	}
    }

    private static Mode checkEncryptArguments(String[] args) {
	if(args.length < 8) {
	    return Mode.BAD_ARGUMENTS;
	}
	
	try {
	    checkStringContent(args[2], "--ptx");
	    checkStringMinimumLength(args[3], 1);
	    checkStringContent(args[4], "--pwd");
	    checkStringMinimumLength(args[5], 1);
	    checkStringContent(args[6], "--output");
	    checkStringMinimumLength(args[7], 1);
	    
	    return Mode.ENCRYPT;
	}
	catch(Exception e) {
	    throw new IllegalArgumentException(e);
	}
    }
    
    private static void checkStringContent(String candidate, String prototype) {
	if(candidate == null || prototype == null) {
	    throw new IllegalArgumentException();
	}
	
	if(!prototype.equals(candidate)) {
	    throw new IllegalArgumentException();
	}
    }
    
    private static void checkStringMinimumLength(String candidate, int minimumLength) {
	if(candidate == null) {
	    throw new IllegalArgumentException();
	}
	
	if(candidate.length() < minimumLength) {
	    throw new IllegalArgumentException();
	}
    }
}