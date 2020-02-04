package org.wso2.samples.decrypt;

import org.apache.axiom.om.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Properties;
import java.util.Scanner;
import javax.crypto.Cipher;

public class DecryptImpl {

    private static Properties prop = new Properties();

    public static void main(String [] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        String plainText;

        Security.removeProvider("BC");
        Security.addProvider(new BouncyCastleProvider());

        /*
        args[0] = encrypted cipher text
        args[1] = keystore path
        args[2] = keystore alias
        args[3] = keystore password
         */
        if (args.length == 5) {

            loadProperties(args[4]);
            String transformation = prop.getProperty("org.wso2.CipherTransformation");
            System.out.println("Decrypting with Transformation :" + transformation);
            plainText = decrypt(Base64.decode(args[0]), args[1], args[2], args[3], transformation);

        } else if (args.length == 4) {

            System.out.println("Decrypting with Default Transformation (RSA)");
            plainText = decrypt(Base64.decode(args[0]), args[1], args[2], args[3]);

        } else {
            System.out.print("Encrypted Text : ");
            String encryptedText = scanner.next();

            System.out.print("KeyStore file path : ");
            String keystorePath = scanner.next();

            System.out.print("KeyStore alias : ");
            String alias = scanner.next();

            System.out.print("KeyStore password : ");
            String password = scanner.next();

            plainText = decrypt(Base64.decode(encryptedText), keystorePath, alias, password);
        }
        System.out.println("*** Plain Text ***\n" + plainText + "\n******************");
    }

    private static String decrypt(byte [] ciphertext, String keystore, String keystoreAlias, String keystorePassword,
                                  String transformation) throws Exception {
        KeyStore keyStore = getKeyStore(keystore, keystorePassword);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keystoreAlias, keystorePassword.toCharArray());
        Cipher cipher = Cipher.getInstance(transformation, "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] cipherbyte=cipher.doFinal(ciphertext);
        return new String(cipherbyte);
    }

    private static String decrypt(byte [] ciphertext, String keystore, String keystoreAlias, String keystorePassword)
            throws Exception {
        return decrypt(ciphertext, keystore, keystoreAlias, keystorePassword, "RSA");
    }

    /**
     *
     * @param keystore keystore path
     * @param keystorePassword keystore password
     * @return
     * @throws Exception
     */
    private static KeyStore getKeyStore(String keystore, String keystorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");

        FileInputStream in = null;
        try {
            in = new FileInputStream(keystore);
            keyStore.load(in, keystorePassword.toCharArray());
        } finally {
            if (in != null) {
                in.close();
            }
        }
        return keyStore;
    }



    private static void loadProperties(String propFilePath) {
        try {
            InputStream inputStream = new FileInputStream(propFilePath);
            prop.load(inputStream);
        } catch (IOException io) {
            io.printStackTrace();
        }
    }
}
