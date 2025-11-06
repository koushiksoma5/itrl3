
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Base64;
// import java.util.Random;

class Rijandel {

    static int keysize = 128;
    static int iv_len = 12;
    static int tag_len = 16;

    static SecretKey generateKey(int keysize) throws Exception {
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(keysize);
        return keygen.generateKey();
    }

    static byte[] civ() {
        byte[] iv = new byte[iv_len];
        SecureRandom sec = new SecureRandom();
        sec.nextBytes(iv);
        return iv;
    }

    static String encrypt(String pt, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(tag_len * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] encrypted = cipher.doFinal(pt.getBytes());

        byte[] both = new byte[encrypted.length + iv.length];

        System.arraycopy(iv, 0, both, 0, iv.length);
        System.arraycopy(encrypted, 0, both, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(both);
    }

    // static String decrypt(String pt, SecretKey key, byte[] iv) throws Exception {
    //     Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    //     GCMParameterSpec spec = new GCMParameterSpec(tag_len * 8, iv);
    //     cipher.init(Cipher.ENCRYPT_MODE, key, spec);

    //     byte[] encrypted = cipher.doFinal(pt.getBytes());

    //     byte[] both = new byte[encrypted.length + iv.length];

    //     System.arraycopy(iv, 0, both, 0, iv.length);
    //     System.arraycopy(encrypted, 0, both, iv.length, encrypted.length);

    //     return Base64.getEncoder().encodeToString(both);
    // }

    static String decrypt(String ct, SecretKey key) throws Exception {

        byte[] decccc = Base64.getDecoder().decode(ct);

        byte iv[] = new byte[iv_len];

        System.arraycopy(decccc, 0, iv, 0, iv_len);
        byte[] cit = new byte[decccc.length - iv_len];

        System.arraycopy(decccc, iv_len, cit, 0, cit.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        GCMParameterSpec spec = new GCMParameterSpec(tag_len * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decrypted = cipher.doFinal(cit);
        return new String(decrypted);
    }

    public static void main(String[] args) {
        try {
            String data = "This is the data";
            SecretKey key = generateKey(keysize);
            byte[] iv = civ();
            System.out.println("data" + data);

            String ect = encrypt(data, key, iv);
            String dct = decrypt(ect, key);
            System.err.println("Encrypted" + ect);
            System.err.println("decrypted" + dct);
        } catch (Exception e) {

        }
    }

}
