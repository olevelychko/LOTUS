import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

public class Lotus {

    private static MessageDigest md;

    static {
        try {
            md = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static String SHA_512(String input) {
        byte[] messageDigest = md.digest(input.getBytes());
        BigInteger no = new BigInteger(1, messageDigest);
        return no.toString(16);
    }

    public static ArrayList<byte[]> AESEncr(String Gsigma, String M) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        ArrayList<byte[]> params = new ArrayList<>();
        SecureRandom secureRandom = new SecureRandom();
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        //byte[] key = new byte[256 / 8]; // generate the key
        //secureRandom.nextBytes(key);
        byte[] keysigma = Gsigma.getBytes();
        System.out.println("This is key " + Arrays.toString(keysigma) + " " + keysigma.length);
        byte[] nonce = new byte[96 / 8];
        secureRandom.nextBytes(nonce);
        byte[] iv = new byte[128 / 8];
        System.arraycopy(nonce, 0, iv, 0, nonce.length);
        Key keySpec = new SecretKeySpec(keysigma, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] plaintext = M.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = cipher.doFinal(plaintext);
        params.add(0, keysigma);
        params.add(1, nonce);
        params.add(2, ciphertext);
        String ciphertextString = new String(ciphertext, StandardCharsets.UTF_8);
        System.err.println("Encrypted: " + Base64.getEncoder().encodeToString(ciphertext));
        System.out.println("this is cipherText " + ciphertextString);
        return params;
    }

    public static String AESDec(ArrayList<byte[]> params) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        byte[] key = params.get(0);
        byte[] nonce = params.get(1);
        byte[] ciphertext = params.get(2);
        byte[] iv = new byte[128 / 8];
        System.arraycopy(nonce, 0, iv, 0, nonce.length);
        Key keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] plaintext = cipher.doFinal(ciphertext);
        System.err.println("Decrypted: " + Base64.getEncoder().encodeToString(plaintext));
        String plaintextString = new String(plaintext, StandardCharsets.UTF_8);
        System.out.println("this is plaintText " + plaintextString);
        return plaintextString;
    }

    public static ArrayList<Double> RandMatrix(int q, int n) {
        ArrayList<Double> MatrixA = new ArrayList<>();
        Random rand = new Random();
        for (int i = 0; i < n * n; i++) {
            int randvalue = rand.nextInt(q);
            MatrixA.add((double) randvalue);
        }
        return MatrixA;
    }

    public static ArrayList<Double> RandGausMatrix(double s, int n, int l) {
        ArrayList<Double> Matrix = new ArrayList<>();
        Random random = new Random();
        for (int i = 0; i < l * n; i++) {
            double Value = random.nextGaussian();
            Value = Value * s;
            Matrix.add(Value);
        }
        return Matrix;
    }

    public static ArrayList<Double> MultiMatrix(ArrayList<Double> A, ArrayList<Double> B, int n, int l) {
        ArrayList<Double> MatrixC = new ArrayList<>();
        int ch = 0;
        double temp = 0.0;
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < l; j++) {
                while (ch != n) {
                    temp = temp + A.get(ch + n * i) * B.get(ch * l + j);
                    ch++;
                }
                MatrixC.add(temp);
                temp = 0;
                ch = 0;
            }
        }

        return MatrixC;
    }

    public static ArrayList<Double> SubstractMatrix(ArrayList<Double> A, ArrayList<Double> B, int l) {
        ArrayList<Double> MatrixC = new ArrayList<>();
        for (int i = 0; i < l * l; i++) {
            MatrixC.add(A.get(i) - B.get(i));
        }
        return MatrixC;
    }

    public static ArrayList<ArrayList<Double>> KeyGeneration(int q, int l, int n, double s) {
        ArrayList<ArrayList<Double>> keyData = new ArrayList<>();
        String x = "VelychkoMelnyk";
        String G = SHA_512(x + "01");
        String H = SHA_512(x + "10");
        System.out.println(x + "0x01");
        System.out.println("Hash G= " + G);
        System.out.println(x + "0x02");
        System.out.println("Hash H= " + H);
        ArrayList<Double> A = RandMatrix(q, n);
        //System.out.println(A);
        ArrayList<Double> R = RandGausMatrix(s, n, l);
        //System.out.println(R);
        ArrayList<Double> S = RandGausMatrix(s, n, l);
        ArrayList<Double> P = (SubstractMatrix(R, MultiMatrix(A, S, n, l), l));
        keyData.add(0, A);
        keyData.add(1, P);
        keyData.add(2, S);
        //System.out.println(P);
        return keyData;

    }

    public static void Encapsulation(String M, int l, int KeyLen) {
        StringBuilder sigma = new StringBuilder();
        StringBuilder K = new StringBuilder();
        Random rand = new Random();
        for (int i = 0; i < l; i++) {
            int randBit = rand.nextInt(2);
            sigma.append(randBit);
        }
        for (int i = 0; i < l; i++) {
            int randBit = rand.nextInt(2);
            K.append(randBit);
        }
        System.out.println("sigma=" + sigma);
        System.out.println();
        System.out.println("K=" + K);
        String Gsigma = SHA_512(sigma + "01");
        BigInteger temp = new BigInteger(Gsigma, 16);
        String newG = temp.toString(2);
        System.out.println("GsigmaNew = ");
        System.out.println(newG);
        StringBuilder csym = new StringBuilder();
        for (int i = 0; i < l; i++) {
            if (K.charAt(i) == newG.charAt(i)) csym.append(0);
            else csym.append(1);
        }
        System.out.println("csym");
        System.out.println(csym);
        String h = SHA_512(sigma + csym.toString() + "10");
    }

    public static void Encryption(String M, int n, int l, int KeyLen, ArrayList<Double> A, ArrayList<Double> S) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        StringBuilder sigma = new StringBuilder();
        Random rand = new Random();
        for (int i = 0; i < l; i++) {
            int randBit = rand.nextInt(2);
            sigma.append(randBit);
        }
        String Gsigma = SHA_512(sigma + "01");
        ArrayList<byte[]> params = AESEncr(Gsigma, M);
        byte[] csym = (params.get(2));
        String csymdec = new String(csym, StandardCharsets.UTF_8);
        String h = SHA_512(sigma+csymdec+"10");
        ArrayList<Double> e1 = RandGausMatrix(3.0, 1, n);
        ArrayList<Double> e2 = RandGausMatrix(3.0, 1, n);
        ArrayList<Double> e3 = RandGausMatrix(3.0, 1, l);
        ArrayList<Double> tempC1 = MultiMatrix(e1, A, n, 1);
        System.out.println(tempC1);

    }

    public static void main(String[] args) throws Exception {
        int n = 576, q = 8192, l = 128, KeyLen = 128;
        double s = 3.0;
        ArrayList<ArrayList<Double>> keyData = KeyGeneration(q, l, n, s);
        String M = "VelychkoMelnyk";
        Encryption(M, n, l, KeyLen, keyData.get(0), keyData.get(1));
    }
}
