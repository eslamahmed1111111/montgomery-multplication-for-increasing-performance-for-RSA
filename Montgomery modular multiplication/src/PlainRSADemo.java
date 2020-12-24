import java.math.BigInteger;
import java.util.Random;

/**
 * Disclaimer:
 * This code is for illustration purposes and shall never be used in any implementation in practice.
 */

public class PlainRSADemo {

    private static BigInteger encrypt(BigInteger m, BigInteger e, BigInteger modulus) {
        return modExp(m, e, modulus);
    }

    private static BigInteger decrypt(BigInteger c, BigInteger d, BigInteger modulus) {
        return modExp(c, d, modulus);
    }
    private static BigInteger encrypt2(BigInteger m, BigInteger e, BigInteger modulus,BigInteger R,BigInteger NN,int exp_length,BigInteger bb) {
        return modExpmontgomery(m, e, modulus, R, NN,exp_length,bb);
    }

    private static BigInteger decrypt2(BigInteger c, BigInteger d, BigInteger modulus,BigInteger R,BigInteger NN,int exp_length,BigInteger bb) {
        return modExpmontgomery(c, d, modulus, R, NN,exp_length, bb);
    }

    private  static BigInteger createR(BigInteger modulus){
        int expBitlength = modulus.bitLength();
        BigInteger R=new BigInteger("2",16);
        R=R.pow(expBitlength);
        return R;
    }

    private  static BigInteger mont(BigInteger aa, BigInteger bb, BigInteger N,BigInteger R, BigInteger NN,int R_length){
        BigInteger t=aa.multiply(bb);
        BigInteger m=t.multiply(NN).and(R);
        t=t.add(m.multiply(N)).shiftRight(R_length);
        if(t.compareTo(N)<0)
            return t;
        else
            return t.subtract(N);
    }

    private static BigInteger modExpmontgomery(BigInteger aa, BigInteger exponent, BigInteger N,BigInteger R,BigInteger NN,int expBitlength,BigInteger bb) {
        R=R.subtract(BigInteger.valueOf(1));
        int R_length=R.bitLength();
        for (int i = expBitlength - 2; i >= 0; i--) {
             aa=mont(aa,aa,N,R,NN,R_length);
            if (exponent.testBit(i)) {
                aa=mont(aa,bb,N,R,NN,R_length);
            }
        }
        return aa;
    }


    private static BigInteger modExp(BigInteger a, BigInteger exponent, BigInteger N) {
        // Note: This code assumes the most significant bit of the exponent is 1, i.e., the exponent is not zero.
        BigInteger result = a;
        int expBitlength = exponent.bitLength();
        for (int i = expBitlength - 2; i >= 0; i--) {
            result = result.multiply(result).mod(N);
            if (exponent.testBit(i)) {
                result = result.multiply(a).mod(N);
            }
        }
        return result;
    }

    public static void main(String[] args) {

        // RSA modulus
        BigInteger modulus = new BigInteger(
                "a12360b5a6d58b1a7468ce7a7158f7a2562611bd163ae754996bc6a2421aa17d3cf6d4d46a06a9d437525571a2bfe9395d440d7b09e9912a2a1f2e6cb072da2d0534cd626acf8451c0f0f1dca1ac0c18017536ea314cf3d2fa5e27a13000c4542e4cf86b407b2255f9819a763797c221c8ed7e7050bc1c9e57c35d5bb0bddcdb98f4a1b58f6d8b8d6edb292fd0f7fa82dc5fdcd78b04ca09e7bc3f4164d901b119c4f427d054e7848fdf7110352c4e612d02489da801ec9ab978d98831fa7f872fa750b092967ff6bdd223199af209383bbce36799a5ed5856f587f7d420e8d76a58b398ef1f7b290bc5b75ef59182bfa02fafb7caeb504bd9f77348aea61ae9",
                16);

        // private exponent
        BigInteger d = new BigInteger(
                "1801d152befc69b1134eda145bf6c94e224fa1acee36f06826436c609840a776a532911ae48101a460699fd9424a1d51329804fa23cbec98bf95cdb0dbc900c05c5a358f48228ab03372b25610b0354d0e4a8c57efe86b1b2fb9ff6580655cdabddb31d7a8cfaf99e7866ba0d93f7ee8d1aab07fc347836c03df537569ab9fcfca8ebf5662feafbdf196bb6c925dbc878f89985096fabd6430511c0ca9c4d99b6f9f5dd9aa3ddfac12f6c2d3194ab99c897ba25bf71e53cd33c1573e242d75c48cd2537d1766bbbf4f7235c40ce3f49b18e00c874932412743dc28b7d3d32e85c922c1d9a8e5bf4c7dd6fe4545dd699295d51945d1fc507c24a709e87561b001",
                16);

        // public exponent (just provided for illustration. The focus in this assignment is on the decryption process)
        BigInteger e = new BigInteger("10001", 16);

        Random rnd = new Random();
        BigInteger m = new BigInteger(modulus.bitLength() - 1, rnd);
        BigInteger c = encrypt(m, e, modulus);
        long startTime = System.nanoTime();
        BigInteger m2 = decrypt(c, d, modulus);
        long stopTime = System.nanoTime();
        System.out.println("Time for RSA without montgomery:"+(stopTime - startTime));
        BigInteger R=createR(modulus); //creatin R
        BigInteger NN=modulus.modInverse(R).multiply(BigInteger.valueOf(-1)); //N_prime
        int e_length=e.bitLength();
        int d_length=d.bitLength();
        BigInteger bb=m.multiply(R).mod(modulus);//b_bar
        BigInteger aa=m.multiply(R).mod(modulus);// a_bar
        BigInteger c2 = encrypt2(aa,e , modulus,R,NN,e_length,bb);
        c2=c2.multiply((R).modInverse(modulus)).mod(modulus);
        bb=c2.multiply(R).mod(modulus);
        aa=c2.multiply(R).mod(modulus);
        startTime = System.nanoTime();
        BigInteger m3 = decrypt2(aa, d, modulus,R,NN,d_length,bb);//m3_bar
        stopTime = System.nanoTime();
        System.out.println("Time for RSA with montgomery:   "+(stopTime - startTime));
        m3=m3.multiply((R).modInverse(modulus)).mod(modulus);//m3
        System.out.println("Original message   = " + m.toString(16));

        System.out.println("Decrypted message1 = " + m2.toString(16));
        System.out.println("Decrypted message2 = " + m3.toString(16));

        if (!m.equals(m2) || !m.equals(m3)) {
            System.err.println("There is an error.");
        }
    }
}
