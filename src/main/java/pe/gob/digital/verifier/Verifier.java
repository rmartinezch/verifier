/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package pe.gob.digital.verifier;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author rmart
 */
public class Verifier {

    static String alg = "SHA256";
    static String signCer = "sign.cer";
    static String originalMsg = "Dato a ser firmado";
    static String signedEncodedMsg = "gpgnJY+RMxZd1OAieLQWBu9JndhxVRGolwQNl3FTGUwlPBBAO/Ram6h5MkEFdWVqoiVWOw82esC75gWVXQLsRM8LD1KRB39FM0LrsDjja8Eia+zC/G9Idxctj4i5azlzfgNGS/k88ti8efqe8HkIEf1ZOr4ZAaFBgi0CAmtJxEwHhNEvAToKtPnZda/MdYrom3GijFIfJBR4hdV30gjtsThTcUBt8ZEgjsM6SpUPd+xidnUDRyh/vPdrkuW3fpJnHNsnMM1kirG4xCUtWD0qahxCcRAIsyXx5f0IcN39fe4duMlYFwwhIKvCT7XuJRpu3j+E7YZeDuFXC3aQnIrHAA==";
    static Certificate certificate = null;
    static byte[] signedDecodedMsg = null;

    public static void main(String[] args) throws CertificateException, FileNotFoundException, UnsupportedEncodingException {
        System.out.println("Verify digital signature using original message, signed encoded message and digital certificate");
        Security.addProvider(new BouncyCastleProvider());
        File certificateFile = new File(signCer);
        certificate = fromByteArrayToX509Certificate(certificateFile);
        if (certificate == null)
            return;
        signedDecodedMsg = Base64.getDecoder().decode(signedEncodedMsg.getBytes("UTF-8"));
        try {
            verify();
        } catch (NoSuchProviderException | UnrecoverableKeyException | IOException | KeyStoreException | NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            Logger.getLogger(Verifier.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * The process of verification needs specify only the algorithm, don't need specify any other additional data
     * @throws NoSuchProviderException
     * @throws UnrecoverableKeyException
     * @throws CertificateException
     * @throws IOException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException 
     */
    private static void verify() throws NoSuchProviderException, UnrecoverableKeyException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String signAlgorithm = alg + "withRSA";
        System.out.println("Signature algorithm: " + signAlgorithm);
        Signature sig = Signature.getInstance(signAlgorithm, "BC");
        sig.initVerify(certificate.getPublicKey());
        sig.update(originalMsg.getBytes());

        boolean valid = sig.verify(signedDecodedMsg);
        System.out.println("verify : " + valid);
    }

    /**
     *
     * @param certificateFile certificate file extracted from dnie
     * @return certificate file in X509Certifcate format
     */
    public static X509Certificate fromByteArrayToX509Certificate(File certificateFile) {
        X509Certificate x509Certificate = null;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            FileInputStream in = new FileInputStream(certificateFile);
            x509Certificate = (X509Certificate) certFactory.generateCertificate(in);
        } catch (CertificateException ex) {
            Logger.getLogger(Verifier.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            System.out.println("File not found: " + certificateFile.getAbsolutePath());
        }
            return x509Certificate;
    }
}
