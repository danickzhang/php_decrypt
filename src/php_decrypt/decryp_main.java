package php_decrypt;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;



public class decryp_main {

    /*config params*/
    static final boolean recovery = false; // true -> upload to recovery server; false -> just look up locally.
    static final int PROJECT_NAME = 0; // 0->craving, 1->nimh
    
    static String outputFilePath = ".\\output.txt";
    static String inputFilePath = ".\\input.txt";
    static String PrivateKeyPath = "C:\\Danick\\keystore\\private.key";
    
    
    /**********************************************************************************/
    static final String CRAVING_RECOVERY_URL =  "http://dslsrv8.cs.missouri.edu/~hw85f/Server/CrtTest/Crt2/recoverDec.php";
    static final String NIMH_RECOVERY_URL =  "http://dslsrv8.cs.missouri.edu/~hw85f/Server/CrtTest/CrtNIMH/recoverDec.php";
    
    static String url = PROJECT_NAME==0?CRAVING_RECOVERY_URL:NIMH_RECOVERY_URL;

    


    public static void main(String[] args){
        try {

            decrpytion();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    protected static void decrpytion() throws Exception {
        
        Key privKey = readPrivateKeyFromFile(PrivateKeyPath);

        Cipher cipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, privKey);

        FileInputStream inputInedx = new FileInputStream(inputFilePath);
        FileInputStream input = new FileInputStream(inputFilePath);

        BufferedReader br = new BufferedReader(new InputStreamReader(inputInedx));

        String line = br.readLine();

        int se = 1;
        byte[] inputByteArray = null;
        int inputOffset = 0;
        int inputLen = 0;
        
        do {
            ///////////////////////////////////
            //    76*(line-1)+rest + line
            ///////////////////////////////////
            inputLen += line.length();

            if(line.length() < 76){
                inputLen+=se;

                inputByteArray = new byte[inputLen];
                se=0;
                input.read(inputByteArray);

                /*
                 * upload to recovery server address when needed.
                 * use server php to parse csv format
                 */
                if(recovery){

                    PrintWriter out = null;
                    BufferedReader in = null;
                    String results = "";
                    try {
                        URL realUrl = new URL(url);
                        // open connection to url
                        URLConnection conn = realUrl.openConnection();
                        // set request params
                        conn.setRequestProperty("accept", "*/*");
                        conn.setRequestProperty("connection", "Keep-Alive");
                        conn.setRequestProperty("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)");
                        // send as POST
                        conn.setDoOutput(true);
                        conn.setDoInput(true);
                        //  get URLConnection output stream
                        out = new PrintWriter(conn.getOutputStream());
                        // send request
                        System.out.println(new String(inputByteArray));
                        out.print("key=data&v="+new String(inputByteArray));
                        // flush output
                        out.flush();
                        // BufferedRead URL response
                        in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                        String lines;
                        while ((lines = in.readLine()) != null) {
                            results += lines;
                        }
                        System.out.println("return: "+results);
                    } catch (Exception e) {
                        System.out.println("POST Exception£¡"+e);
                        e.printStackTrace();
                    }
                    //close file and stream at finally
                    finally{
                        try{
                            if(out!=null){
                                out.close();
                            }
                            if(in!=null){
                                in.close();
                            }
                        }
                        catch(IOException ex){
                            ex.printStackTrace();
                        }
                    }

                }//end uploading

                inputOffset += inputLen;
                inputLen = 0;

                byte[] b2 = Base64.decodeBase64(inputByteArray);

                byte [] keybyte = Arrays.copyOfRange(b2, 0, 256);
                byte [] filebyte = Arrays.copyOfRange(b2, 256, b2.length);

                byte [] keyre = cipher.doFinal(keybyte);

                SecretKeySpec secretKeySpec = new SecretKeySpec(keyre, "AES");
//              System.out.println("KEY "+secretKeySpec.getAlgorithm()+" "+secretKeySpec.getFormat()+" "+secretKeySpec.getEncoded().length+" ");

                Cipher cipherAes = Cipher.getInstance("AES");
                cipherAes.init(Cipher.DECRYPT_MODE, secretKeySpec);
                byte [] result=cipherAes.doFinal(filebyte);

                System.out.println(new String(result));
                
                writeToFile(outputFilePath, new String(result));

            }else{
                //length wrong, do nothing
                
            }

            line = br.readLine();
            se++;
        }while (line != null);

    }


    protected static void writeToFile(String f, String toWrite) throws IOException{
        FileWriter fw = new FileWriter(f, true);
        fw.write(toWrite+'\n');
        fw.flush();
        fw.close();
    }

    public static PublicKey readPrivateKeyFromFile(String fileName){

        try{
            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(fileName));
            
            BigInteger m = (BigInteger)ois.readObject();
            BigInteger e = (BigInteger)ois.readObject();
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory fact = KeyFactory.getInstance("RSA", new BouncyCastleProvider());
            PublicKey pubKey = fact.generatePublic(keySpec);
            
            return pubKey;
        }catch(Exception e){
            e.getMessage();
            return null;
        }
    }



}
