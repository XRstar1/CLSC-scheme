package chen;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;

public class chen{


    //------------------------------------系统初始化--------------------------------
    public static void setup(String pairingFile, String publicFile,String mskFile) {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //设置KGC主私钥s

        Element s = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();
        mskProp.setProperty("s", Base64.getEncoder().encodeToString(s.toBytes()));
        storePropToFile(mskProp, mskFile);

        //设置主公钥K_pub和公开参数
        Element P = bp.getG1().newRandomElement().getImmutable();
        Element P_pub = P.powZn(s).getImmutable();
        Properties pubProp = new Properties();
        pubProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pubProp.setProperty("P_pub", Base64.getEncoder().encodeToString(P_pub.toBytes()));
        storePropToFile(pubProp, publicFile);
    }



    //---------------------------注册阶段-----------------------------------
    public static void KeyGen(String pairingFile, String publicFile, String mskFile, String id, String pkFile ,String skFile, String pidFile) throws NoSuchAlgorithmException, IOException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //公共参数群G生成元P,和主公钥Pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PubStr)).getImmutable();

        //取出主私钥
        Properties mskPro = loadPropFromFile(mskFile);
        String mskStr = mskPro.getProperty("s");
        Element s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskStr)).getImmutable();

        //用户操作：
        Element r = bp.getZr().newRandomElement().getImmutable();
        Element R= P.powZn(r).getImmutable();

        String pi = "1年";
        byte[] h0_hash = sha1(pi+P_pub.toString()+R.powZn(s));
        byte [] IDByte = id.getBytes();
        byte[]  PidByte = new byte[IDByte.length];
        for (int j = 0; j < IDByte.length; j++){
            PidByte[j] = (byte)(IDByte[j] ^ h0_hash[j]);
        }

        String Pid = new String(PidByte,"utf-8");




        //生成部分私钥
        Element a = bp.getZr().newRandomElement().getImmutable();
        Element T = P.powZn(a).getImmutable();
        byte [] h1_hash = sha1(Pid+T.toString()+P.toString()+P_pub.toString());
        Element h1 = bp.getZr().newElementFromHash(h1_hash,0,h1_hash.length).getImmutable();
        Element d = a.add(s.mul(h1)).getImmutable();




        if (P.powZn(d).equals(T.add(P_pub.powZn(h1)))){


            Element x = bp.getZr().newRandomElement().getImmutable();
            Element Q = P.powZn(x).getImmutable();

            FileReader SkReader = new FileReader(skFile);
            Properties skstore = new Properties();
            skstore.load(SkReader);
            skstore.setProperty("x"+id, Base64.getEncoder().encodeToString(x.toBytes()));
            skstore.setProperty("d"+id, Base64.getEncoder().encodeToString(d.toBytes()));


            FileReader PkReader = new FileReader(pkFile);
            Properties pkstore = new Properties();
            pkstore.load(PkReader);
            pkstore.setProperty("T"+id, Base64.getEncoder().encodeToString(T.toBytes()));
            pkstore.setProperty("Q"+id, Base64.getEncoder().encodeToString(Q.toBytes()));



            FileReader pidReader = new FileReader(pidFile);
            Properties pidPro = new Properties();
            pidPro.load(pidReader);
            pidPro.setProperty("pid"+id, Base64.getEncoder().encodeToString(Pid.getBytes()));




            FileWriter skWriter = new FileWriter(skFile);
            FileWriter pkWriter = new FileWriter(pkFile);
            FileWriter pidWriter = new FileWriter(pidFile);
            skstore.store(skWriter, "新增sk信息");
            pkstore.store(pkWriter,"新增pk消息");
            pidPro.store(pidWriter,"新增pid消息");
            SkReader.close();
            PkReader.close();
            pidReader.close();
            skWriter.close();
            pkWriter.close();
            pidWriter.close();
        }else {
            System.out.println("验证不通过");
        }

    }

    public static void signCrypt(String pairFile, String publicFile, String pidFile, String skFile, String pkFile,  String message, String signCryptFile) throws NoSuchAlgorithmException, IOException {

        Pairing bp = PairingFactory.getPairing(pairFile);
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();

        //发送者的操作：
        //取出自己的公私钥对：
        Properties skProp = loadPropFromFile(skFile);
        String xStr = skProp.getProperty("x"+"send");
        String dStr = skProp.getProperty("d"+"send");
        Element xi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xStr)).getImmutable();
        Element di = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(dStr)).getImmutable();
        Properties pkProp = loadPropFromFile(pkFile);
        String TiStr = pkProp.getProperty("T"+"send");
        String TjStr = pkProp.getProperty("T"+"rec");
        String QiStr = pkProp.getProperty("Q"+"send");
        String QjStr = pkProp.getProperty("Q"+"rec");
        Element Ti = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TiStr)).getImmutable();
        Element Tj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TjStr)).getImmutable();
        Element Qi = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QiStr)).getImmutable();
        Element Qj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QjStr)).getImmutable();

        //获取假名
        Properties pidPro = loadPropFromFile(pidFile);
        String pidi = pkProp.getProperty("pid"+"send");
        String pidj = pkProp.getProperty("pid"+"rec");

        Element u = bp.getZr().newRandomElement().getImmutable();
        byte [] hi_hash = sha1( pidi+Ti.toString()+P.toString()+P_pub.toString());
        Element hi = bp.getZr().newElementFromHash(hi_hash,0,hi_hash.length).getImmutable();
        Element U_ = Qi.add(Ti.add(P_pub.powZn(hi))).powZn(u);


        byte [] hj_hash = sha1( pidj +Tj.toString()+P.toString()+P_pub.toString());
        Element hj = bp.getZr().newElementFromHash(hj_hash,0,hj_hash.length).getImmutable();



          //  String TStr = pkProp.getProperty("T");
            //String QStr = pkProp.getProperty("Q");
            //Element T = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TStr)).getImmutable();
            //Element Q = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QStr)).getImmutable();

        Element V = (Qj.powZn(hj).add(Tj.powZn(hi).add(P_pub.powZn(hj).powZn(hi)))).powZn(u.mul(xi.add(di)));
        byte [] Y_hash = sha1( pidj +U_.toString()+V.toString());

        System.out.println(V);

        byte[] messageByte = message.getBytes();
        byte[] c = new byte[messageByte.length];
            for (int j = 0; j < messageByte.length; j++){
                c[j] = (byte)(messageByte[j] ^ Y_hash[j]);
            }
        Element k = bp.getZr().newRandomElement().getImmutable();
        Element I = P.powZn(k).getImmutable();
      //  System.out.println(I);

        byte[] h3_hash = sha1(I.toString()+c.toString());
        Element r = bp.getZr().newElementFromHash(h3_hash,0, h3_hash.length);
        Element tha = hi.mul(xi).add(hj.mul(di)).mul(r).add(k);

        Properties sigC = new Properties();
        sigC.setProperty("U_", Base64.getEncoder().encodeToString(U_.toBytes()));
        sigC.setProperty("r", Base64.getEncoder().encodeToString(r.toBytes()));
        sigC.setProperty("tha", Base64.getEncoder().encodeToString(tha.toBytes()));
        sigC.setProperty("I", Base64.getEncoder().encodeToString(I.toBytes()));
        sigC.setProperty("c", Base64.getEncoder().encodeToString(c));
        //sigC.setProperty("u", Base64.getEncoder().encodeToString(u.toBytes()));
        storePropToFile(sigC,signCryptFile);
    }

    public static void unsignCrypt(String pairingFile, String publicFile, String pidFile ,String skFile, String pkFile, String signCryptFile, String message) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //公开参数
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();


        //接收者的假名
        Properties pidProp = loadPropFromFile(pidFile);
        String pidj = pidProp.getProperty("pid"+"send");

        String pidi = pidProp.getProperty("pid"+"rec");
        //接收者的私钥
        Properties skProp = loadPropFromFile(skFile);
        String xjStr = skProp.getProperty("x"+"rec");
        String djStr = skProp.getProperty("d"+"rec");
        Element xj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xjStr)).getImmutable();
        Element dj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(djStr)).getImmutable();

        //发送者的公钥
        Properties pkProp = loadPropFromFile(pkFile);
        String QiStr = pkProp.getProperty("Q"+"send");
        String TiStr = pkProp.getProperty("T"+"send");
        String QjStr = pkProp.getProperty("Q"+"rec");
        String TjStr = pkProp.getProperty("T"+"rec");
        Element Qi = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QiStr)).getImmutable();
        Element Qj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QjStr)).getImmutable();
        Element Ti = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TiStr)).getImmutable();
        Element Tj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TjStr)).getImmutable();


        //获取签密信息
        Properties sigC = loadPropFromFile(signCryptFile);
        String UStr = sigC.getProperty("U_");
        String rStr = sigC.getProperty("r");
        String thaStr = sigC.getProperty("tha");
        String IStr = sigC.getProperty("I");
        String cStr = sigC.getProperty("c");
        //String uStr = sigC.getProperty("u");
        Element U_ = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(UStr)).getImmutable();
        Element r = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(rStr)).getImmutable();
        Element tha = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(thaStr)).getImmutable();
        Element I = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(IStr)).getImmutable();
        //Element u = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(uStr)).getImmutable();
        byte[] c = cStr.getBytes();

        byte [] hi_hash = sha1( pidi +Ti.toString()+P.toString()+P_pub.toString());
        Element hi = bp.getZr().newElementFromHash(hi_hash,0,hi_hash.length).getImmutable();
        byte [] hj_hash = sha1( pidj +Tj.toString()+P.toString()+P_pub.toString());
        Element hj = bp.getZr().newElementFromHash(hj_hash,0,hj_hash.length).getImmutable();






        Element Z = U_.powZn(hj.mul(xj).add(hi.mul(dj)));

        System.out.println(Z);


        byte [] Y = sha1(pidj+U_.toString()+Z.toString());

        Element I_ = P.powZn(tha).sub(Qi.powZn(r.mul(hi))).sub(Ti.powZn(r.mul(hj))).sub(P_pub.powZn(r.mul(hi.mul(hj))));
       // System.out.println(I_);

        byte [] h3_hash = sha1(I_.toString()+c.toString());
        Element h3 = bp.getZr().newElementFromHash(h3_hash,0, h3_hash.length);
        if (r.equals(h3)) {
           System.out.println("成功");
            byte[] messageByte = new byte[c.length];
            for (int j = 0; j < messageByte.length; j++){
                messageByte[j] = (byte)(c[j] ^ Y[j]);
            }
            String DeCryptmessage = new String(messageByte,"utf-8");
            System.out.println(DeCryptmessage);
       }
    }




    public static void storePropToFile(Properties prop, String fileName){
        try(FileOutputStream out = new FileOutputStream(fileName)){
            prop.store(out, null);
        }
        catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (
                FileInputStream in = new FileInputStream(fileName)){
            prop.load(in);
        }
        catch (IOException e){
            e.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }

    public static byte[] sha1(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static void main(String[] args) throws Exception {
        //String ID =  "rsuj@snnu.edu.com";
        String  message  ="12345678";
        String [] users = new String[] {"send", "rec"};
        String dir = "database/data_chen/";
        String pairingParametersFileName = "database/data_ours/a.properties";
        String publicParameterFileName = dir + "pub.properties";
        String pidFileName = dir + "pid.properties";
        String mskFileName = dir + "msk.properties";
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "sk.properties";
        String signCryptFileName = dir + "signCrypt.properties";
        long start = System.currentTimeMillis();

        setup(pairingParametersFileName,publicParameterFileName,mskFileName);
        for (int i = 0; i < users.length; i++) {
            KeyGen(pairingParametersFileName,publicParameterFileName,mskFileName,users[i],pkFileName,skFileName,pidFileName);
        }
        signCrypt(pairingParametersFileName,publicParameterFileName,pidFileName,skFileName,pkFileName,message,signCryptFileName);
        unsignCrypt(pairingParametersFileName,publicParameterFileName,pidFileName,skFileName,pkFileName,signCryptFileName,message);
        long end = System.currentTimeMillis();
        System.out.print("运行时间为");
        System.out.println((end-start)*10);
    }

}
