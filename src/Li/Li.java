package Li;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Li {
    private static final  Map<Object,byte []> C = new HashMap<>();

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
    public static void KeyGen(String pairingFile, String publicFile, String mskFile, String id, String pkFile ,String skFile, int index) throws NoSuchAlgorithmException, IOException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //公共参数群G生成元P,和主公钥Pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PubStr)).getImmutable();

        //用户操作：
        Element x = bp.getZr().newRandomElement().getImmutable();
        Element X = P.powZn(x).getImmutable();




        //KGC的操作:
        //取出主私钥s
        Properties mskProp = loadPropFromFile(mskFile);
        String sStr = mskProp.getProperty("s");
        Element s= bp.getZr().newElementFromBytes
                (Base64.getDecoder().decode(sStr)).getImmutable();




        //生成部分私钥
       // Element r = bp.getZr().newRandomElement().getImmutable();
      //  Element R = P.powZn(r).getImmutable();
        byte [] h0_hash = sha1(id+s.toString());
        Element gamma = bp.getZr().newElementFromHash(h0_hash,0,h0_hash.length).getImmutable();
        Element y = s.mul(gamma).getImmutable();
       // Element q = Math.pow(h0,-1);

        Element tha1 = P.powZn(gamma.invert()).getImmutable();
        Element tha2 =P.powZn(gamma).getImmutable();

        Element PK = X.powZn(gamma);

        if (tha1.powZn(y).equals(P_pub)&& tha2.powZn(x).equals(PK)){

            FileReader SkReader = new FileReader(skFile);
            FileReader PkReader = new FileReader(pkFile);

            Properties skstore = new Properties();
            skstore.load(SkReader);
            skstore.setProperty("x"+index, Base64.getEncoder().encodeToString(x.toBytes()));
            skstore.setProperty("y"+index, Base64.getEncoder().encodeToString(y.toBytes()));


            Properties pkstore = new Properties();
            pkstore.load(PkReader);

            pkstore.setProperty("PK"+index, Base64.getEncoder().encodeToString(PK.toBytes()));
            pkstore.setProperty("X"+index, Base64.getEncoder().encodeToString(X.toBytes()));
          //  pkstore.setProperty("R"+index, Base64.getEncoder().encodeToString(R.toBytes()));

            FileWriter skWriter = new FileWriter(skFile);
            FileWriter pkWriter = new FileWriter(pkFile);
            skstore.store(skWriter, "新增sk信息");
            pkstore.store(pkWriter,"新增pk消息");

            SkReader.close();
            PkReader.close();
            skWriter.close();
            pkWriter.close();

        }else {
            System.out.println("验证不通过");
        }

    }

    public static void signCrypt(String pairFile, String publicFile, String skFile, String pkFile, String message, String[] rec, String signCryptFile) throws NoSuchAlgorithmException, IOException {

        Pairing bp = PairingFactory.getPairing(pairFile);
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();

        //发送者的操作：
        //取出自己的公私钥对：
        Properties skProp = loadPropFromFile(skFile);
        String xStr = skProp.getProperty("x0");
        String yStr = skProp.getProperty("y0");
        Element x = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xStr)).getImmutable();
        Element y = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(yStr)).getImmutable();
        Properties pkProp = loadPropFromFile(pkFile);
        String PKStr = pkProp.getProperty("PK0");
       // String RStr = pkProp.getProperty("R0");
        Element PK = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PKStr)).getImmutable();
      //  Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();


      Element r = bp.getZr().newRandomElement().getImmutable();
      //  Element R = P.powZn(r).getImmutable();

        Element Vx = bp.getZr().newRandomElement().getImmutable();
        Element Vy = bp.getZr().newRandomElement().getImmutable();
        byte[] h2_hash = sha1(Vx.toString()+Vy.toString());
        Element W = PK.powZn(r);
        Element V = P.powZn(r.mul(x));
        Element tha = bp.getZr().newRandomElement();
        List<Element> list = new ArrayList<>();
        Element h2 = bp.getZr().newElementFromHash(h2_hash,0,h2_hash.length).getImmutable();




        for (int i=1; i< rec.length ; i++){


            String PKiStr = pkProp.getProperty("PK"+i);
           Element PKi = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PKiStr)).getImmutable();
            Element Ki = PKi.powZn(y.mul(x.mul(r)));



            byte[] h1 = sha1(Ki.toString());

            byte[] h6_hash = sha1(Ki.toString()+W.toString());
            Element h6 = bp.getZr().newElementFromHash(h6_hash,0,h6_hash.length).getImmutable();
            list.add(h6);




            byte[] messageByte = message.getBytes();


            byte[] c = new byte[messageByte.length];
            for (int j = 0; j < messageByte.length; j++){
                c[j] = (byte)(messageByte[j] ^ h1[j]);
            }

            C.put(h2.toString(),c);


        }
      //  byte [] h3_hash = sha1(Ki.toString()+W.toString());

      //  Element h3 = bp.getZr().newElementFromHash(h3_hash,0,h3_hash.length).getImmutable();
        Element h61 = list.get(0);
        Element h62 = list.get(1);
        Element h63 = list.get(2);
        Element z_ = (h61.add(h62.add(h63)));
        Element a2 = z_.negate();
        Element a1 = h62.mul(h63).add(h61.mul(h63)).add(h61.mul(h62));
        Element z__ = h61.mul(h62.mul(h63));
        Element a0 = z__.negate().add(tha);

        byte [] h3_hash = sha1(Vx.toString()+Vy.toString()+W.toString()+tha.toString()+a2.toString()+a1.toString()+a0.toString());
        Element h3 = bp.getZr().newElementFromHash(h3_hash,0, h3_hash.length);

        Properties sigC = new Properties();
        sigC.setProperty("Vx", Base64.getEncoder().encodeToString(Vx.toBytes()));
        sigC.setProperty("Vy", Base64.getEncoder().encodeToString(Vy.toBytes()));
        sigC.setProperty("W", Base64.getEncoder().encodeToString(W.toBytes()));
       // sigC.setProperty("R", Base64.getEncoder().encodeToString(R.toBytes()));
       // sigC.setProperty("V", Base64.getEncoder().encodeToString(V.toBytes()));
        sigC.setProperty("h3", Base64.getEncoder().encodeToString(h3.toBytes()));
        sigC.setProperty("a0", Base64.getEncoder().encodeToString(a0.toBytes()));
        sigC.setProperty("a1", Base64.getEncoder().encodeToString(a1.toBytes()));
        sigC.setProperty("a2", Base64.getEncoder().encodeToString(a2.toBytes()));
        //sigC.setProperty("C", Base64.getEncoder().encodeToString(C.getBytes()));
        storePropToFile(sigC,signCryptFile);
    }

    public static void unsignCrypt(String pairingFile, String publicFile, String skFile, String pkFile, String[] user, String sigCryptFile, int index) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //公开参数
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();

        //接收者的私钥
        Properties skProp = loadPropFromFile(skFile);
        String xiStr = skProp.getProperty("x"+index);
        String yiStr = skProp.getProperty("y"+index);
        Element xi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xiStr)).getImmutable();
        Element yi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(yiStr)).getImmutable();

        //发送者的公钥
        Properties pkProp = loadPropFromFile(pkFile);
        String PKStr = pkProp.getProperty("PK0");
        String XsStr = pkProp.getProperty("X0");
        Element PKs = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PKStr)).getImmutable();
        Element Xs = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XsStr)).getImmutable();
       // Element Rs = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RsStr)).getImmutable();


        //获取签密信息
        Properties sigC = loadPropFromFile(sigCryptFile);
        String VxStr = sigC.getProperty("Vx");
        String VyStr = sigC.getProperty("Vy");
        String WStr = sigC.getProperty("W");
       String a0Str = sigC.getProperty("a0");
        String a1Str = sigC.getProperty("a1");
        String a2Str = sigC.getProperty("a2");
        String h3Str = sigC.getProperty("h3");
      //  String VStr = sigC.getProperty("V");
        Element Vx = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(VxStr)).getImmutable();
        Element Vy = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(VyStr)).getImmutable();
        Element a0 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(a0Str)).getImmutable();
        Element a1= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(a1Str)).getImmutable();
        Element a2 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(a2Str)).getImmutable();
        Element h3= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(h3Str)).getImmutable();
      //  Element V = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(VStr)).getImmutable();
      //  Element R= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();


        Element W = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(WStr)).getImmutable();

        Element K_ = W.powZn(xi.mul(yi)).getImmutable();

        byte [] h1_hash = sha1(K_.toString());

        Element h1_ = bp.getZr().newElementFromHash(h1_hash,0, h1_hash.length);



        byte [] h2_hash = sha1(Vx.toString()+Vy.toString());
        Element h2 = bp.getZr().newElementFromHash(h2_hash,0, h2_hash.length);

        byte[] h6_hash = sha1(K_.toString()+W.toString());
        Element h6_ = bp.getZr().newElementFromHash(h6_hash,0,h6_hash.length).getImmutable();

        Element tha_ = h6_.mul(h6_.mul(h6_)).add(a2.mul(h6_.mul(h6_))).add(a1.mul(h6_)).add(a0);

        byte [] h3_hash = sha1(Vx.toString()+Vy.toString()+W.toString()+tha_.toString()+a2.toString()+a1.toString()+a0.toString());
        Element h3_ = bp.getZr().newElementFromHash(h3_hash,0, h3_hash.length);


        byte[] ci = C.get(h2.toString());


        //byte[] h2_hash = sha1(user[0]+C.toString()+Xs.toString()+Rs.toString()+T.toString());
       // Element h2 = bp.getZr().newElementFromHash(h2_hash,0, h2_hash.length).getImmutable();
       // byte[] h1_hash = sha1(user[0]+Xs.toString()+Rs.toString()+P_pub.toString());
      //  Element h1 = bp.getZr().newElementFromHash(h1_hash,0, h1_hash.length).getImmutable();
        if (h3.equals(Xs.powZn(h3_))){
            System.out.println("成功");
            byte[] message = new byte[ci.length];
            for (int j = 0; j < message.length; j++){
                message[j] = (byte)(ci[j] ^ h1_hash[j]);
            }
            String str = new String(message,"utf-8");

            System.out.println(str);
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
        String ID =  "rsuj@snnu.edu.com";
        String message  ="12345678";
        String [] users = new String[] {"send@snnu.edu.com", "rec1@snnu.edu.com","rec2@snnu.edu.com","rec3@snnu.edu.com"};
        String dir = "database/data_Li/";
        String pairingParametersFileName = "database/data_Li/a.properties";
        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "sk.properties";
        String signCryptFileName = dir + "signCrypt.properties";

        long start = System.currentTimeMillis();
        setup(pairingParametersFileName,publicParameterFileName,mskFileName);
        for (int i = 0; i< users.length;i++){
            KeyGen(pairingParametersFileName,publicParameterFileName,mskFileName,users[i],pkFileName,skFileName, i);
        }

        signCrypt(pairingParametersFileName,publicParameterFileName,skFileName,pkFileName,message,users,signCryptFileName);
        unsignCrypt(pairingParametersFileName,publicParameterFileName,skFileName,pkFileName,users,signCryptFileName,2);
        long end = System.currentTimeMillis();
        System.out.print("运行时间为");
        System.out.println((end-start)*10);
    }

}
