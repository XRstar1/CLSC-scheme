package chen2;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;

public class slv {
    //private static final  Map<Object,byte []> C = new HashMap<>();

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
        Element Q= bp.getG1().newRandomElement().getImmutable();

        Element g = bp.pairing(P,Q);
        Properties pubProp = new Properties();
        pubProp.setProperty("g", Base64.getEncoder().encodeToString(g.toBytes()));
        pubProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pubProp.setProperty("P_pub", Base64.getEncoder().encodeToString(P_pub.toBytes()));


      //  Properties pubProp = new Properties();
        pubProp.setProperty("Q", Base64.getEncoder().encodeToString(Q.toBytes()));
       // pubProp.setProperty("P_pub", Base64.getEncoder().encodeToString(P_pub.toBytes()));
        storePropToFile(pubProp, publicFile);
    }



    //---------------------------注册阶段-----------------------------------
    public static void KeyGen(String pairingFile, String publicFile, String mskFile, String id, String pkFile ,String skFile, int index) throws NoSuchAlgorithmException, IOException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //公共参数群G生成元P,和主公钥Pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String QStr = pubProp.getProperty("Q");
        String PubStr = pubProp.getProperty("P_pub");
        String gStr = pubProp.getProperty("g");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element Q = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PubStr)).getImmutable();
        Element g = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(gStr)).getImmutable();

        //用户操作：
        Element x1 = bp.getZr().newRandomElement().getImmutable();
      //  Element X = P.powZn(x).getImmutable();
        Element x2 = bp.getZr().newRandomElement().getImmutable();



        //KGC的操作:
        //取出主私钥s
        Properties mskProp = loadPropFromFile(mskFile);
        String sStr = mskProp.getProperty("s");
        Element s= bp.getZr().newElementFromBytes
        (Base64.getDecoder().decode(sStr)).getImmutable();




        //生成部分私钥
       // Element r = bp.getZr().newRandomElement().getImmutable();
       // Element R = P.powZn(r).getImmutable();


          Element PK1 = P.powZn(x1).getImmutable();
          //Element T = P.powZn(q.add(s)).getImmutable();
          Element PK2 = P.powZn(x2).getImmutable();
        byte [] q_hash = sha1(id,PK2);
        Element q = bp.getZr().newElementFromHash(q_hash,0,q_hash.length).getImmutable();
        Element D = P.powZn(q.add(s).invert()).getImmutable();




            FileReader SkReader = new FileReader(skFile);
            FileReader PkReader = new FileReader(pkFile);


            Properties skstore = new Properties();
            skstore.load(SkReader);
         //   skstore.setProperty("x"+index, Base64.getEncoder().encodeToString(x.toBytes()));
            skstore.setProperty("D"+index, Base64.getEncoder().encodeToString(D.toBytes()));
        skstore.setProperty("q"+index, Base64.getEncoder().encodeToString(q.toBytes()));

            Properties pkstore = new Properties();
            pkstore.load(PkReader);
            pkstore.setProperty("PK1"+index, Base64.getEncoder().encodeToString(PK1.toBytes()));
            pkstore.setProperty("PK2"+index, Base64.getEncoder().encodeToString(PK2.toBytes()));

            FileWriter skWriter = new FileWriter(skFile);
            FileWriter pkWriter = new FileWriter(pkFile);


            skstore.store(skWriter, "新增sk信息");
            pkstore.store(pkWriter,"新增pk消息");
       // pkstore.store(mskWriter,"新增pks消息");
       // mskReader.close();
            SkReader.close();
            PkReader.close();
            skWriter.close();
            pkWriter.close();
      //  mskWriter.close();



    }

    public static void signCrypt(String pairFile,String mskFile, String publicFile, String skFile, String pkFile, String messages, String[] rec, String signCryptFile) throws NoSuchAlgorithmException, IOException {

        Pairing bp = PairingFactory.getPairing(pairFile);
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        String QStr = pubProp.getProperty("Q");

        String gStr = pubProp.getProperty("g");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element Q = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QStr)).getImmutable();
        // Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PubStr)).getImmutable();
        Element g = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(gStr)).getImmutable();
        // Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();

        //发送者的操作：
        //取出自己的公私钥对：
        Properties skProp = loadPropFromFile(skFile);
        String xStr = skProp.getProperty("x0");
        String DStr = skProp.getProperty("D0");
        String qStr = skProp.getProperty("q0");
        Element x = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xStr)).getImmutable();
        Element D = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(DStr)).getImmutable();
        Element q = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(qStr)).getImmutable();
        Properties pkProp = loadPropFromFile(pkFile);
        String PK1Str = pkProp.getProperty("PK10");
        String PK2Str = pkProp.getProperty("PK10");
        Element PK1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK1Str)).getImmutable();
        Element PK2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK2Str)).getImmutable();

        Properties mskProp = loadPropFromFile(mskFile);
        String sStr = mskProp.getProperty("s");
        Element s = bp.getZr().newElementFromBytes
                (Base64.getDecoder().decode(sStr)).getImmutable();

        Element u = bp.getZr().newRandomElement().getImmutable();
        Element U = P.powZn(u);
        Element r1 = bp.getZr().newRandomElement().getImmutable();
        Element gamma = bp.getZr().newRandomElement().getImmutable();
        Element beta = bp.getZr().newRandomElement().getImmutable();
        Element r2 = bp.getZr().newRandomElement().getImmutable();
        byte[] h2_hash = sha1(r2.toString() + rec[0] + PK1.toString() + PK2.toString(), PK2);
        Element h2 = bp.getZr().newElementFromHash(h2_hash, 0, h2_hash.length).getImmutable();
        Element W = bp.pairing(P.powZn(r1), P.powZn(r1));
        Element C1 = P.powZn(r1.mul(h2.invert()));
        Element C2 = P.powZn(r1.mul(beta.add(s)));
        Element T = D.powZn(u.mul(gamma.invert()));
        byte[] h1_hash = sha1(r2.toString() + rec + PK1.toString() + PK2.toString());
        Element h1 = bp.getZr().newElementFromHash(h1_hash, 0, h1_hash.length).getImmutable();
        Element C3 = h2.mul(q.sub(beta));
        byte[] h4_hash = sha1(C3.toString() + r2 + rec + rec[0]);
        Element h4 = bp.getZr().newElementFromHash(h4_hash, 0, h4_hash.length).getImmutable();

        Element t = gamma.mul(x.add(h4)).getImmutable();


        byte[] h3_hash = sha1(W.toString() + h2.toString() + rec[0] + PK1.toString() + PK2.toString() + rec, PK2);
        Element h3 = bp.getZr().newElementFromHash(h3_hash, 0, h3_hash.length).getImmutable();


        Element z = D.powZn(r1.div(x.add(h3))).getImmutable();

        byte[] messageByte = messages.getBytes();

        byte[] c = new byte[messageByte.length];
        for (int j = 0; j < messageByte.length; j++) {
            c[j] = (byte) (messageByte[j] ^ h3_hash[j]);
        }


        FileReader signCReader = new FileReader(signCryptFile);
        FileWriter sigCWriter = new FileWriter(signCryptFile);


        Properties signCstore = new Properties();
        signCstore.load(signCReader);
        signCstore.setProperty("c", Base64.getEncoder().encodeToString(c));
        signCstore.setProperty("t", Base64.getEncoder().encodeToString(t.toBytes()));
        signCstore.setProperty("C1", Base64.getEncoder().encodeToString(C1.toBytes()));
        signCstore.setProperty("C2", Base64.getEncoder().encodeToString(C2.toBytes()));
        signCstore.setProperty("C3", Base64.getEncoder().encodeToString(C3.toBytes()));
        signCstore.setProperty("U", Base64.getEncoder().encodeToString(U.toBytes()));
        signCstore.setProperty("T", Base64.getEncoder().encodeToString(U.toBytes()));
        signCstore.setProperty("r2", Base64.getEncoder().encodeToString(r2.toBytes()));
       for (int i = 1; i < rec.length; i++) {

            String PK1iStr = pkProp.getProperty("PK1" + i);
            String PK2iStr = pkProp.getProperty("PK2" + i);
            Element PK1i = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK1iStr)).getImmutable();
            Element PK2i = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK2iStr)).getImmutable();


            //Element vi = PK1i.powZn(r1).getImmutable();


           // byte[] h5i_hash = sha1(W.toString() + vi.toString() + PK1i.toString() + rec[i], PK2);
           // Element h5i = bp.getZr().newElementFromHash(h5i_hash, 0, h5i_hash.length).getImmutable();

            //Element d1i = P.powZn(r1.mul(q.add(s))).getImmutable();


            // byte[] messagesByte = messages.getBytes();

            //byte[] d2i = new byte[h2_hash.length];
           // for (int j = 0; j < h2_hash.length; j++) {
           //     d2i[j] = (byte) (h2_hash[j] ^ h5i_hash[j]);
           // }


        }

        FileWriter signCWriter = new FileWriter(signCryptFile);
        FileWriter pkWriter = new FileWriter(pkFile);


        //signCstore.store(signCWriter,"新增singC消息");
        // pkstore.store(mskWriter,"新增pks消息");
        // mskReader.close();
        signCReader.close();
        //  PkReader.close();
        sigCWriter.close();
        // pkWriter.close();
        //  mskWriter.close();


        // byte [] h2_hash = sha1(rec[0]+C.toString()+X.toString()+R.toString()+T.toString());
        //Element h2 = bp.getZr().newElementFromHash(h2_hash,0, h2_hash.length);
        //Element v = h2.mul(x.add(d.add(t)));

        // Properties sigC = new Properties();
        // sigC.setProperty("c", Base64.getEncoder().encodeToString(c.toBytes()));
        // sigC.setProperty("di1", Base64.getEncoder().encodeToString(.toBytes()));
        //sigC.setProperty("C", Base64.getEncoder().encodeToString(C.getBytes()));
        // storePropToFile(sigC,signCryptFile);
    }

    private static byte[] sha1(String s) {
        return s.getBytes();
    }


    public static void unsignCrypt(String pairingFile, String publicFile, String mskFile,String skFile, String pkFile, String[] user, String sigCryptFile, int index) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //公开参数
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();




        Properties mskProp = loadPropFromFile(mskFile);
        String sStr = mskProp.getProperty("s");
        Element s= bp.getZr().newElementFromBytes
                (Base64.getDecoder().decode(sStr)).getImmutable();






        //接收者的私钥
        Properties skProp = loadPropFromFile(skFile);
        String xiStr = skProp.getProperty("x"+index);
        String DiStr = skProp.getProperty("D"+index);
        Element xi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xiStr)).getImmutable();
        Element Di = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(DiStr)).getImmutable();
        String qsStr = skProp.getProperty("q0");
        Element qs = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(qsStr)).getImmutable();
        //发送者的公钥
        Properties pkProp = loadPropFromFile(pkFile);
        String PK1iStr = pkProp.getProperty("PK1"+index);
        String PK1sStr = pkProp.getProperty("PK10");
        String PK2sStr = pkProp.getProperty("PK20");

        Element PK1i = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK1iStr)).getImmutable();
        Element PK2s = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK2sStr)).getImmutable();
        Element PK1s = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PK1sStr)).getImmutable();


        //获取签密信息
        Properties sigC = loadPropFromFile(sigCryptFile);
        String cStr = sigC.getProperty("c");
        String C1Str = sigC.getProperty("C1");
        String C2Str = sigC.getProperty("C1");
        String C3Str = sigC.getProperty("C3");
        String CStr = sigC.getProperty("C");
        String UStr = sigC.getProperty("U");
        String r2Str = sigC.getProperty("r2");
        String TStr = sigC.getProperty("T"+index);
       // String UStr = sigC.getProperty("U"+index);
        String tStr = sigC.getProperty("t"+index);
        byte[] c = cStr.getBytes();
        //byte[] d2i = d2iStr.getBytes();
        //Element c = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(cStr)).getImmutable();
        Element C1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1Str)).getImmutable();
        Element C2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1Str)).getImmutable();
        Element C3 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(C1Str)).getImmutable();
      //  Element C1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1Str)).getImmutable();
        Element U = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(UStr)).getImmutable();
        Element T = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TStr)).getImmutable();
        Element r2 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(UStr)).getImmutable();
        //Element d2i = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(di2Str)).getImmutable();
        Element t = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(tStr)).getImmutable();


       // Element U_ = T.powZn(xi.add(di)).getImmutable();
        Element w_ = bp.pairing(C1.mul(C3).add(C2),Di).getImmutable();



        byte [] h5_hash = sha1(w_.toString()+U.toString()+PK1i.toString()+U.powZn(xi));

       Element h5_ = bp.getZr().newElementFromHash(h5_hash,0, h5_hash.length);

       // byte[] h2_hash = new byte[h5_hash.length];
        //for (int j = 0; j < h2_hash.length; j++){
           // h2_hash[j] = (byte)(c[j] ^ h5_hash[j]);
       // }
        //Element h2_ = bp.getZr().newElementFromHash(h2_hash,0, h5_hash.length);


        byte [] h_hash = sha1( C3.toString() +c.toString()+r2.toString()+user+C1.toString()+C2.toString()+PK1i.toString());
        Element h_ = bp.getZr().newElementFromHash(h_hash,0,h_hash.length).getImmutable();




        // byte [] h5i_hash = sha1(w_.toString()+vi.toString()+PK1i);
      // Element h5 = bp.getZr().newElementFromHash(h5i_hash,0, h5i_hash.length);


       //byte[] ci = C.get(h5.toString());

        //byte [] h4_hash = sha1(h2_.toString()+user[0], PK2);
       // Element h4 = bp.getZr().newElementFromHash(h3_hash,0,h4_hash.length).getImmutable();
      // byte[] h2_hash = sha1(user[0]+C.toString()+Xs.toString()+Rs.toString()+T.toString());
      //  Element h2 = bp.getZr().newElementFromHash(h2_hash,0, h2_hash.length).getImmutable();
       // byte[] h1_hash = sha1(user[0]+Xs.toString()+Rs.toString()+P_pub.toString());
       // Element h1 = bp.getZr().newElementFromHash(h1_hash,0, h1_hash.length).getImmutable();
        if (bp.pairing(PK2s.add(P_pub.add(P.powZn(qs))),T.powZn(t)).equals(bp.pairing(U,P.powZn(h_)).powZn(bp.pairing(U,PK1s)))){
         System.out.println("成功");
           byte[] message = new byte[c.length];
           for (int j = 0; j < message.length; j++){
               message[j] = (byte)(c[j] ^ h5_hash[j]);
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

    public static byte[] sha1(String content, Element PK2) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static void main(String[] args) throws Exception {
        String ID =  "rsuj@snnu.edu.com";
        String  messages  ="12345678";
        String [] users = new String[] {"send@snnu.edu.com", "rec1@snnu.edu.com","rec2@snnu.edu.com","rec3@snnu.edu.com"};
        String dir = "database/data_ours/";
        String pairingParametersFileName = "database/data_selv/a.properties";
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

        signCrypt(pairingParametersFileName,mskFileName,publicParameterFileName,skFileName,pkFileName,messages,users,signCryptFileName);
        unsignCrypt(pairingParametersFileName,publicParameterFileName,mskFileName,skFileName,pkFileName,users,signCryptFileName,2);
        long end = System.currentTimeMillis();
        System.out.print("运行时间为");
        System.out.println((end-start)*10);
    }

}
