package Qiu;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Qiu {
    private static final  Map<Object,byte []> C = new HashMap<>();

    //------------------------------------系统初始化--------------------------------
    public static void Psetup(String pairingFile, String publicFile,String mskFile) throws IOException {
        Pairing bp1 = PairingFactory.getPairing(pairingFile);
        //设置KGC主私钥s
        Element s1 = bp1.getZr().newRandomElement().getImmutable();
        FileReader mskReader = new FileReader(mskFile);
        Properties mskstore = new Properties();
        mskstore.load(mskReader);
        mskstore.setProperty("s1", Base64.getEncoder().encodeToString(s1.toBytes()));

        FileWriter mskWriter = new FileWriter(mskFile);
        mskstore.store(mskWriter,"New");







        //设置主公钥K_pub和公开参数
        Element P = bp1.getG1().newRandomElement().getImmutable();
        Element P_1 = P.powZn(s1).getImmutable();

        FileReader pk1Reader = new FileReader(publicFile);
        FileWriter pk1Writer = new FileWriter(publicFile);



        Properties pk1store = new Properties();
        pk1store.load(pk1Reader);
        pk1store.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));

        pk1store.setProperty("P_1", Base64.getEncoder().encodeToString(P_1.toBytes()));
        pk1store.store(pk1Writer,"New");

        mskReader.close();
        mskWriter.close();
        pk1Reader.close();
        pk1Writer.close();


    }

    public static void Ksetup(String pairingFile, String publicFile,String mskFile) throws IOException {
        Pairing bp2 = PairingFactory.getPairing(pairingFile);
        //设置KGC主私钥s
        Element s2 = bp2.getZr().newRandomElement().getImmutable();
        FileReader mskReader = new FileReader(mskFile);

        Properties mskstore = new Properties();
        mskstore.load(mskReader);
        mskstore.setProperty("s2", Base64.getEncoder().encodeToString(s2.toBytes()));


        FileWriter mskWriter = new FileWriter(mskFile);
        mskstore.store(mskWriter,"New");












        //设置主公钥K_pub和公开参数
        Element P = bp2.getG1().newRandomElement().getImmutable();
        Element P_2 = P.powZn(s2).getImmutable();

        FileReader pk2Reader = new FileReader(publicFile);
        Properties pk2store = new Properties();
        pk2store.load(pk2Reader);
        pk2store.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pk2store.setProperty("P_2", Base64.getEncoder().encodeToString(P_2.toBytes()));
        FileWriter pk2Writer = new FileWriter(publicFile);
        pk2store.store(pk2Writer,"New");

        mskReader.close();
        mskWriter.close();
        pk2Reader.close();
        pk2Writer.close();
    }


    //---------------------------注册阶段-----------------------------------
    public static void KgcKeyGen(String pairingFile, String publicFile, String mskFile, String id, String pkFile ,String skFile, int index) throws NoSuchAlgorithmException, IOException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //公共参数群G生成元P,和主公钥Pub
        //Properties sigC = loadPropFromFile(sigCryptFile);
       // String cStr = sigC.getProperty("c");
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PubStr = pubProp.getProperty("P_2");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PubStr)).getImmutable();

        //用户操作：
        Element x = bp.getZr().newRandomElement().getImmutable();
        Element X = P.powZn(x).getImmutable();




        //KGC的操作:
        //取出主私钥s
        Properties mskProp = loadPropFromFile(mskFile);
        String sStr = mskProp.getProperty("s2");
        Element s2= bp.getZr().newElementFromBytes
        (Base64.getDecoder().decode(sStr)).getImmutable();




        //生成部分私钥
        Element t = bp.getZr().newRandomElement().getImmutable();
        Element T = P.powZn(t).getImmutable();
        byte [] h1_hash = sha1(id+X.powZn(s2).toString()+T.toString());
        Element h1 = bp.getZr().newElementFromHash(h1_hash,0,h1_hash.length).getImmutable();
        Element d = t.add(s2.mul(h1)).getImmutable();
        Element u = d.add(h1).getImmutable();





        if (P.powZn(u).equals(T.add(P_2.powZn(h1)).add(P.powZn(h1)))){

            FileReader SkReader = new FileReader(skFile);
            FileReader PkReader = new FileReader(pkFile);

            Properties skstore = new Properties();
            skstore.load(SkReader);
            skstore.setProperty("x"+index, Base64.getEncoder().encodeToString(x.toBytes()));
            skstore.setProperty("d"+index, Base64.getEncoder().encodeToString(d.toBytes()));



            Properties pkstore = new Properties();
            Element PK = T.add(X);
            pkstore.load(PkReader);
            pkstore.setProperty("PK"+index, Base64.getEncoder().encodeToString(PK.toBytes()));


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
    public static void IbcKeyGen(String pairingFile, String publicFile, String mskFile, String id,String pkFile,String sk2File, int index) throws NoSuchAlgorithmException, IOException {
        Pairing bp = PairingFactory.getPairing(pairingFile);
        //公共参数群G生成元P,和主公钥Pub
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PubStr = pubProp.getProperty("P_1");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PubStr)).getImmutable();






        //IBC的操作:
        //取出主私钥s
        Properties mskProp = loadPropFromFile(mskFile);
        String sStr = mskProp.getProperty("s1");
        Element s1= bp.getZr().newElementFromBytes
                (Base64.getDecoder().decode(sStr)).getImmutable();




        //生成私钥
        Element t = bp.getZr().newRandomElement().getImmutable();
        Element T = P.powZn(t).getImmutable();
        byte [] h1_hash = sha1(id+T.toString()+P_1.toString());
        Element h1 = bp.getZr().newElementFromHash(h1_hash,0,h1_hash.length).getImmutable();
        Element d = t.add(s1.mul(h1)).getImmutable();







        FileReader SkReader = new FileReader(sk2File);
          FileReader PkReader = new FileReader(pkFile);

            Properties skstore = new Properties();
            skstore.load(SkReader);
            skstore.setProperty("T"+index, Base64.getEncoder().encodeToString(T.toBytes()));
            skstore.setProperty("d"+index, Base64.getEncoder().encodeToString(d.toBytes()));






            FileWriter skWriter = new FileWriter(sk2File);

            skstore.store(skWriter, "新增sk信息");


            SkReader.close();

            skWriter.close();




    }


    public static void signCrypt(String pairFile, String publicFile, String sk2File, String pkFile, String[] messages, String[] rec, String signCryptFile) throws NoSuchAlgorithmException, IOException {

        Pairing bp = PairingFactory.getPairing(pairFile);
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PpubStr = pubProp.getProperty("P_2");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();

        //发送者的操作：
        //取出自己的公私钥对：
        Properties skProp = loadPropFromFile(sk2File);

        String xStr = skProp.getProperty("T0");
        String dStr = skProp.getProperty("d0");
        Element T = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(xStr)).getImmutable();
        Element d = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(dStr)).getImmutable();
        Properties pkProp = loadPropFromFile(pkFile);
        //String PKStr = pkProp.getProperty("PK");

        //Element PK = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PKStr)).getImmutable();



        Element r1 = bp.getZr().newRandomElement().getImmutable();
        Element r2 = bp.getZr().newRandomElement().getImmutable();
        Element R1 = P.powZn(r1).getImmutable();
        Element R2 = P.powZn(r2).getImmutable();

        //Element fx = bp.getZr().newZeroElement();
        Element tha = bp.getZr().newRandomElement();
        List <Element> list = new ArrayList<>();
        for (int i=1; i< rec.length ; i++){

            String PKiStr = pkProp.getProperty("PK"+i);
            Element PKi = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PKiStr)).getImmutable();
            byte [] hi_hash = sha1(rec[i] + PKi.toString()+P_2.toString());
            Element hi = bp.getZr().newElementFromHash(hi_hash,0,hi_hash.length).getImmutable();
            Element Ui = PKi.add(P_2).powZn(r1.mul(hi));
            byte[] z_hash = sha1(rec[i]+Ui.toString()+R1.toString());
            Element z = bp.getZr().newElementFromHash(z_hash,0,z_hash.length).getImmutable();
            list.add(z);





            byte[] messageByte = messages[i].getBytes();
            //byte[] z_hash = sha1(rec[i]+Ui.toString()+R1.toString());
            byte[] c = new byte[messageByte.length];
            for (int j = 0; j < messageByte.length; j++){
                c[j] = (byte)(messageByte[j] ^ z_hash[j]);
            }
            byte [] h4i_hash = sha1(z.toString()+R1.toString());
            Element ci = bp.getZr().newElementFromHash(c,0,c.length);
            Element h4i = bp.getZr().newElementFromHash(h4i_hash,0,h4i_hash.length).getImmutable();
            C.put(h4i.toString(),c);
            //System.out.println(list);
            //   Element zi = bp.getZr().newElementFromHash(z_hash,0,z_hash.length).getImmutable()
            }
        Element z1 = list.get(0);
        Element z2 = list.get(1);
        Element z3 = list.get(2);
        Element z_ = (z1.add(z2.add(z3)));
        Element a2 = z_.negate();
        Element a1 = z2.mul(z3).add(z1.mul(z3)).add(z1.mul(z2));
        Element z__ = z1.mul(z2.mul(z3)).add(tha);
        Element a0 = z__.negate();

        byte [] h_hash = sha1(rec[0]+R1.toString()+R2.toString()+C.toString()+tha.toString()+a0.toString()+a1.toString()+a2.toString());



        Element h = bp.getZr().newElementFromHash(h_hash,0, h_hash.length);
        Element v = r1.div(h.powZn(r2).add(d));

        Properties sigC = new Properties();
        sigC.setProperty("T", Base64.getEncoder().encodeToString(T.toBytes()));
        sigC.setProperty("R2", Base64.getEncoder().encodeToString(R2.toBytes()));
        sigC.setProperty("v", Base64.getEncoder().encodeToString(v.toBytes()));
        sigC.setProperty("h", Base64.getEncoder().encodeToString(h.toBytes()));
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
        String PpubStr = pubProp.getProperty("P_1");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();

        //接收者的私钥
        Properties skProp = loadPropFromFile(skFile);
        String xiStr = skProp.getProperty("x"+index);
        String diStr = skProp.getProperty("d"+index);
        Element xi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xiStr)).getImmutable();
        Element di = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(diStr)).getImmutable();

        //发送者的公钥
        Properties pkProp = loadPropFromFile(pkFile);
        String PKsStr = pkProp.getProperty("PK0");

        Element PKs = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PKsStr)).getImmutable();



        //获取签密信息
        Properties sigC = loadPropFromFile(sigCryptFile);
        String TStr = sigC.getProperty("T");
        String vStr = sigC.getProperty("v");
        String hStr = sigC.getProperty("h");
        String R2Str = sigC.getProperty("R2");
        String a0Str = sigC.getProperty("a0");
        String a1Str = sigC.getProperty("a1");
        String a2Str = sigC.getProperty("a2");
       // String hStr = sigC.getProperty("h");

        Element T = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TStr)).getImmutable();
        Element v = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(vStr)).getImmutable();
        Element h = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(hStr)).getImmutable();
        Element a0 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(a0Str)).getImmutable();
        Element a1= bp.getZr().newElementFromBytes(Base64.getDecoder().decode(a1Str)).getImmutable();
        Element a2 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(a2Str)).getImmutable();
        Element R2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(R2Str)).getImmutable();
       // Element h = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(hStr)).getImmutable();
        byte[] hs_hash = sha1(user[0]+T.toString()+P_1.toString());
        Element hs = bp.getZr().newElementFromHash(hs_hash,0, hs_hash.length).getImmutable();

       // Element R1_ = v.powZn(h.powZn(R2).add(T).add(hs.powZn(P_1))).getImmutable();
        Element R1_ = R2.powZn(h.mul(v)).add(T.powZn(v)).add(P_1.powZn(hs)).getImmutable();
        Element Ui_ = R1_.powZn(xi.add(di)).getImmutable();

        byte [] v_hash = sha1(user[index]+Ui_.toString()+R1_.toString());

        Element v_ = bp.getZr().newElementFromHash(v_hash,0, v_hash.length);

       Element tha_ = v_.mul(v_.mul(v_)).add(a2.mul(v_.mul(v_))).add(a1.mul(v_)).add(a0);

        byte [] h5i_hash = sha1(v_.toString()+R1_.toString());
        Element h5 = bp.getZr().newElementFromHash(h5i_hash,0, h5i_hash.length);




        byte[] ci = C.get(h5.toString());



        byte[] h__hash = sha1(user[0]+R1_.toString()+R2.toString()+C.toString()+tha_.toString()+a0.toString()+a1.toString()+a2.toString());

        Element h_= bp.getZr().newElementFromHash(h__hash,0, h__hash.length).getImmutable();
       if (h.equals(h_)){

           // System.out.println("成功");
            byte[] message = new byte[ci.length];
            for (int j = 0; j < message.length; j++){
                message[j] = (byte)(ci[j] ^ v_hash[j]);
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
        String ID = "rsuj@snnu.edu.com";
        String [] messages  =new String[] {"111","12345678","01234567890123456789","7777777777","123","1123","123","123","123","123"};
        String [] users = new String[] {"send@snnu.edu.com", "rec1@snnu.edu.com","rec2@snnu.edu.com","rec3@snnu.edu.com","rec4@snnu.edu.com","rec5@snnu.edu.com","rec6@snnu.edu.com","rec7@snnu.edu.com","rec8@snnu.edu.com","rec9@snnu.edu.com"};
        String dir = "database/data_Qiu/";
        String pairingParametersFileName = "database/data_ours/a.properties";
        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "sk.properties";
        String sk2FileName = dir + "sk2.properties";
        String signCryptFileName = dir + "signCrypt.properties";

        long start = System.currentTimeMillis();

        //Psetup(pairingParametersFileName, publicParameterFileName, mskFileName);
     // Ksetup(pairingParametersFileName,publicParameterFileName,mskFileName);

       for (int i = 0; i< users.length;i++){
          KgcKeyGen(pairingParametersFileName,publicParameterFileName,mskFileName,users[i],pkFileName,skFileName, i);
        }

      // Psetup(pairingParametersFileName,publicParameterFileName,mskFileName);

       for (int i = 0; i< users.length;i++){
           IbcKeyGen(pairingParametersFileName,publicParameterFileName,mskFileName,users[i],pkFileName,sk2FileName, i);
       }


      signCrypt(pairingParametersFileName,publicParameterFileName,sk2FileName,pkFileName,messages,users,signCryptFileName);unsignCrypt(pairingParametersFileName,publicParameterFileName,skFileName,pkFileName,users,signCryptFileName,2);
        System.out.println();
        long end = System.currentTimeMillis();
        System.out.print("运行时间为");
        System.out.println((end-start));
    }




}


