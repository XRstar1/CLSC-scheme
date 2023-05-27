package ours;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
// import org.python.antlr.ast.Str;

import java.io.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Format;
import java.text.SimpleDateFormat;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class ours{




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
        Element r = bp.getZr().newRandomElement().getImmutable();
        Element R = P.powZn(r).getImmutable();
        byte [] h1_hash = sha1(id+X.toString()+R.toString()+P_pub.toString());
        Element h1 = bp.getZr().newElementFromHash(h1_hash,0,h1_hash.length).getImmutable();
        Element d = r.add(s.mul(h1)).getImmutable();




        if (P.powZn(d).equals(R.add(P_pub.powZn(h1)))){

            FileReader SkReader = new FileReader(skFile);
            FileReader PkReader = new FileReader(pkFile);

            Properties skstore = new Properties();
            skstore.load(SkReader);
            skstore.setProperty("x"+index, Base64.getEncoder().encodeToString(x.toBytes()));
            skstore.setProperty("d"+index, Base64.getEncoder().encodeToString(d.toBytes()));


            Properties pkstore = new Properties();
            pkstore.load(PkReader);
            pkstore.setProperty("X"+index, Base64.getEncoder().encodeToString(X.toBytes()));
            pkstore.setProperty("R"+index, Base64.getEncoder().encodeToString(R.toBytes()));

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

    public static void signCrypt(String pairFile, String publicFile, String skFile, String pkFile, String[] messages, String[] rec, String signCryptFile) throws NoSuchAlgorithmException, IOException {

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
        String dStr = skProp.getProperty("d0");
        Element x = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xStr)).getImmutable();
        Element d = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(dStr)).getImmutable();
        Properties pkProp = loadPropFromFile(pkFile);
        String XStr = pkProp.getProperty("X0");
        String RStr = pkProp.getProperty("R0");
        Element X = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XStr)).getImmutable();
        Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RStr)).getImmutable();


        Element t = bp.getZr().newRandomElement().getImmutable();
        Element T = P.powZn(t).getImmutable();


        for (int i=1; i< rec.length ; i++){

            String XiStr = pkProp.getProperty("X"+i);
            String RiStr = pkProp.getProperty("R"+i);
            Element Xi = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XiStr)).getImmutable();
            Element Ri = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RiStr)).getImmutable();

            byte [] h1i_hash = sha1(rec[i] + Xi.toString() +Ri.toString()+P_pub.toString());
            Element h1i = bp.getZr().newElementFromHash(h1i_hash,0,h1i_hash.length).getImmutable();

            Element Ui = Xi.add(Ri.add(P_pub.powZn(h1i))).powZn(t);

            byte[] messageByte = messages[i].getBytes();
            byte[] alpha_hash = sha1(rec[i]+Ui.toString());
            byte[] c = new byte[messageByte.length];
            for (int j = 0; j < messageByte.length; j++){
                c[j] = (byte)(messageByte[j] ^ alpha_hash[j]);
            }
            Element alphai = bp.getZr().newElementFromHash(alpha_hash,0,alpha_hash.length).getImmutable();
            byte [] h5i_hash = sha1(alphai.toString()+T.toString());
            Element ci = bp.getZr().newElementFromHash(c,0,c.length);
            Element h5i = bp.getZr().newElementFromHash(h5i_hash,0,h5i_hash.length).getImmutable();
            C.put(h5i.toString(),c);
        }

        byte [] h2_hash = sha1(rec[0]+C.toString()+X.toString()+R.toString()+T.toString());
        Element h2 = bp.getZr().newElementFromHash(h2_hash,0, h2_hash.length);
        Element v = h2.mul(x.add(d.add(t)));

        Properties sigC = new Properties();
        sigC.setProperty("T", Base64.getEncoder().encodeToString(T.toBytes()));
        sigC.setProperty("v", Base64.getEncoder().encodeToString(v.toBytes()));
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
        String diStr = skProp.getProperty("d"+index);
        Element xi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xiStr)).getImmutable();
        Element di = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(diStr)).getImmutable();

        //发送者的公钥
        Properties pkProp = loadPropFromFile(pkFile);
        String XsStr = pkProp.getProperty("X0");
        String RsStr = pkProp.getProperty("R0");
        Element Xs = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XsStr)).getImmutable();
        Element Rs = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RsStr)).getImmutable();


        //获取签密信息
        Properties sigC = loadPropFromFile(sigCryptFile);
        String TStr = sigC.getProperty("T");
        String vStr = sigC.getProperty("v");
        Element T = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TStr)).getImmutable();
        Element v = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(vStr)).getImmutable();

        Element U_ = T.powZn(xi.add(di)).getImmutable();

        byte [] alpha_hash = sha1(user[index]+U_.toString());

        Element alpha_ = bp.getZr().newElementFromHash(alpha_hash,0, alpha_hash.length);



        byte [] h5i_hash = sha1(alpha_.toString()+T.toString());
        Element h5 = bp.getZr().newElementFromHash(h5i_hash,0, h5i_hash.length);


        byte[] ci = C.get(h5.toString());


        byte[] h2_hash = sha1(user[0]+C.toString()+Xs.toString()+Rs.toString()+T.toString());
        Element h2 = bp.getZr().newElementFromHash(h2_hash,0, h2_hash.length).getImmutable();
        byte[] h1_hash = sha1(user[0]+Xs.toString()+Rs.toString()+P_pub.toString());
        Element h1 = bp.getZr().newElementFromHash(h1_hash,0, h1_hash.length).getImmutable();
        if (P.powZn(v).equals(Xs.add(Rs.add(P_pub.powZn(h1).add(T))).powZn(h2))){
            System.out.println("成功");
            byte[] message = new byte[ci.length];
            for (int j = 0; j < message.length; j++){
                message[j] = (byte)(ci[j] ^ alpha_hash[j]);
            }
            String str = new String(message,"utf-8");

            System.out.println(str);
        }else {
            System.out.println("解签密失败！");
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
        String [] messages  =new String[] {"111","12345678","01234567890123456789","7777777777","123","1123","123","123","123","123"};
        String [] users = new String[] {"send@snnu.edu.com", "rec1@snnu.edu.com","rec2@snnu.edu.com","rec3@snnu.edu.com","rec4@snnu.edu.com","rec5@snnu.edu.com","rec6@snnu.edu.com","rec7@snnu.edu.com","rec8@snnu.edu.com","rec9@snnu.edu.com"};
        String dir = "database/data_ours/";
        String pairingParametersFileName = "database/data_ours/a.properties";
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

        signCrypt(pairingParametersFileName,publicParameterFileName,skFileName,pkFileName,messages,users,signCryptFileName);
        unsignCrypt(pairingParametersFileName,publicParameterFileName,skFileName,pkFileName,users,signCryptFileName,2);
        long end = System.currentTimeMillis();
        System.out.print("运行时间为");
        System.out.println(end-start);

    }

}
