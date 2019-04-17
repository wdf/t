import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class TCP {
    public static void main(String args[]) throws Exception {
        String localhost = "127.0.0.1";
        String address = localhost;
        int port = 8333;
        int listen = 3333;
        byte[] key = new byte[] { 49, 38, -88, -75, 103, -50, 94, -92 };
        boolean encryption = false;

//        args = new String[]{"127.0.0.1:8443"};
//        args = new String[]{"8333", "8443"};

        if (args.length > 0) {
            String[] as = args[0].split(":");
            encryption = as.length > 1;
            if (encryption) {
                address = as[0];
                port = Integer.parseInt(as[1]);
            } else {
                port = Integer.parseInt(as[0]);
            }
        }
        if (args.length > 1) {
            listen = Integer.parseInt(args[1]);
        }
//        if (localhost.equals(address)) {
//            encryption = true;
//        }
        if (port == listen) {
            System.out.println("port and listen equals");
            return;
        }

        ServerSocket serverSocket = new ServerSocket(listen);

        int id = 1;
        while (true) {
            Socket connectionSocket = serverSocket.accept();
            try {
                System.out.println("客户端：" + connectionSocket.getInetAddress().getHostName() + " - " + id);
                Socket clientSocket = new Socket(address, port);
                Thread server = new ThreadedTCP(connectionSocket, clientSocket, id, encryption,key); //密文-明文
                Thread client = new ThreadedTCP(clientSocket, connectionSocket, id, !encryption,key);//明文-密文
                id++;
                server.start();
                client.start();
            } catch (Exception ex) {
                if (connectionSocket.isConnected()) {
                    connectionSocket.close();
                }
            }
        }
    }
}

class ThreadedTCP extends Thread {
    boolean encryption;
    Socket fromSocket;
    Socket toSocket;
    byte[] key;
    int counter;
    int size = 10240;

    public ThreadedTCP(Socket from, Socket to, int c, boolean enc,byte[] k) {
        fromSocket = from;
        toSocket = to;
        encryption = enc;
        counter = c;
        key = k;
    }

    public void run() {
        try {
            InputStream in = fromSocket.getInputStream();
            OutputStream out = toSocket.getOutputStream();
            boolean complete = true;
            byte[] data = new byte[size];
            if (encryption) {
                System.out.println("加密");
                Encryption.encrypt(in,out,key);
            } else {
                System.out.println("解密");
                Encryption.decrypt(in,out,key);
            }
            System.out.println("客户端退出");
            if (toSocket.isConnected()) {
                toSocket.close();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.println("error:"+ex.getMessage());
        }
    }

    private static void sendBytes(BufferedInputStream in, OutputStream out) throws Exception {
        int size = 10240;
        byte[] data = new byte[size];
        int bytes = 0;
        int c = in.read(data, 0, data.length);
        out.write(data, 0, c);
        out.flush();
    }
}

class Encryption {
    private static String Algorithm = "DES";
    public static byte[] getKey() throws Exception {
        KeyGenerator keygen = KeyGenerator.getInstance(Algorithm);
        keygen.init(new SecureRandom());
        SecretKey deskey = keygen.generateKey();
        return deskey.getEncoded();
    }
    public static void encrypt(InputStream in , OutputStream out, byte[] key)
            throws Exception {
        // 秘密（对称）密钥(SecretKey继承(key))
        // 根据给定的字节数组构造一个密钥。
        SecretKey deskey = new SecretKeySpec(key, Algorithm);
        // 生成一个实现指定转换的 Cipher 对象。Cipher对象实际完成加解密操作
        Cipher c = Cipher.getInstance(Algorithm);
        // 用密钥初始化此 cipher
        c.init(Cipher.ENCRYPT_MODE, deskey);

        byte[] buffer = new byte[10240];

        CipherInputStream cin = new CipherInputStream(in, c);
        int i;
        while ((i = cin.read(buffer)) != -1) {
            out.write(buffer, 0, i);
        }
        out.close();
        cin.close();
    }

    // 解密
    public static void decrypt(InputStream in , OutputStream out, byte[] key)
            throws Exception {

        // DES算法要求有一个可信任的随机数源
        SecureRandom sr = new SecureRandom();
        // 创建一个 DESKeySpec 对象,指定一个 DES 密钥
        DESKeySpec ks = new DESKeySpec(key);
        // 生成指定秘密密钥算法的 SecretKeyFactory 对象。
        SecretKeyFactory factroy = SecretKeyFactory.getInstance(Algorithm);
        // 根据提供的密钥规范（密钥材料）生成 SecretKey 对象,利用密钥工厂把DESKeySpec转换成一个SecretKey对象
        SecretKey sk = factroy.generateSecret(ks);
        // 生成一个实现指定转换的 Cipher 对象。Cipher对象实际完成加解密操作
        Cipher c = Cipher.getInstance(Algorithm);
        // 用密钥和随机源初始化此 cipher
        c.init(Cipher.DECRYPT_MODE, sk, sr);

        byte[] buffer = new byte[1024];
        CipherOutputStream cout = new CipherOutputStream(out, c);
        int i;
        while ((i = in.read(buffer)) != -1) {
            cout.write(buffer, 0, i);
        }
        cout.close();
        in.close();
    }


}
