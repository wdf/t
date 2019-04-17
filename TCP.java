import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Security;

public class TCP {
    public static void main(String args[]) throws Exception {
        String localhost = "127.0.0.1";
        String address = localhost;
        int port = 8333;
        int listen = 3333;
        boolean encryption = false;

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
            listen = Integer.parseInt(args[2]);
        }
        if (localhost.equals(address)) {
            encryption = true;
        }
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
                Thread server = new ThreadedTCP(connectionSocket, clientSocket, id, !encryption); //密文-明文
                Thread client = new ThreadedTCP(clientSocket, connectionSocket, id, encryption);//明文-密文
                id++;
                server.start();
                client.start();
            } catch (Exception ex) {
                if(connectionSocket.isConnected()){
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
    int counter;
    int size = 9022386;

    public ThreadedTCP(Socket from, Socket to, int c, boolean enc) {
        fromSocket = from;
        toSocket = to;
        encryption = enc;
        counter = c;
    }

    public void run() {
        try {
            InputStream in = fromSocket.getInputStream();
            OutputStream output = toSocket.getOutputStream();
            boolean complete = true;
            byte[] data = new byte[size];
            while (complete) {
                int c = in.read(data, 0, data.length);
                if (c == -1) {
                    complete = false;
                    if (toSocket.isConnected()) {
                        toSocket.close();
                    }
                    System.out.println("客户端退出");
                } else {
                    System.out.println(encryption);
                    if (encryption) {
                        data = Encryption.encryptMode(data);
                    } else {
                        data = Encryption.decryptMode(data);
                    }
                    output.write(data, 0, c);
                    output.flush();
                }
            }
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
    }

    private static void sendBytes(BufferedInputStream in, OutputStream out) throws Exception {
        int size = 9022386;
        byte[] data = new byte[size];
        int bytes = 0;
        int c = in.read(data, 0, data.length);
        out.write(data, 0, c);
        out.flush();
    }
}

class Encryption {
    static {
        Security.addProvider(new com.sun.crypto.provider.SunJCE());
    }

    static final byte[] keyBytes = {0x11, 0x22, 0x4F, 0x58,

            (byte) 0x88, 0x10, 0x40, 0x38, 0x28, 0x25, 0x79, 0x51,

            (byte) 0xCB, (byte) 0xDD, 0x55, 0x66, 0x77, 0x29, 0x74,

            (byte) 0x98, 0x30, 0x40, 0x36, (byte) 0xE2

    };
    private static final String Algorithm = "DESede"; // 定义 加密算法,可用
    // DES,DESede,Blowfish

    // keybyte为加密密钥，长度为24字节

    // src为被加密的数据缓冲区（源）
    public static byte[] encryptMode(byte[] src) {
        return encryptMode(keyBytes, src);
    }

    public static byte[] encryptMode(byte[] keyBytes, byte[] src) {

        try {

            // 生成密钥

            SecretKey deskey = new SecretKeySpec(keyBytes, Algorithm);

            // 加密

            Cipher c1 = Cipher.getInstance(Algorithm);

            c1.init(Cipher.ENCRYPT_MODE, deskey);

            return c1.doFinal(src);

        } catch (java.security.NoSuchAlgorithmException e1) {

            e1.printStackTrace();

        } catch (javax.crypto.NoSuchPaddingException e2) {

            e2.printStackTrace();

        } catch (java.lang.Exception e3) {

            e3.printStackTrace();

        }

        return null;

    }

    // keybyte为加密密钥，长度为24字节

    // src为加密后的缓冲区

    public static byte[] decryptMode(byte[] src) {
        return decryptMode(keyBytes, src);
    }

    public static byte[] decryptMode(byte[] keyBytes, byte[] src) {

        try {

            // 生成密钥

            SecretKey deskey = new SecretKeySpec(keyBytes, Algorithm);

            // 解密

            Cipher c1 = Cipher.getInstance(Algorithm);

            c1.init(Cipher.DECRYPT_MODE, deskey);

            return c1.doFinal(src);

        } catch (java.security.NoSuchAlgorithmException e1) {

            e1.printStackTrace();

        } catch (javax.crypto.NoSuchPaddingException e2) {

            e2.printStackTrace();

        } catch (java.lang.Exception e3) {

            e3.printStackTrace();

        }

        return null;

    }

    // 转换成十六进制字符串

    public static String byte2hex(byte[] b) {

        String hs = "";

        String stmp = "";

        for (int n = 0; n < b.length; n++) {

            stmp = (java.lang.Integer.toHexString(b[n] & 0XFF));

            if (stmp.length() == 1)
                hs = hs + "0" + stmp;

            else
                hs = hs + stmp;

            if (n < b.length - 1)
                hs = hs + ":";

        }

        return hs.toUpperCase();

    }

}