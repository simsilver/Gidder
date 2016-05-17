import org.apache.mina.util.Base64;
import org.apache.sshd.SshServer;
import org.apache.sshd.server.PasswordAuthenticator;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.keyprovider.AbstractGeneratorHostKeyProvider;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 *
 */
public class Main implements PasswordAuthenticator, PublickeyAuthenticator {


    public String generateSha1(String data) {
        byte[] dataBytes = data.getBytes();

        SHA1Digest sha1 = new SHA1Digest();
        sha1.reset();
        sha1.update(dataBytes, 0, dataBytes.length);

        int outputSize = sha1.getDigestSize();
        byte[] dataDigest = new byte[outputSize];

        sha1.doFinal(dataDigest, 0);

        String dataSha1 = new String(Hex.encode(dataDigest));

        return dataSha1;
    }

    @Override
    public boolean authenticate(String username, String password, ServerSession session) {
        if (password == null || "".equals(password.trim())) {
            return false;
        }

        // FIXME test
        String passwordSaved = generateSha1(username);

        String passwordSha1 = generateSha1(password);
        System.out.println("Password SHA1: " + passwordSha1);

        if (passwordSha1.equals(passwordSaved)) {
            return true;
        }

        return false;
    }

    @Override
    public boolean authenticate(String username, PublicKey key, ServerSession session) {
        if (key == null) {
            return false;
        }

        if (key instanceof RSAPublicKey) {
            try {
                String publicKey = username;

                if (publicKey == null || "".equals(publicKey.trim())) {
                    return false;
                }

                PublicKey knownkey = decodePublicKey(publicKey);
                return ((RSAPublicKey) knownkey).getModulus().equals(((RSAPublicKey) key).getModulus());

            } catch (IllegalArgumentException e) {
                System.out.println("Problem while decoding the public key.");
            } catch (NoSuchAlgorithmException e) {
                System.out.println("Problem while decoding the public key.");
            } catch (InvalidKeySpecException e) {
                System.out.println("Problem while decoding the public key.");
            }
        }

        return false;
    }

    private byte[] bytes;
    private int pos;

    private PublicKey decodePublicKey(String keystring) throws IllegalArgumentException, NoSuchAlgorithmException, InvalidKeySpecException {
        bytes = null;
        pos = 0;

        for (String part : keystring.split(" ")) {
            if (part.startsWith("AAAA")) {
                bytes = Base64.decodeBase64(part.getBytes());
                break;
            }
        }

        if (bytes == null) {
            throw new IllegalArgumentException("No Base64 part to decode.");
        }

        String type = decodeType();
        if (type.equals("ssh-rsa")) {
            BigInteger e = decodeBigInt();
            BigInteger m = decodeBigInt();
            RSAPublicKeySpec spec = new RSAPublicKeySpec(m, e);
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } else {
            throw new IllegalArgumentException("Unknown type: " + type);
        }
    }

    private String decodeType() {
        int len = decodeInt();
        String type = new String(bytes, pos, len);
        pos += len;
        return type;
    }

    private int decodeInt() {
        return ((bytes[pos++] & 0xFF) << 24) | ((bytes[pos++] & 0xFF) << 16) | ((bytes[pos++] & 0xFF) << 8) | (bytes[pos++] & 0xFF);
    }

    private BigInteger decodeBigInt() {
        int len = decodeInt();
        byte[] bigIntBytes = new byte[len];
        System.arraycopy(bytes, pos, bigIntBytes, 0, len);
        pos += len;
        return new BigInteger(bigIntBytes);
    }

    public static void main(String[] args) {
        Main main = new Main();
        AbstractGeneratorHostKeyProvider hostKeyProvider =
                new SimpleGeneratorHostKeyProvider();
        hostKeyProvider.setAlgorithm("RSA");
        SshServer sshServer = SshServer.setUpDefaultServer();
        sshServer.setPort(22);
        sshServer.setPasswordAuthenticator(main);
        sshServer.setPublickeyAuthenticator(main);
        sshServer.setKeyPairProvider(hostKeyProvider);
        try {
            sshServer.start();
            do {
                Thread.sleep(1000);
            } while (true);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
