package org.code.tlsdecrypt;

import java.util.Arrays;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

// TLSv1.2 AES-128-CBC-HMAC
public class AES128CBC {
    public static void main(String[] args) {
        byte[] cipherBytes = Hex.decode(
                "fb51a810ad3749dbbca0a32c1cf4cfda8491ad150de39229d9f7fc9266257dba44fac3c1cd2d355385cdef9fbd2a989026e7d7a7f9dff228a10f61ef2d484cfc644866b3cb7ba291d4d630c4f9e69e8e0e8cf9d636c73ae35f1a7a5bbc890105ad1116a55416dfdc0f76eb73514730b815d4d7771b7c12970f0629c3abba9e35bf2471d3907d57a9be9892eee6e51532fc33c144f7265395df8d9b98793fa485d6db21780bc78f9b81514d53e609a57648aa357b0e8ecddaaf0753e1615f26d0195e9b84f8786e6d7a5aad70488539cff9ce5841979a669dd4c4296eb311c7c7561a599d111d2febc9e73a0ac399fd3f8afbba3ec071358d3489f0a3962c499d3afbe41c6c894f312263d57ebcb83c69928ba4b8c4a2a44dd6a61298d8988c0a457bcfa335686a757cfa2bbcc3c0856a05f2a5c11e992be43c825beb7e48802d276d1e388365ca1cb11205148c461cb36efb81def49b306492fb4e256e110e6a0f9ec58497b33a288286754383916e3b261b74e665cac514d43707e0407bfbe78e5229b71b882248b916029d444b790778b41f2898dd1d5bdbcfe1fa6f51d0c33fbdc3b7abade38873877a87b65cc1c78022a66e18dfe5ecbb7292bb826b17e8");
        byte[] serverWriteBytes = Hex.decode("42 4a 72 c5 88 e6 6f 79 2c e3 20 e6 6a dd e7 e0");
        byte[] serverIV = Hex.decode("66 4a 40 32 c7 e0 0c 30 59 8a 33 e4 57 c0 00 59");
        byte[] serverMAC = Hex.decode("c2 f4 70 0d 07 73 ab 4c 92 1f 35 43 9c 87 7d ed 20 62 94 40 ff 64 2f bb 80 55 97 ee 60 1d 04 4b");
        // Also called MAC Header
        byte[] AADBytes = Hex.decode("0000000000000001170303018d");

        CBCBlockCipher cipher = new CBCBlockCipher(new AESEngine());
        BufferedBlockCipher aesCBC = new BufferedBlockCipher(cipher);
        KeyParameter key = new KeyParameter(serverWriteBytes);
        ParametersWithIV keyWithIV = new ParametersWithIV(key, serverIV);

        // decrypt
        cipher.init(false, keyWithIV);
        byte[] outputBytes = new byte[aesCBC.getOutputSize(cipherBytes.length)];
        int len = aesCBC.processBytes(cipherBytes, 0, cipherBytes.length, outputBytes, 0);
        try {
            aesCBC.doFinal(outputBytes, len);
        } catch (DataLengthException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalStateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidCipherTextException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        // First 16 bytes are random IV (https://tools.ietf.org/html/rfc4346#section-6.2.3.2)
        // 7D B6 DF 45 87 26 C6 CC F4 5E 9A 5A 7C 27 A3 88
        outputBytes = Arrays.copyOfRange(outputBytes, 16, outputBytes.length);
        System.out.println("Size of decrypted message: " + outputBytes.length);

        // find and remove padding
        int pad = outputBytes[outputBytes.length - 1];
        System.out.println("Pad: " + pad);
        outputBytes = Arrays.copyOfRange(outputBytes, 0, outputBytes.length - pad - 1);
        System.out.println("Size of unpadded message: " + outputBytes.length);

        // extract MAC (last 32 bytes)
        byte[] message = Arrays.copyOfRange(outputBytes, 0, outputBytes.length - 32);
        byte[] macOutput = Arrays.copyOfRange(outputBytes, outputBytes.length - 32, outputBytes.length);
        System.out.println("Size of actual message (MAC removed): " + message.length);
        System.out.println(new String(message));
        System.out.println(Utils.bytesToHex(macOutput));
        
        // MAC check
        HMac mac = new HMac(new SHA256Digest());
        mac.init(new KeyParameter(serverMAC));
        byte[] outMac = new byte[mac.getMacSize()];
        mac.update(AADBytes, 0, AADBytes.length);
        mac.update(message, 0, message.length);
        mac.doFinal(outMac, 0);
        System.out.println(Utils.bytesToHex(outMac));
    }
}