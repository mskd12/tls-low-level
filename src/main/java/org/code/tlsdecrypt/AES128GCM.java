package org.code.tlsdecrypt;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

/**
 * TLS v1.2/v1.3 AES-128-GCM
 */
public class AES128GCM {
    public static void main(String[] args) {
        // The first 8 bytes of the ciphertext should be used to construct the nonce.
        byte[] cipherBytes = Hex.decode(
                "794ba44cc4948957d9964146d5efcb358df9dfef0212f32c581127ef7cb6b994c683aa08bd77e64c4133d5637b959e90fdf1970686a51c32818c00eda962e090a742c823f1b5463373788f815840436885143295025b2e7eff11356daeec76da4730217ee35ceb8dbf9c2521eff5dc40d9ff101b047a611965b58614ad9dbf57481a2883749cabddb5563a1d263206d81c81eb4ac4e8fb68c30bd9a3d39f34e71fafa4e57741939bedb94971e89270641af2d62be4bfa324086ab4b820f7dd7244bcdeb52cd76169a0fefe6c53e4d2ba1a627185956c48c8bc0c1b7920274de9259c16f6fa4f2df1d578c99c59fe99e579716cb4ad0de4b9c52505a7d561a7e89ecd5699fa5c3e36995bf628e8bd43facc154436d1b52c21eb247e6fdd2db8bcffa5094364832514d196dcb32e5919a6d05142b24db3f3de8c1aafc19376a94ea89961792e490c");
        // "1d 31 d2 ab 2e 92 31 84 11 48 11 7f 56 2f 56 69" SERVER_WRITE
        byte[] serverWriteBytes = Hex.decode("1d31d2ab2e9231841148117f562f5669");

        byte[] AADBytes = Hex.decode("0000000000000001170303012f");
        assert AADBytes.length == 13;

        byte[] serverIVBytes = Hex.decode("4e5651eb");
        assert serverIVBytes.length == 4;
        // Nonce = Server_IV (4 bytes) || Counter (8 bytes)
        byte[] nonceBytes = new byte[12];
        for (int i=0; i<nonceBytes.length; i++) {
            nonceBytes[i] = i < serverIVBytes.length ? serverIVBytes[i] : cipherBytes[i - serverIVBytes.length];
        }

        GCMBlockCipher aesGcm = new GCMBlockCipher(new AESEngine());
        KeyParameter key = new KeyParameter(serverWriteBytes);
        AEADParameters aeadParameters = new AEADParameters(key, 128, nonceBytes, AADBytes);
        aesGcm.init(false, aeadParameters);
        // The ciphertext starts from an offset of 8 bytes
        byte[] outputBytes = new byte[aesGcm.getOutputSize(cipherBytes.length - 8)];
        int len = aesGcm.processBytes(cipherBytes, 8, cipherBytes.length - 8, outputBytes, 0);

        try {
            len += aesGcm.doFinal(outputBytes, len);
        } catch (IllegalStateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidCipherTextException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        System.out.println(new String(outputBytes));
    }
}
