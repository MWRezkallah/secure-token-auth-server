import { generateKeyPairSync, RSAKeyPairOptions } from "crypto";
import { join } from "path";
import { writeFileSync, existsSync, mkdirSync, readFileSync } from "fs";

export const createAsymmetricKeyPair = (passphrase: string, kPath = "keys") => {
  // options for the generated asymmetric keypair
  const rsaKeyPairOptions: RSAKeyPairOptions<"pem", "pem"> = {
    modulusLength: 4096,
    publicKeyEncoding: {
      format: "pem",
      type: "spki",
    },
    privateKeyEncoding: {
      format: "pem",
      type: "pkcs8",
      cipher: "aes-256-cbc",
      passphrase: passphrase,
    },
  };

  // write the key pairs into pub.key and priv.key files
  const keysPath = join(__dirname, kPath);

  if (!existsSync(keysPath)) {
    mkdirSync(keysPath, { recursive: true });
    // generate asymmetric the key pair
    const { privateKey, publicKey } = generateKeyPairSync(
      "rsa",
      rsaKeyPairOptions
    );
    writeFileSync(join(keysPath, "pub.key"), publicKey);
    writeFileSync(join(keysPath, "priv.key"), privateKey);
    return { privateKey, publicKey };
  } else {
    const publicKey = readFileSync(join(keysPath, "pub.key")).toString();
    const privateKey = readFileSync(join(keysPath, "priv.key")).toString();
    return { privateKey, publicKey };
  }
};
