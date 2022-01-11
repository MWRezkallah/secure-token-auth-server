import { privateEncrypt, publicDecrypt, RsaPrivateKey } from "crypto";

function encryptSecret(
  privateKey: string,
  passphrase: string,
  secret: string
): string {
  // prepare the application secret and encrypt it using the encrypted private key
  const privKey: RsaPrivateKey = {
    key: privateKey,
    passphrase: passphrase,
  };
  const secretBuf = Buffer.from(secret);
  const encryptedSecret = privateEncrypt(privKey, secretBuf).toString("base64");
  return encryptedSecret;
}

function decryptSecret(encryptedSecret: string, publicKey: string): string {
  // decrept the encrypted application secret
  const decipheredText = publicDecrypt(
    publicKey,
    Buffer.from(encryptedSecret, "base64")
  ).toString();
  return decipheredText;
}

export { encryptSecret, decryptSecret };
