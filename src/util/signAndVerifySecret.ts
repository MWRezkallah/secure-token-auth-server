import { sign, SignPrivateKeyInput, verify } from "crypto";

function signSecret(
  secret: string,
  privateKey: string,
  passphrase: string
): string {
  const data = Buffer.from(secret, "base64");
  const key: SignPrivateKeyInput = { key: privateKey, passphrase: passphrase };
  const signature = sign("SHA256", data, key).toString("base64");
  return signature;
}

function verifySecret(
  secret: string,
  publickey: string,
  signature: string
): boolean {
  const data = Buffer.from(secret, "base64");
  const signatureBuff = Buffer.from(signature, "base64");
  return verify("SHA256", data, publickey, signatureBuff);
}

export { signSecret, verifySecret };
