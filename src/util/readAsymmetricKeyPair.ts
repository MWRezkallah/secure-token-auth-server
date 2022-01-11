import { join } from "path";
import { readFileSync } from "fs";

export const readAsymmetricKeyPair = (kpath="keys") => {
  const keysPath = join(__dirname, kpath);
  const pubKey = readFileSync(join(keysPath, "pub.key")).toString();
  const privKey = readFileSync(join(keysPath, "priv.key")).toString();

  return { publicKey: pubKey, privateKey: privKey };
};
