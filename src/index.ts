import axios from "axios";
import express, { Request, Response, NextFunction, Application } from "express";
import {
  createKeys,
  readKeys,
  encryptSecret,
  signSecret,
  verifySecret,
  decryptSecret,
} from "./util";

const app: Application = express();

app.use(express.json());

// Authority server
app.post("/api/create-keys", (req: Request, res: Response) => {
  try {
    const { passphrase } = req.body;
    const { privateKey, publicKey } = createKeys(passphrase, "keys");
    res.status(200).json({ privateKey, publicKey });
  } catch (error: any) {
    res.status(500).json({ status: "Error", message: error.message });
  }
});

app.post("/api/set-token", async (req: Request, res: Response) => {
  try {
    const { passphrase, secret, application, pin } = req.body;
    const { privateKey } = readKeys("keys");
    const cipher = encryptSecret(privateKey, passphrase, secret);
    const signature = signSecret(cipher, privateKey, passphrase);

    const { data } = await axios({
      url: "http://localhost:4000/api/token/set-manager",
      method: "POST",
      data: {
        pin,
        application,
        data: { cipher, signature },
      },
      headers: { "Content-Type": "application/json" },
    });
    res.status(200).send(data);
  } catch (error: any) {
    res.status(500).json({ status: "Error", message: error.message });
  }
});

// Client server
app.post("/api/get-token", async (req: Request, res: Response) => {
  try {
    const { cipher, signature } = req.body;
    const { publicKey } = readKeys("keys");
    const isVerified = verifySecret(cipher, publicKey, signature);
    if (!isVerified) res.status(403).send({ status: "Error", message: "Non authorized!" });
    const secret = decryptSecret(cipher, publicKey);
    res.status(201).send({"status":"Success", "message":"Authorized!", secret})
  } catch (error: any) {
    res.status(500).json({ status: "Error", message: error.message });
  }
});

app.listen(5000, () => console.log("listening on port 5000"));
