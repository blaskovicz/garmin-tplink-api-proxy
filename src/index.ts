import bodyParser from "body-parser";
import crypto from "crypto";
import dotenv from "dotenv";
import escapeHtml from "escape-html";
import express from "express";
import expressAsyncHandler from "express-async-handler";
import { readdirSync, readFileSync } from "fs";
import redis from "redis";
import tplinkCloudApi, { login } from "tplink-cloud-api";
import hs100 from "tplink-cloud-api/distribution/hs100";
import lb100 from "tplink-cloud-api/distribution/lb100";
import { promisify } from "util";
import { v4 } from "uuid";

dotenv.config();
try {
  const files = readdirSync("/var/run/secrets");
  for (const f of files) {
    const value = readFileSync(`/var/run/secrets/${f}`, { encoding: "utf8" });
    const key = f.toUpperCase();
    const prevValue = process.env[key];
    if (prevValue && prevValue !== value) {
      console.log(`[swarmed] ${key} value overridden.`);
    }
    process.env[key] = value;
  }
} catch (e) {}

const redisUrl = process.env.REDIS_URL;

const clientIdToSecret = JSON.parse(
  process.env.CLIENT_ID_TO_SECRET || '{"foo_id":"bar_secret"}'
);
const algorithm = "aes-256-ctr";
const password = process.env.CRYPTO_SECRET || "feedbeef";

// Part of https://github.com/chris-rock/node-crypto-examples
// Nodejs encryption with CTR
function encrypt(text: string): string {
  const cipher = crypto.createCipher(algorithm, password);
  let crypted = cipher.update(text, "utf8", "hex");
  crypted += cipher.final("hex");
  return crypted;
}
function decrypt(text: string): string {
  const decipher = crypto.createDecipher(algorithm, password);
  let dec = decipher.update(text, "hex", "utf8");
  dec += decipher.final("utf8");
  return dec;
}

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// GET /oauth2/authorize?redirect_uri=...&client_id=...&state=TODO&response_type=code
// <- redirect with code&state or error
app.all(
  "/oauth2/authorize",
  expressAsyncHandler(async (req: express.Request, res: express.Response) => {
    if (req.method !== "GET" && req.method !== "POST") {
      return res.status(400).json({ message: "invalid request method" });
    }

    const { redirect_uri, client_id, state, response_type } = req.query;
    const { email, password } = req.body;
    if (!client_id || !clientIdToSecret[client_id]) {
      return res.status(400).json({ message: "invalid client_id provided" });
    }
    if (
      redirect_uri !== "http://localhost" &&
      redirect_uri !== "https://localhost"
    ) {
      return res.status(400).json({ message: "invalid redirect_uri provided" });
    }
    if (response_type !== "code") {
      return res
        .status(400)
        .json({ message: "invalid response_type requested" });
    }

    let formError: string;
    let code: string;

    if (req.method === "POST") {
      try {
        const client = redis.createClient(redisUrl);
        const redisSet = promisify(client.set).bind(client);
        // login
        code = v4();
        if (!email || !password) {
          throw new Error(); // don't even bother with login
        }
        const tplink = await login(email, password, code);
        const accessToken = tplink.getToken();
        await redisSet(code, encrypt(accessToken), "EX", 300); // code valid for 5min
      } catch (e) {
        formError = "Invalid login credentials provided.";
      }
    }

    if (req.method === "GET" || formError) {
      // render login form
      res.contentType("text/html");
      res.send(`
    <html>
      <head>
        <title>TPLink Cloud Control Login</title>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
      </head>
      <body>
        <div class="container">
          <div style='border: 3px solid #f8f9fa; margin-top: 10px; padding: 5px'>
            <h3>TPLink Cloud Control Login</h3>
            <p>
              <b>Do you authorize TPLink Cloud Control to access your smart-home devices?</b>
            </p>
            <p>
              This will be used for turning on and off devices, only.
            </p>
            ${
              formError
                ? `<div class="alert alert-danger">Error! ${escapeHtml(
                    formError
                  )}</div>`
                : ""
            }
            <form method="POST">
              <div class="form-group">
                <label for="email" style="display:block">TPLink Cloud/Kasa Email</label>
                <input id="email" type="text" name="email">
              </div>
              <div class="form-group">
                <label for="password" style="display:block">TPLink Cloud/Kasa Password</label>
                <input id="password" type="password" name="password">
              </div>
              <button type="submit" class="btn btn-primary">Authorize</button>
            </form>
          </div>
        </div>
      </body>
    </html> 
    `);
    } else {
      // redirect
      res.redirect(`${redirect_uri}?state=${state || ""}&code=${code}`);
    }
  })
);

// POST /oauth2/token?grant_type=authorization_code&redirect_uri=...&client_id=...&client_secret=...&code=...
// <- response { "access_token": token, "token_type": "bearer", expires_in: null, refresh_token: null}
app.post(
  "/oauth2/token",
  expressAsyncHandler(async (req: express.Request, res: express.Response) => {
    const {
      grant_type,
      client_id,
      client_secret,
      redirect_uri,
      code
    } = req.query;
    if (
      !client_id ||
      !clientIdToSecret[client_id] ||
      clientIdToSecret[client_id] !== client_secret
    ) {
      return res
        .status(400)
        .json({ message: "invalid client_id/client_secret provided" });
    }
    if (
      redirect_uri !== "http://localhost" &&
      redirect_uri !== "https://localhost"
    ) {
      return res.status(400).json({ message: "invalid redirect_uri provided" });
    }
    if (grant_type !== "authorization_code") {
      return res.status(400).json({ message: "invalid grant_type requested" });
    }
    if (!code) {
      return res.status(400).json({ message: "invalid code provided" });
    }

    const client = redis.createClient(redisUrl);
    const redisDel = promisify(client.del).bind(client);
    const redisGet = promisify(client.get).bind(client);
    const encToken = await redisGet(code);
    if (!encToken) {
      return res.status(400).json({ message: "invalid code provided" });
    }
    redisDel(code);
    return res.json({ access_token: decrypt(encToken), token_type: "bearer" });
  })
);

app.get(
  "/api/v1/devices",
  expressAsyncHandler(async (req: express.Request, res: express.Response) => {
    const accessToken = (req.headers["authorization"] || "").split(" ")[1];
    if (!accessToken) {
      return res.status(401).json({ message: "not authenticated" });
    }

    const tplink = new tplinkCloudApi(accessToken, v4());
    const devices = await tplink.getDeviceList();
    for (const rawDevice of devices) {
      rawDevice.is_on = false;
      const device = tplink.newDevice(rawDevice);
      if (device.status !== 1) continue; // can only request status of online devices
      if (device.genericType === "bulb") {
        rawDevice.is_on = await (device as lb100).isOn();
      } else if (device.genericType === "plug") {
        rawDevice.is_on = await (device as hs100).isOn();
      }
    }
    res.json(devices);
  })
);

app.put(
  "/api/v1/devices/:id",
  expressAsyncHandler(async (req: express.Request, res: express.Response) => {
    const accessToken = (req.headers["authorization"] || "").split(" ")[1];
    if (!accessToken) {
      return res.status(401).json({ message: "not authenticated" });
    }
    if (!req.params.id) {
      return res.status(400).json({ message: "invalid device id provided" });
    }
    if (req.body.is_on === undefined || req.body.is_on == null) {
      return res
        .status(400)
        .json({ message: "unsupported update payload in request body" });
    }

    const tplink = new tplinkCloudApi(accessToken, v4());
    const device = (await tplink.getDeviceList())
      .map(d => tplink.newDevice(d))
      .find(d => d.id === req.params.id);
    if (!device) {
      return res.status(404).json({ message: "device not found" });
    }
    if (device.status !== 1) {
      return res.status(400).json({ message: "cannot update offline device" });
    }

    if (device.genericType === "bulb") {
      await (device as lb100)[req.body.is_on ? "powerOn" : "powerOff"]();
    } else if (device.genericType === "plug") {
      await (device as hs100)[req.body.is_on ? "powerOn" : "powerOff"]();
    } else {
      return res.status(501).json({ message: "not implemented" });
    }

    res.json({ message: "update successful" });
  })
);

app.listen(process.env.PORT || 3000);
