const express = require("express");
const session = require("express-session");
const path = require("path");
const dotenv = require("dotenv");
const axios = require("axios");
const Database = require("better-sqlite3");

dotenv.config();

const app = express();
const db = new Database("hotspot.db");

const PORT = process.env.PORT || 3000;
const UNIFI_BASE_URL = process.env.UNIFI_BASE_URL;
const UNIFI_USERNAME = process.env.UNIFI_USERNAME;
const UNIFI_PASSWORD = process.env.UNIFI_PASSWORD;
const UNIFI_SITE = process.env.UNIFI_SITE || "default";
const AUTHORIZE_MINUTES = parseInt(process.env.AUTHORIZE_MINUTES || "480", 10);
const SESSION_SECRET = process.env.SESSION_SECRET || "change-me";

if (process.env.TRUST_PROXY === "true") {
  app.set("trust proxy", 1);
}

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));

db.prepare(`
  CREATE TABLE IF NOT EXISTS guest_access (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    cpf TEXT NOT NULL,
    mac TEXT NOT NULL,
    ip TEXT,
    ap TEXT,
    ssid TEXT,
    accepted_terms INTEGER NOT NULL,
    created_at TEXT NOT NULL
  )
`).run();

function onlyDigits(value) {
  return (value || "").replace(/\D/g, "");
}

function normalizeMac(mac) {
  return (mac || "").trim().toLowerCase();
}

function isValidCPF(cpf) {
  cpf = onlyDigits(cpf);

  if (!cpf || cpf.length !== 11) return false;
  if (/^(\d)\1{10}$/.test(cpf)) return false;

  let sum = 0;
  for (let i = 0; i < 9; i++) {
    sum += parseInt(cpf.charAt(i), 10) * (10 - i);
  }

  let remainder = (sum * 10) % 11;
  if (remainder === 10) remainder = 0;
  if (remainder !== parseInt(cpf.charAt(9), 10)) return false;

  sum = 0;
  for (let i = 0; i < 10; i++) {
    sum += parseInt(cpf.charAt(i), 10) * (11 - i);
  }

  remainder = (sum * 10) % 11;
  if (remainder === 10) remainder = 0;
  if (remainder !== parseInt(cpf.charAt(10), 10)) return false;

  return true;
}

function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function unifiLogin() {
  const client = axios.create({
    baseURL: UNIFI_BASE_URL,
    withCredentials: true,
    validateStatus: () => true,
    httpsAgent: new (require("https").Agent)({
      rejectUnauthorized: false
    })
  });

  let response = await client.post("/api/login", {
    username: UNIFI_USERNAME,
    password: UNIFI_PASSWORD
  });

  if (response.status >= 200 && response.status < 300) {
    return client;
  }

  response = await client.post("/api/auth/login", {
    username: UNIFI_USERNAME,
    password: UNIFI_PASSWORD
  });

  if (response.status >= 200 && response.status < 300) {
    return client;
  }

  throw new Error(`Falha no login UniFi. HTTP ${response.status}`);
}

async function authorizeGuest(mac, minutes) {
  const client = await unifiLogin();

  const payload = {
    cmd: "authorize-guest",
    mac,
    minutes
  };

  let response = await client.post(`/api/s/${UNIFI_SITE}/cmd/stamgr`, payload);

  if (response.status >= 200 && response.status < 300) {
    return response.data;
  }

  response = await client.post(`/proxy/network/api/s/${UNIFI_SITE}/cmd/stamgr`, payload);

  if (response.status >= 200 && response.status < 300) {
    return response.data;
  }

  throw new Error(`Falha ao autorizar guest. HTTP ${response.status}`);
}

app.get("/", (req, res) => {
  const query = req.query || {};

  const context = {
    id: query.id || "",
    ap: query.ap || "",
    t: query.t || "",
    url: query.url || "",
    ssid: query.ssid || "",
    vlan: query.vlan || "",
    mac: query.mac || "",
    ip: query.ip || "",
    redirect: query.url || "https://www.google.com"
  };

  req.session.portalContext = context;

  const filePath = path.join(__dirname, "public", "index.html");
  let html = require("fs").readFileSync(filePath, "utf8");

  html = html
    .replaceAll("{{MAC}}", escapeHtml(context.mac))
    .replaceAll("{{IP}}", escapeHtml(context.ip))
    .replaceAll("{{SSID}}", escapeHtml(context.ssid))
    .replaceAll("{{REDIRECT}}", escapeHtml(context.redirect));

  res.send(html);
});

app.post("/login", async (req, res) => {
  try {
    const { nome, cpf, aceite } = req.body;
    const ctx = req.session.portalContext || {};

    const normalizedCPF = onlyDigits(cpf);
    const mac = normalizeMac(ctx.mac || req.body.mac);
    const ip = ctx.ip || req.ip;
    const ap = ctx.ap || "";
    const ssid = ctx.ssid || "";
    const redirectUrl = ctx.redirect || "https://www.google.com";

    if (!nome || nome.trim().length < 3) {
      return res.status(400).send("Nome inválido.");
    }

    if (!isValidCPF(normalizedCPF)) {
      return res.status(400).send("CPF inválido.");
    }

    if (aceite !== "on") {
      return res.status(400).send("É obrigatório aceitar os termos.");
    }

    if (!mac) {
      return res.status(400).send("MAC do cliente não informado pelo portal.");
    }

    db.prepare(`
      INSERT INTO guest_access
      (nome, cpf, mac, ip, ap, ssid, accepted_terms, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).run(
      nome.trim(),
      normalizedCPF,
      mac,
      ip,
      ap,
      ssid,
      1
    );

    await authorizeGuest(mac, AUTHORIZE_MINUTES);

    return res.send(`
      <!DOCTYPE html>
      <html lang="pt-BR">
      <head>
        <meta charset="UTF-8" />
        <meta http-equiv="refresh" content="2;url=${escapeHtml(redirectUrl)}" />
        <title>Acesso liberado</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            background: #f5f5f5;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
          }
          .box {
            background: #fff;
            padding: 24px;
            border-radius: 10px;
            box-shadow: 0 2px 14px rgba(0,0,0,.08);
            max-width: 420px;
            text-align: center;
          }
        </style>
      </head>
      <body>
        <div class="box">
          <h2>Acesso liberado</h2>
          <p>Seu acesso foi autorizado com sucesso.</p>
          <p>Redirecionando...</p>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    console.error(error);
    return res.status(500).send(`Erro ao liberar acesso: ${escapeHtml(error.message)}`);
  }
});

app.get("/admin/logs", (req, res) => {
  const rows = db.prepare(`
    SELECT id, nome, cpf, mac, ip, ap, ssid, accepted_terms, created_at
    FROM guest_access
    ORDER BY id DESC
    LIMIT 200
  `).all();

  let html = `
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8" />
      <title>Logs Hotspot</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 24px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; font-size: 14px; }
        th { background: #eee; }
      </style>
    </head>
    <body>
      <h1>Logs de acesso do hotspot</h1>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Nome</th>
            <th>CPF</th>
            <th>MAC</th>
            <th>IP</th>
            <th>AP</th>
            <th>SSID</th>
            <th>Aceitou termos</th>
            <th>Data/Hora</th>
          </tr>
        </thead>
        <tbody>
  `;

  for (const row of rows) {
    html += `
      <tr>
        <td>${escapeHtml(row.id)}</td>
        <td>${escapeHtml(row.nome)}</td>
        <td>${escapeHtml(row.cpf)}</td>
        <td>${escapeHtml(row.mac)}</td>
        <td>${escapeHtml(row.ip || "")}</td>
        <td>${escapeHtml(row.ap || "")}</td>
        <td>${escapeHtml(row.ssid || "")}</td>
        <td>${row.accepted_terms ? "Sim" : "Não"}</td>
        <td>${escapeHtml(row.created_at)}</td>
      </tr>
    `;
  }

  html += `
        </tbody>
      </table>
    </body>
    </html>
  `;

  res.send(html);
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://0.0.0.0:${PORT}`);
});