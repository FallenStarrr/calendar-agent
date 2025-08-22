import express from "express";
import { google } from "googleapis";
import OpenAI from "openai";
import fs from "fs";
import crypto from "crypto";
import cookieParser from "cookie-parser";
import path from "path";
import { fileURLToPath } from "url";
import { secrets } from "./config/loadSecrets.js";


const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TOKEN_FILE = path.join(__dirname, "token_store.json");
console.log("TOKEN_FILE =>", TOKEN_FILE);


const PENDING_STATES = new Set();
const app = express();
app.use(express.json());
app.use(cookieParser());

const REDIRECT_URI = "http://localhost:3000/oauth2callback";
const GOOGLE_SCOPES = ["https://www.googleapis.com/auth/calendar.events"];
// ===================================================================

// OpenAI клиент
const openai = new OpenAI({ apiKey: secrets.openai.apiKey });

// Google OAuth2 + Calendar
const oAuth2Client = new google.auth.OAuth2(
  secrets.google.clientId,
  secrets.google.clientSecret,
  secrets.google.redirectUri
);

// in-memory токены
let ACCESS_TOKEN = null;
let ACCESS_TOKEN_EXPIRES_AT = 0;
let REFRESH_TOKEN = null;


try {
  const saved = JSON.parse(fs.readFileSync(TOKEN_FILE, "utf8"));
  ACCESS_TOKEN = saved.access_token || null;
  REFRESH_TOKEN = saved.refresh_token || null;
  ACCESS_TOKEN_EXPIRES_AT = saved.expires_at_ms || 0;
} catch {}

function persistTokens({ access_token, refresh_token, expires_in, expiry_date } = {}) {
  if (refresh_token) REFRESH_TOKEN = refresh_token;
  if (access_token) {
    ACCESS_TOKEN = access_token;
    ACCESS_TOKEN_EXPIRES_AT = expiry_date ?? (Date.now() + (expires_in ? expires_in*1000 : 3600_000) - 30_000);
  }
  const payload = {
    access_token: ACCESS_TOKEN,
    refresh_token: REFRESH_TOKEN,
    expires_at_ms: ACCESS_TOKEN_EXPIRES_AT,
    expires_at_iso: ACCESS_TOKEN_EXPIRES_AT ? new Date(ACCESS_TOKEN_EXPIRES_AT).toISOString() : null,
  };
  fs.writeFileSync(TOKEN_FILE, JSON.stringify(payload, null, 2));
}


async function ensureAccess() {
  // access ещё жив
  if (ACCESS_TOKEN && Date.now() < ACCESS_TOKEN_EXPIRES_AT) return;

  // пробуем обновиться по refresh
  if (REFRESH_TOKEN) {
    oAuth2Client.setCredentials({ refresh_token: REFRESH_TOKEN });
    const { token } = await oAuth2Client.getAccessToken(); // выдаст новый access
    if (!token) throw new Error("Не удалось обновить access_token по refresh_token");
    persistTokens({ access_token: token, expires_in: 3600 });
    return;
  }
  throw new Error("Нет валидного токена. Пройди авторизацию через /auth/start");
}

async function calendarClient() {
  await ensureAccess();
  oAuth2Client.setCredentials({
    access_token: ACCESS_TOKEN,
    refresh_token: REFRESH_TOKEN || undefined,
    expiry_date: ACCESS_TOKEN_EXPIRES_AT,
  });
  return google.calendar({ version: "v3", auth: oAuth2Client });
}

// ВСТАВЬ рядом с ensureAccess() и calendarClient()

async function authClient() {
  await ensureAccess(); // твоя функция, которая обновляет access по refresh
  oAuth2Client.setCredentials({
    access_token: ACCESS_TOKEN,
    refresh_token: REFRESH_TOKEN || undefined,
    expiry_date: ACCESS_TOKEN_EXPIRES_AT,
  });
  return oAuth2Client;
}

// ===== Маршруты авторизации =====

// 1) Удобный старт: ставит куку state и редиректит на Google
app.get("/auth/start", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  res.cookie("oauth_state", state, { httpOnly: true, sameSite: "lax", maxAge: 10 * 60 * 1000 });
  const url = oAuth2Client.generateAuthUrl({
    access_type: "offline",               // нужен refresh_token
    prompt: "consent",                    // форс вернёт refresh даже если доступ уже выдан
    include_granted_scopes: true,
    scope: GOOGLE_SCOPES,
    state,
    redirect_uri: REDIRECT_URI ,
  });
  res.redirect(url);
});

// 2) Колбэк: проверка state, обмен кода на токены, запись файла
app.get("/oauth2callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    const expected = req.cookies.oauth_state;
    if (!state || !expected || state !== expected) {
      return res.status(400).send("OAuth state mismatch/missing");
    }
    res.clearCookie("oauth_state");

    if (!code) return res.status(400).send("no code");
    const { tokens } = await oAuth2Client.getToken({
      code,
      redirect_uri: REDIRECT_URI,   // тот же URI
    });
    if (!tokens?.access_token) return res.status(400).json({ error: "no access_token", tokens });

    persistTokens(tokens);
    res.send(
      `ok`
    );
  } catch (e) {
    console.error("oauth2callback error:", e);
    res.status(500).send(String(e));
  }
});

// 3) Статус
app.get("/auth/status", (_req, res) => {
  res.json({
    hasAccessToken: Boolean(ACCESS_TOKEN),
    hasRefreshToken: Boolean(REFRESH_TOKEN),
    expiresAtISO: ACCESS_TOKEN_EXPIRES_AT ? new Date(ACCESS_TOKEN_EXPIRES_AT).toISOString() : null,
  });
});

// ===== Тест: создание события =====
app.post("/create-event", async (req, res) => {
  try {
    const { title, startISO, endISO, timezone = "Asia/Almaty", description, attendees = [], location } = req.body;
    if (!title || !startISO || !endISO) return res.status(400).json({ error: "нужны title, startISO, endISO" });

    const calendar = await calendarClient();
    const r = await calendar.events.insert({
      calendarId: "primary",
      requestBody: {
        summary: title,
        description,
        location,
        start: { dateTime: startISO, timeZone: timezone },
        end: { dateTime: endISO, timeZone: timezone },
        attendees: attendees.filter(Boolean).map(e => ({ email: String(e).trim() })),
      },
    });
    res.json({ id: r.data.id, link: r.data.htmlLink });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});


app.get("/whoami", async (_req, res) => {
  try {
    const auth = await authClient();
    const oauth2 = google.oauth2({ version: "v2", auth });
    const { data } = await oauth2.userinfo.get();
    res.json(data); // { email, name, ... }
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});



app.get("/event/:id", async (req, res) => {
  const cal = await calendarClient();
  const r = await cal.events.get({ calendarId: "primary", eventId: req.params.id });
  res.json(r.data); // смотри organizer.email, creator.email, status
});


app.get("/events/list", async (req, res) => {
  const cal = await calendarClient();
  const timeMin = req.query.timeMin || "2025-08-22T00:00:00+06:00";
  const timeMax = req.query.timeMax || "2025-08-23T00:00:00+06:00";
  const r = await cal.events.list({ calendarId: "primary", timeMin, timeMax, singleEvents: true, orderBy: "startTime" });
  res.json(r.data.items.map(e => ({ id: e.id, summary: e.summary, start: e.start, end: e.end })));
});


// ===== Health =====
app.get("/health", (_req, res) => res.json({ ok: true }));

app.listen(3000, () => console.log("http://localhost:3000"));


