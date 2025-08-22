import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";


const __dirnameSecret = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_PATH = path.resolve(__dirnameSecret, "secrets.json");
const PATH = process.env.SECRETS_PATH || DEFAULT_PATH;
console.log("Путь: ", PATH)


if (!fs.existsSync(PATH)) {
  throw new Error(`secrets.json не найден: ${PATH}\nСоздай по образцу config/secrets.example.json`);
}

let raw;


try {
  raw = JSON.parse(fs.readFileSync(PATH, "utf8"));
} catch (e) {
  throw new Error(`secrets.json повреждён: ${PATH}\n${e.message}`);
}

export const secrets = Object.freeze(raw);
