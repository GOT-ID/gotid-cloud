// migrate.js - Professional migration runner for GOT-ID Cloud

// 1) Load environment variables from .env (same as server.js)
import "dotenv/config";

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { query } from "./db/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runMigration() {
  try {
    const sqlPath = path.join(__dirname, "sql", "001_anpr_fusion.sql");
    const sql = fs.readFileSync(sqlPath, "utf8");

    console.log("[MIGRATE] Using DATABASE_URL:", process.env.DATABASE_URL || "(not set)");
    console.log("[MIGRATE] Running 001_anpr_fusion.sql ...");
    await query(sql);
    console.log("[MIGRATE] Migration complete.");
    process.exit(0);
  } catch (err) {
    console.error("[MIGRATE] Migration failed:", err);
    process.exit(1);
  }
}

runMigration();