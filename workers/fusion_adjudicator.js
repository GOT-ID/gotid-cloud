import { query } from "../db/index.js";

const SIGN_WINDOW_SEC = 20; // time to wait for BLE after ANPR
const LOOP_INTERVAL_MS = 2000;

console.log("🚔 GOT-ID Fusion Worker Started...");

async function processJobs() {
  try {
    const jobs = await query(`
      SELECT *
      FROM fusion_jobs
      WHERE status = 'PENDING'
        AND due_at <= NOW()
      ORDER BY due_at ASC
      LIMIT 10
    `);

    for (const job of jobs.rows) {
      await processSingleJob(job);
    }
  } catch (err) {
    console.error("❌ Worker loop error:", err);
  }
}

async function processSingleJob(job) {
  const { id, anpr_id } = job;

  try {
    console.log(`🔍 Processing ANPR job ${anpr_id}`);

    // 1. Get ANPR event
    const anprRes = await query(
      `SELECT * FROM anpr_events WHERE id = $1 LIMIT 1`,
      [anpr_id]
    );

    if (!anprRes.rows.length) {
      await failJob(id, "ANPR event missing");
      return;
    }

    const anpr = anprRes.rows[0];

    // 2. Find matching scan within window AFTER ANPR
    const scanRes = await query(
      `
      SELECT *
      FROM scan_events
      WHERE plate = $1
        AND created_at BETWEEN $2 AND ($2 + interval '${SIGN_WINDOW_SEC} seconds')
      ORDER BY created_at ASC
      LIMIT 1
      `,
      [anpr.plate, anpr.ts]
    );

    const scan = scanRes.rows[0] || null;

    let fusion_verdict = "UNKNOWN";
    let final_label = "UNKNOWN";
    let reasons = [];

    if (!scan) {
      // 🚨 TRUE UUID MISSING
      fusion_verdict = "UUID_MISSING";
      final_label = "CLONE_MISSING_TAG_STRONG";
      reasons.push("No GOT-ID broadcast detected within window after ANPR.");
    } else {
      // ✅ USE SCANNER TRUTH
      const result = (scan.result || "").toUpperCase();

      if (result === "MATCH") {
        fusion_verdict = "MATCH";
        final_label = "MATCH_STRONG";
        reasons.push("Valid cryptographic identity confirmed.");
      } else if (result === "RELAY_SUSPECT") {
        fusion_verdict = "RELAY_SUSPECT";
        final_label = "RELAY_ATTACK";
        reasons.push("Challenge-response failed.");
      } else if (result === "REPLAY_SUSPECT") {
        fusion_verdict = "REPLAY_SUSPECT";
        final_label = "REPLAY_ATTACK";
        reasons.push("Counter rollback detected.");
      } else if (result === "INVALID_TAG") {
        fusion_verdict = "INVALID_TAG";
        final_label = "INVALID_IDENTITY";
        reasons.push("Signature invalid.");
      } else if (result === "CLONE_SUSPECT") {
        fusion_verdict = "CLONE_SUSPECT";
        final_label = "CLONED_VEHICLE";
        reasons.push("Public key mismatch.");
      } else if (result === "TAMPERED") {
        fusion_verdict = "TAMPERED";
        final_label = "TAMPER_ALERT";
        reasons.push("Tamper flag active.");
      } else {
        fusion_verdict = "UNKNOWN";
        final_label = "UNKNOWN";
        reasons.push("Unclassified scanner result.");
      }
    }

    // 3. Insert fusion result
    await query(
      `
      INSERT INTO fusion_events (
        plate,
        scan_event_id,
        anpr_id,
        fusion_verdict,
        final_label,
        reasons,
        created_at
      )
      VALUES ($1,$2,$3,$4,$5,$6,NOW())
      `,
      [
        anpr.plate,
        scan?.id ?? null,
        anpr.id,
        fusion_verdict,
        final_label,
        reasons
      ]
    );

    // 4. Mark job complete
    await query(
      `UPDATE fusion_jobs SET status='DONE', processed_at=NOW() WHERE id=$1`,
      [id]
    );

    console.log(`✅ Job ${id} complete → ${final_label}`);

  } catch (err) {
    console.error(`❌ Job ${id} failed:`, err);
    await failJob(id, err.message);
  }
}

async function failJob(id, error) {
  await query(
    `
    UPDATE fusion_jobs
    SET status='FAILED',
        attempts = attempts + 1,
        last_error = $2
    WHERE id=$1
    `,
    [id, error]
  );
}

// 🔁 Loop forever
setInterval(processJobs, LOOP_INTERVAL_MS);
