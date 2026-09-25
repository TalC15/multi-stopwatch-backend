import { PGlite } from "@electric-sql/pglite";
import { readFile } from "node:fs/promises";

export const ids = {
  company: "00000000-0000-4000-8000-000000000001",
  otherCompany: "00000000-0000-4000-8000-000000000002",
  manager: "00000000-0000-4000-8000-000000000003",
  worker: "00000000-0000-4000-8000-000000000004",
  outsider: "00000000-0000-4000-8000-000000000005",
  superadmin: "00000000-0000-4000-8000-000000000006",
  session: "00000000-0000-4000-8000-000000000007",
  personal: "00000000-0000-4000-8000-000000000008",
  deleted: "00000000-0000-4000-8000-000000000009",
  shared: "00000000-0000-4000-8000-000000000010",
  standalone: "00000000-0000-4000-8000-000000000011",
  secondManager: "00000000-0000-4000-8000-000000000012",
};

export const schema = `
  CREATE ROLE anon;
  CREATE ROLE authenticated;
  CREATE ROLE service_role;
  CREATE TABLE public.workspaces (
    id uuid PRIMARY KEY, name text NOT NULL, owner_id uuid,
    invite_code text UNIQUE
  );
  CREATE TABLE public.users (
    id uuid PRIMARY KEY, username text NOT NULL UNIQUE, pin_hash text NOT NULL,
    role text NOT NULL CHECK (role IN ('superadmin','manager','worker')),
    workspace_id uuid REFERENCES public.workspaces(id),
    telegram_chat_id text
  );
  CREATE TABLE public.sessions (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    refresh_token_hash text NOT NULL,
    revoked_at timestamptz,
    last_used_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE TABLE public.timers (
    id uuid PRIMARY KEY,
    user_id uuid REFERENCES public.users(id) ON DELETE CASCADE,
    created_by uuid REFERENCES public.users(id),
    workspace_id uuid REFERENCES public.workspaces(id) ON DELETE CASCADE,
    name text, type text CHECK (type IN ('up','down')),
    target_minutes numeric, started_at timestamptz,
    ends_at timestamptz, ended_at timestamptz,
    duration_ms bigint, accumulated_ms bigint,
    status text, record_status text CHECK (record_status IN ('active','completed','deleted')),
    is_shared boolean DEFAULT false,
    paused_count integer, is_pay boolean
  );
`;

export async function fixture(t) {
  const db = new PGlite();
  t.after(() => db.close());
  await db.exec(schema);
  await db.exec(await readFile(new URL("../../db/migrations/20260925_company_account_deactivation.sql", import.meta.url), "utf8"));
  await db.query("INSERT INTO workspaces(id,name) VALUES($1,'A'),($2,'B')", [ids.company, ids.otherCompany]);
  for (const [name, role, workspace] of [
    ["manager", "manager", ids.company],
    ["worker", "worker", ids.company],
    ["outsider", "manager", ids.otherCompany],
    ["superadmin", "superadmin", null],
  ]) {
    await db.query(
      "INSERT INTO users(id,username,pin_hash,role,workspace_id) VALUES($1,$2,'pin',$3,$4)",
      [ids[name], name, role, workspace],
    );
  }
  await db.query("UPDATE workspaces SET owner_id=$1 WHERE id=$2", [ids.manager, ids.company]);
  await db.query("INSERT INTO sessions(id,user_id,refresh_token_hash) VALUES($1,$2,'hash')", [ids.session, ids.worker]);
  return db;
}

export async function timer(db, id, opts = {}) {
  const fields = {
    id,
    user_id: ids.worker,
    created_by: ids.worker,
    workspace_id: ids.company,
    type: "up",
    target_minutes: 1,
    status: "running",
    record_status: "active",
    is_shared: false,
    accumulated_ms: 5000,
    ...opts,
  };
  const columns = Object.keys(fields);
  const values = Object.values(fields);
  await db.query(`INSERT INTO timers (${columns.join(",")}) VALUES (${columns.map((_, i) => `$${i+1}`).join(",")})`, values);
}

export async function close(db, actor = ids.manager, worker = ids.worker) {
  const { rows } = await db.query("SELECT public.keeptimer_close_company_worker($1,$2) AS result", [actor, worker]);
  return rows[0].result;
}

export async function change(db, actor, id, update = {}, remove = false) {
  const { rows } = await db.query(
    "SELECT (public.keeptimer_change_timer($1,$2,$3::jsonb,$4)).*",
    [actor, id, JSON.stringify(update), remove],
  );
  return rows[0];
}

export async function row(db, table, id) {
  const { rows } = await db.query(`SELECT * FROM ${table} WHERE id=$1`, [id]);
  return rows[0];
}
