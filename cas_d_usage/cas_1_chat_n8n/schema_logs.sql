-- ===========================================================================
--  Base de journalisation des executions — Assistant MITRE ATT&CK (n8n)
--  sqlite3 "C:/chemin/logs.db" < schema_logs.sql
-- ===========================================================================

PRAGMA journal_mode = WAL;

-- Un tour de chat = une ligne.
CREATE TABLE IF NOT EXISTS executions (
    execution_id              TEXT PRIMARY KEY,
    request_ts                TEXT NOT NULL,
    session_id                TEXT,
    user_id                   TEXT,
    question                  TEXT NOT NULL,
    answer                    TEXT,
    model                     TEXT,
    tokens_input              INTEGER,          -- NULL si n8n ne les expose pas
    tokens_output             INTEGER,
    started_at                TEXT,
    finished_at               TEXT,
    latency_ms                INTEGER,
    -- Indicateur central : le modele s'est-il reellement ancre ?
    mcp_used                  INTEGER NOT NULL DEFAULT 0,   -- 0 / 1
    mcp_call_count            INTEGER NOT NULL DEFAULT 0,
    mcp_tools                 TEXT,             -- JSON : ["search_techniques", ...]
    status                    TEXT,
    error_message             TEXT,
    -- Reproductibilite : release ATT&CK effectivement consultee
    mitre_release_enterprise  TEXT,
    mitre_release_ics         TEXT
);

-- Un identifiant MITRE cite par tour = une ligne.
--   relation = 'requested' : identifiant present dans les ARGUMENTS d'un appel
--                            (le modele l'a explicitement demande)
--   relation = 'related'   : identifiant apparu dans la REPONSE d'un outil ou
--                            dans la reponse finale
CREATE TABLE IF NOT EXISTS execution_mitre_ids (
    execution_id  TEXT NOT NULL,
    id_type       TEXT NOT NULL,   -- technique | tactic | mitigation | software
                                   -- | group | datasource | internal
    mitre_id      TEXT NOT NULL,
    matrix        TEXT,            -- Enterprise | ICS | NULL si indeterminable
    relation      TEXT NOT NULL DEFAULT 'requested',
    PRIMARY KEY (execution_id, mitre_id, relation),
    FOREIGN KEY (execution_id) REFERENCES executions(execution_id)
);

CREATE INDEX IF NOT EXISTS idx_exec_ts      ON executions(request_ts);
CREATE INDEX IF NOT EXISTS idx_exec_session ON executions(session_id);
CREATE INDEX IF NOT EXISTS idx_mitre_id     ON execution_mitre_ids(mitre_id);

-- ---------------------------------------------------------------------------
--  Requetes d'exploitation
-- ---------------------------------------------------------------------------

-- Taux d'utilisation effective du MCP (indicateur du chapitre 1)
--   SELECT ROUND(100.0 * SUM(mcp_used) / COUNT(*), 1) AS taux_ancrage_pct,
--          COUNT(*) AS tours
--   FROM executions;

-- Les tours ou la regle d'ancrage n'a PAS ete suivie (a auditer)
--   SELECT execution_id, request_ts, question
--   FROM executions WHERE mcp_used = 0 ORDER BY request_ts DESC;

-- Outils les plus appeles
--   SELECT value AS outil, COUNT(*) AS n
--   FROM executions, json_each(executions.mcp_tools)
--   GROUP BY outil ORDER BY n DESC;

-- Techniques les plus souvent citees
--   SELECT mitre_id, id_type, COUNT(DISTINCT execution_id) AS tours
--   FROM execution_mitre_ids GROUP BY mitre_id, id_type
--   ORDER BY tours DESC LIMIT 20;

-- Latence
--   SELECT COUNT(*) AS n, ROUND(AVG(latency_ms)) AS moy_ms,
--          MIN(latency_ms) AS min_ms, MAX(latency_ms) AS max_ms
--   FROM executions WHERE status = 'ok';

-- Coherence des releases consultees (reproductibilite d'une campagne)
--   SELECT mitre_release_enterprise, mitre_release_ics, COUNT(*) AS tours
--   FROM executions GROUP BY 1, 2;
