let meta = #{
    name: "execute-beads",
    description: "Triage with bv, polish with beads-workflow, implement via br, then compliance-verify closed work",
    when_to_use: "Execute ready/in-progress beads end-to-end with triage, polish, implementation, and compliance audit",
    phases: [
        #{ title: "Triage", detail: "br + bv health, ready queue, top picks" },
        #{ title: "Polish", detail: "beads-workflow plan-space review of actionable beads" },
        #{ title: "Execute", detail: "implement and close claimed beads" },
        #{ title: "Compliance", detail: "sample false-closed audit on closed beads" },
        #{ title: "Sync", detail: "br sync flush + handoff report" },
    ],
};

// Optional: args.max_implement = max beads to implement this run (default 1)
// Optional: args.bead_id = force a specific bead instead of triage pick
// Optional: args.skip_compliance = true to skip Phase 4 sample audit
// Optional: args.compliance_sample = number of closed beads to sample (default 8)

let max_implement = 1;
let forced_bead = ();
let skip_compliance = false;
let compliance_sample = 8;
if args != () {
    if args.max_implement != () { max_implement = args.max_implement; }
    if args.bead_id != () { forced_bead = args.bead_id; }
    if args.skip_compliance != () { skip_compliance = args.skip_compliance; }
    if args.compliance_sample != () { compliance_sample = args.compliance_sample; }
}

let triage_schema = #{
    "type": "object",
    "required": ["ready_ids", "in_progress_ids", "top_pick", "blockers_summary", "cycles_empty", "health_ok", "notes"],
    "properties": #{
        "ready_ids": #{ "type": "array", "items": #{ "type": "string" }, "maxItems": 20 },
        "in_progress_ids": #{ "type": "array", "items": #{ "type": "string" }, "maxItems": 20 },
        "top_pick": #{ "type": "string" },
        "blockers_summary": #{ "type": "string" },
        "cycles_empty": #{ "type": "boolean" },
        "health_ok": #{ "type": "boolean" },
        "notes": #{ "type": "string" },
    },
};

let polish_schema = #{
    "type": "object",
    "required": ["bead_ids_reviewed", "changes_made", "still_actionable", "summary"],
    "properties": #{
        "bead_ids_reviewed": #{ "type": "array", "items": #{ "type": "string" }, "maxItems": 20 },
        "changes_made": #{ "type": "array", "items": #{ "type": "string" }, "maxItems": 40 },
        "still_actionable": #{ "type": "array", "items": #{ "type": "string" }, "maxItems": 20 },
        "summary": #{ "type": "string" },
    },
};

let execute_schema = #{
    "type": "object",
    "required": ["bead_id", "status", "reason", "files_touched", "tests_run", "close_attempted"],
    "properties": #{
        "bead_id": #{ "type": "string" },
        "status": #{ "type": "string" },
        "reason": #{ "type": "string" },
        "files_touched": #{ "type": "array", "items": #{ "type": "string" }, "maxItems": 40 },
        "tests_run": #{ "type": "array", "items": #{ "type": "string" }, "maxItems": 20 },
        "close_attempted": #{ "type": "boolean" },
    },
};

let compliance_schema = #{
    "type": "object",
    "required": ["sampled_ids", "flagged_for_review", "false_closed_likely", "calibration_note", "summary"],
    "properties": #{
        "sampled_ids": #{ "type": "array", "items": #{ "type": "string" }, "maxItems": 30 },
        "flagged_for_review": #{ "type": "array", "items": #{ "type": "string" }, "maxItems": 30 },
        "false_closed_likely": #{ "type": "array", "items": #{ "type": "string" }, "maxItems": 20 },
        "calibration_note": #{ "type": "string" },
        "summary": #{ "type": "string" },
    },
};

let handoff_schema = #{
    "type": "object",
    "required": ["flushed", "closed_ids", "still_open_ids", "report_path", "summary"],
    "properties": #{
        "flushed": #{ "type": "boolean" },
        "closed_ids": #{ "type": "array", "items": #{ "type": "string" }, "maxItems": 20 },
        "still_open_ids": #{ "type": "array", "items": #{ "type": "string" }, "maxItems": 20 },
        "report_path": #{ "type": "string" },
        "summary": #{ "type": "string" },
    },
};

// ---------------------------------------------------------------------------
// Phase 1 — Triage (beads-br + beads-bv)
// ---------------------------------------------------------------------------
phase("Triage");
log("Phase 1: br doctor / ready / bv triage");

let triage_prompt = "";
triage_prompt += "You are the beads triage agent for the FastMCP Rust project at ";
triage_prompt += "/Users/jemanuel/projects/fastmcp_rust.\n\n";
triage_prompt += "FIRST (mandatory before any other tool use):\n";
triage_prompt += "1. Read /Users/jemanuel/projects/fastmcp_rust/AGENTS.md in full (use read_file; multiple chunks if needed).\n";
triage_prompt += "2. Read /Users/jemanuel/projects/fastmcp_rust/README.md in full.\n";
triage_prompt += "Internalize: no file deletion; no irreversible git; main not master; asupersync only (NO tokio); ";
triage_prompt += "MCP 2026-07-28 unverified; FND-01 does not claim aggregate MCP support; br never runs git; ";
triage_prompt += "bv only with --robot-*; no script-based mass code edits.\n\n";
triage_prompt += "Follow /beads-br and /beads-bv skills strictly:\n";
triage_prompt += "- ALWAYS use --json for br; NEVER run bare bv (use --robot-* only).\n";
triage_prompt += "- br NEVER runs git; do not commit.\n\n";
triage_prompt += "REQUIRED shell commands (run all of them):\n";
triage_prompt += "1. br doctor --json\n";
triage_prompt += "2. br dep cycles\n";
triage_prompt += "3. br ready --json\n";
triage_prompt += "4. br list --status=in_progress --json\n";
triage_prompt += "5. br stats --json\n";
triage_prompt += "6. bv --robot-triage\n";
triage_prompt += "7. bv --robot-next\n";
triage_prompt += "8. bv --robot-plan (summarize tracks only)\n\n";
triage_prompt += "If doctor reports unhealthy store, set health_ok=false and explain in notes.\n";
triage_prompt += "If dep cycles non-empty, set cycles_empty=false.\n";
triage_prompt += "Pick top_pick as: (a) first in_progress if any, else (b) first ready, else (c) highest ";
triage_prompt += "impact unblocked item from bv --robot-next / triage. Use empty string if nothing.\n";
if forced_bead != () {
    triage_prompt += "OVERRIDE: forced bead_id from args is ";
    triage_prompt += forced_bead;
    triage_prompt += " — set top_pick to that id if it exists.\n";
}
triage_prompt += "Return structured JSON only matching the schema. Do not implement code in this phase.";

let triage = agent(triage_prompt, #{
    label: "triage",
    capability_mode: "execute",
    output_schema: triage_schema,
});

if triage == () || triage.success == false || triage.output == () {
    complete(#{
        summary: "Triage agent failed; aborting without implementation.",
        phase_failed: "Triage",
    });
}

let top_pick = triage.output.top_pick;
let ready_ids = triage.output.ready_ids;
let in_progress_ids = triage.output.in_progress_ids;
let health_ok = triage.output.health_ok;
let cycles_empty = triage.output.cycles_empty;
log("Triage top_pick received; checking health");

if health_ok == false {
    complete(#{
        summary: "Bead store unhealthy — hand off to fixing-beads-problems before execute.",
        triage: triage.output,
    });
}
if cycles_empty == false {
    complete(#{
        summary: "Dependency cycles detected — fix graph before execute.",
        triage: triage.output,
    });
}

// Build work list: forced > in_progress > ready > top_pick
let work_ids = [];
if forced_bead != () {
    work_ids.push(forced_bead);
} else {
    if in_progress_ids != () {
        for id in in_progress_ids {
            if work_ids.len() < max_implement { work_ids.push(id); }
        }
    }
    if ready_ids != () {
        for id in ready_ids {
            let already = false;
            for w in work_ids { if w == id { already = true; } }
            if already == false && work_ids.len() < max_implement { work_ids.push(id); }
        }
    }
    if work_ids.len() == 0 && top_pick != () && top_pick != "" {
        work_ids.push(top_pick);
    }
}

if work_ids.len() == 0 {
    let report = "# Execute Beads — No Work\n\n";
    report += "Triage found no ready or in-progress beads.\n\n";
    report += "## Blockers\n\n";
    report += triage.output.blockers_summary;
    report += "\n\n## Notes\n\n";
    report += triage.output.notes;
    let path = write_scratch_file("execute-beads-report.md", report);
    complete(#{
        summary: "No actionable beads. Graph is blocked/deferred.",
        path: path,
        triage: triage.output,
    });
}

log("Work queue size=" + work_ids.len().to_string());

// ---------------------------------------------------------------------------
// Phase 2 — Polish (beads-workflow plan-space)
// ---------------------------------------------------------------------------
phase("Polish");
log("Phase 2: polish actionable beads in plan space");

let polish_prompt = "";
polish_prompt += "You are the beads-workflow polish agent for /Users/jemanuel/projects/fastmcp_rust.\n\n";
polish_prompt += "FIRST (mandatory before any bead mutations):\n";
polish_prompt += "1. Read /Users/jemanuel/projects/fastmcp_rust/AGENTS.md in full.\n";
polish_prompt += "2. Read /Users/jemanuel/projects/fastmcp_rust/README.md in full.\n";
polish_prompt += "Keep AGENTS rules fresh: no file deletion, asupersync-only, no tech-debt shims, br-only bead edits.\n\n";
polish_prompt += "Apply /beads-workflow plan-space polish to the following bead IDs ONLY:\n";
for id in work_ids {
    polish_prompt += "- ";
    polish_prompt += id;
    polish_prompt += "\n";
}
polish_prompt += "\nVerbatim polish checklist (do not oversimplify; do not drop features):\n";
polish_prompt += "Check over each bead super carefully — are you sure it makes sense? Is it optimal? ";
polish_prompt += "Could we change anything to make the system work better for users? If so, revise the beads. ";
polish_prompt += "It's a lot easier and faster to operate in plan space before implementing! ";
polish_prompt += "DO NOT OVERSIMPLIFY. DO NOT LOSE ANY FEATURES. Ensure comprehensive unit/e2e tests with detailed ";
polish_prompt += "logging are in scope. ONLY use the br CLI for bead mutations (br show, br update, br comment, ";
polish_prompt += "br dep *). Also use bv --robot-suggest and bv --robot-priority for hygiene.\n\n";
polish_prompt += "Rules:\n";
polish_prompt += "- Never hand-edit .beads JSONL/SQLite.\n";
polish_prompt += "- Never implement application code in this phase.\n";
polish_prompt += "- Never delete files.\n";
polish_prompt += "- After edits, re-run br show on each reviewed bead.\n";
polish_prompt += "- still_actionable must list beads that remain ready/in_progress and implementable now.\n";
polish_prompt += "Return structured JSON matching the schema.";

let polish = agent(polish_prompt, #{
    label: "polish",
    capability_mode: "execute",
    output_schema: polish_schema,
});

let still_actionable = work_ids;
if polish != () && polish.success && polish.output != () && polish.output.still_actionable != () {
    if polish.output.still_actionable.len() > 0 {
        still_actionable = polish.output.still_actionable;
    }
}
log("Still actionable after polish: " + still_actionable.len().to_string());

// Cap implement count again
let execute_ids = [];
for id in still_actionable {
    if execute_ids.len() < max_implement { execute_ids.push(id); }
}
if execute_ids.len() == 0 {
    complete(#{
        summary: "Polish left no actionable beads.",
        triage: triage.output,
        polish: if polish != () && polish.success { polish.output } else { () },
    });
}

// ---------------------------------------------------------------------------
// Phase 3 — Execute (implement via br lifecycle)
// ---------------------------------------------------------------------------
phase("Execute");
log("Phase 3: implement " + execute_ids.len().to_string() + " bead(s)");

let exec_jobs = [];
for id in execute_ids {
    let p = "";
    p += "You are an implementation agent for FastMCP Rust at /Users/jemanuel/projects/fastmcp_rust.\n\n";
    p += "FIRST (mandatory before implementation):\n";
    p += "1. Read /Users/jemanuel/projects/fastmcp_rust/AGENTS.md in full with read_file.\n";
    p += "2. Read /Users/jemanuel/projects/fastmcp_rust/README.md in full with read_file.\n";
    p += "Then open the bead with br show. Do not write code until both docs are read.\n\n";
    p += "Skills: /beads-br for lifecycle. Project rules from AGENTS.md + README apply:\n";
    p += "- asupersync only (NO tokio/hyper/reqwest/axum)\n";
    p += "- NEVER delete files without explicit user permission\n";
    p += "- No git reset --hard / git clean / rm -rf\n";
    p += "- Work on main only; never master\n";
    p += "- No script-based mass code transforms; edit files manually/in-place\n";
    p += "- No file proliferation (no mainV2.rs style forks)\n";
    p += "- MCP 2026-07-28 under implementation / unverified; FND-01 does not claim aggregate support\n";
    p += "- FND-01 graph: no jwt/jsonwebtoken or redis on default production edge\n";
    p += "- After code changes: cargo check --workspace --all-targets (or rch exec -- ...)\n";
    p += "- br sync --flush-only only if you close the bead; leave git commit to orchestrator/human\n\n";
    p += "TARGET BEAD: ";
    p += id;
    p += "\n\n";
    p += "COORDINATION FIRST (mandatory — Agent Mail):\n";
    p += "A. Register via mcp-agent-mail (prefer name PlumDeer if available, else auto-generate adjective+noun). ";
    p += "Project key: /Users/jemanuel/projects/fastmcp_rust\n";
    p += "B. list_agents, fetch_inbox, search_messages on thread_id=";
    p += id;
    p += " for STILL_DRIVING / HANDOFF / REHASH.\n";
    p += "C. file_reservation_paths exclusive on Owned surfaces before any edit; if exclusive conflicts, try shared observe.\n";
    p += "D. Peers may hold exclusive (CyanCedar assignee, concurrent execute-beads). Serialize via mail; never thrash.\n";
    p += "E. If conflicts exist OR another agent holds exclusive you do not hold:\n";
    p += "   - Prefer COLLABORATE not steal: status=partial or blocked; close_attempted=false if you cannot implement safely.\n";
    p += "   - Do NOT force-release, reassign, close, or overwrite Owned paths held exclusively by another agent.\n";
    p += "   - Do read-only REHASH of the three Owned digests and post findings to Agent Mail thread ";
    p += id;
    p += ".\n";
    p += "   - If exclusive expires/yields mid-session, re-claim exclusive and continue implementation.\n";
    p += "F. If YOU hold exclusive grants on all Owned paths you will edit: implement substantive residual progress.\n";
    p += "   Priority: sealed ordinary happy path (leave E_ORDINARY_EVIDENCE only when sealed/live matrix complete), B-R4 stage emission, A Ok(permit), C supply, D-final FROZEN==live, F suite green, E FND01AUTHORv2.\n";
    p += "   Keep phase_b_policy_authority_rule sentinels until full compiled authority bindings land.\n";
    p += "   Never remove E_PHASE_B_* / dual-zero dead-gate bans without completing authority.\n";
    p += "   Prefer rch exec -- cargo test -p fastmcp-rust --test fnd_01_dependency_evidence ...\n";
    p += "   Do NOT edit integrator-owned paths (Cargo.toml, oauth production, .1.1 receipts).\n";
    p += "G. Only close if ALL acceptance criteria are met: full freeze-mirror family == live, peer REHASH_PASS, ";
    p += "≥180s quiet window, no dual-zero dead gates, ordinary evidence dispatch complete, FND01AUTHORv2. Prefer partial over false close.\n";
    p += "H. send_message on thread ";
    p += id;
    p += " with progress; include PlumDeer, CyanCedar, ProudWaterfall, BeigeLynx, PlumSquirrel, BrightStork, CoralTiger in to/cc when known.\n\n";
    p += "Steps when unblocked (mandatory tool use):\n";
    p += "1. br show ";
    p += id;
    p += " --json  — read full description, acceptance_criteria, notes, ownership card.\n";
    p += "2. br update ";
    p += id;
    p += " --status in_progress  (only if not claimed by another active exclusive holder).\n";
    p += "3. Inspect owned files and existing evidence under evidence/fnd-01/ and related crates.\n";
    p += "4. Implement the bead fully per acceptance criteria — no stubs, no TODO theater.\n";
    p += "5. Run the relevant tests (prefer rch exec -- cargo test ... when available; else local cargo test).\n";
    p += "6. If ALL acceptance criteria are met with concrete proof, close:\n";
    p += "   br close ";
    p += id;
    p += " --reason \"...\"\n";
    p += "   Then br sync --flush-only\n";
    p += "7. If not complete, leave in_progress and explain remaining gaps in reason.\n\n";
    p += "For FND-01 verification child (.1.14) specifically: owned surfaces include ";
    p += "evidence/fnd-01/dependency-verification.toml, crates/fastmcp/tests/fnd_01_dependency_evidence.rs, ";
    p += "and crates/fastmcp/examples/fnd_01_evidence_harness.rs. Do not claim .1.1 or .1.15 work.\n\n";
    p += "PRIORITY HARD GATES this run (if exclusive/write access available):\n";
    p += "0. fetch_inbox on thread bd-mcp-2026-07-28-support-ahet.1.14; honor RubyBridge STILL_DRIVING exclusive if active.\n";
    p += "1. Reconfirm offline suite still PASS (D-M7 residual must stay green).\n";
    p += "2. Primary: finish ordinary B1 — clear E_ORDINARY_HANDOFF_PENDING on happy path via ";
    p += "20-tool ordinary_reprobe + ControlLedgerExpectation + OrdinaryExecutionPermit join.\n";
    p += "3. Then acquisition Ok(permit) / supply C / D-final freeze + FND01AUTHORv2 if time remains.\n";
    p += "4. Do not close unless lanes A–F freeze package complete with digests posted to Agent Mail.\n";
    p += "5. Lease-safe: exclusive on all Owned paths before edits; yield if denied; no force-release; no dual exclusive thrash.\n";
    p += "6. Prefer rch exec -- for cargo test/check. Post REHASH digests + B1 status to Agent Mail after material edits.\n\n";
    p += "Return structured JSON: status one of completed|partial|blocked|failed; list files_touched and tests_run.";

    exec_jobs.push(#{
        prompt: p,
        label: "exec:" + id,
        capability_mode: "all",
        output_schema: execute_schema,
    });
}

let exec_results = parallel(exec_jobs);

let closed_ids = [];
let still_open_ids = [];
let exec_summaries = [];
let i = 0;
for r in exec_results {
    let bid = execute_ids[i];
    if r != () && r.success && r.output != () {
        exec_summaries.push(r.output);
        if r.output.close_attempted == true && r.output.status == "completed" {
            closed_ids.push(bid);
        } else {
            still_open_ids.push(bid);
        }
    } else {
        still_open_ids.push(bid);
        exec_summaries.push(#{
            bead_id: bid,
            status: "failed",
            reason: "execute agent failed or returned unusable output",
            files_touched: [],
            tests_run: [],
            close_attempted: false,
        });
    }
    i += 1;
}
log("Execute closed=" + closed_ids.len().to_string() + " open=" + still_open_ids.len().to_string());

// ---------------------------------------------------------------------------
// Phase 4 — Compliance sample (beads-compliance-and-completion-verification)
// ---------------------------------------------------------------------------
let compliance_out = ();
if skip_compliance == false {
    phase("Compliance");
    log("Phase 4: sample compliance audit on closed beads");

    let cprompt = "";
    cprompt += "You are running a SAMPLE compliance pass for /Users/jemanuel/projects/fastmcp_rust using ";
    cprompt += "/beads-compliance-and-completion-verification.\n\n";
    cprompt += "FIRST (mandatory):\n";
    cprompt += "1. Read /Users/jemanuel/projects/fastmcp_rust/AGENTS.md in full.\n";
    cprompt += "2. Read /Users/jemanuel/projects/fastmcp_rust/README.md in full.\n";
    cprompt += "Honor no-delete / no-branch-for-audit / asupersync-only / honest MCP status claims.\n\n";
    cprompt += "HARD RULES from the skill:\n";
    cprompt += "1. NEVER create or switch git branches for the audit.\n";
    cprompt += "2. Audit artifacts live ONLY at <project>/beads_compliance_audit/ (subdir, not sibling).\n";
    cprompt += "3. Do NOT lead with raw false-closed counts — calibrate first; reframe as flagged-for-review.\n";
    cprompt += "4. Status is a claim, not a fact — re-derive from evidence.\n";
    cprompt += "5. Sample mode: do NOT audit all 290 closed beads.\n\n";
    cprompt += "Procedure:\n";
    cprompt += "A. Run br doctor --json and br stats --json.\n";
    cprompt += "B. If skill scripts exist at ~/.claude/skills/beads-compliance-and-completion-verification/scripts/, ";
    cprompt += "prefer: bash preflight.sh, then single-bead-audit or a light inventory. If scripts missing, ";
    cprompt += "do a manual sample audit.\n";
    cprompt += "C. Sample up to ";
    cprompt += compliance_sample.to_string();
    cprompt += " closed beads stratified as: (1) any beads closed in this workflow session if known: ";
    for id in closed_ids {
        cprompt += id;
        cprompt += " ";
    }
    cprompt += "; (2) high-PageRank FND-01 related closed children; (3) recent closes from br list / bv.\n";
    cprompt += "D. For each sampled bead: br show --json; locate claimed code/tests; skim for stubs/TODOs/";
    cprompt += "unimplemented; note whether acceptance criteria look truly met. Run a quick test only if cheap ";
    cprompt += "and targeted (do not full cargo test --workspace unless necessary).\n";
    cprompt += "E. Classify: verified-looking vs flagged-for-review vs false-closed-likely.\n";
    cprompt += "F. Write a short markdown under beads_compliance_audit/sample-pass-report.md if the dir is writable; ";
    cprompt += "ensure project .gitignore excludes beads_compliance_audit/ if you create it. Do not push.\n";
    cprompt += "G. calibration_note MUST remind that deterministic flags overstate true false-closed rate.\n\n";
    cprompt += "Return structured JSON only.";

    let compliance = agent(cprompt, #{
        label: "compliance-sample",
        capability_mode: "all",
        output_schema: compliance_schema,
    });
    if compliance != () && compliance.success {
        compliance_out = compliance.output;
    }
} else {
    log("Skipping compliance (args.skip_compliance=true)");
}

// ---------------------------------------------------------------------------
// Phase 5 — Sync + report
// ---------------------------------------------------------------------------
phase("Sync");
log("Phase 5: flush beads and write handoff report");

let sprompt = "";
sprompt += "You are the flush/handoff agent for /Users/jemanuel/projects/fastmcp_rust.\n\n";
sprompt += "FIRST: skim AGENTS.md beads section (br is non-invasive; you must flush explicitly; never bare bv).\n";
sprompt += "1. Run: br sync --flush-only\n";
sprompt += "2. Run: br ready --json and br list --status=in_progress --json\n";
sprompt += "3. Run: bv --robot-next (or triage quick_ref)\n";
sprompt += "4. Do NOT git commit or push unless .beads/ needs staging note only — prefer leave git to the human.\n";
sprompt += "5. Write a concise handoff markdown to beads_compliance_audit/execute-beads-handoff.md ";
sprompt += "(create parent dir if needed) summarizing triage, polish, execute outcomes, compliance sample.\n\n";
sprompt += "Known execute outcomes (JSON):\n";
sprompt += json_encode(exec_summaries);
sprompt += "\nClosed this run: ";
sprompt += json_encode(closed_ids);
sprompt += "\nStill open: ";
sprompt += json_encode(still_open_ids);
sprompt += "\nCompliance: ";
sprompt += json_encode(compliance_out);
sprompt += "\n\nReturn structured JSON: flushed true if br sync --flush-only succeeded; report_path absolute or relative; summary for operator.";

let handoff_agent = agent(sprompt, #{
    label: "flush-handoff",
    capability_mode: "all",
    output_schema: handoff_schema,
});

// Build final report for workflow UI
let report = "# Execute Beads Workflow Report\n\n";
report += "## Triage\n\n";
report += "- top_pick: ";
report += top_pick;
report += "\n- health_ok: ";
report += triage.output.health_ok.to_string();
report += "\n- cycles_empty: ";
report += triage.output.cycles_empty.to_string();
report += "\n- blockers: ";
report += triage.output.blockers_summary;
report += "\n\n## Work queue\n\n";
for id in execute_ids {
    report += "- ";
    report += id;
    report += "\n";
}
report += "\n## Execute\n\n";
report += "- closed: ";
report += json_encode(closed_ids);
report += "\n- still_open: ";
report += json_encode(still_open_ids);
report += "\n\n## Compliance\n\n";
if compliance_out != () {
    report += compliance_out.summary;
    report += "\n\nCalibration: ";
    report += compliance_out.calibration_note;
} else {
    report += "(skipped or failed)\n";
}
report += "\n\n## Flush / Handoff\n\n";
if handoff_agent != () && handoff_agent.success && handoff_agent.output != () {
    report += handoff_agent.output.summary;
} else {
    report += "handoff agent failed — run br sync --flush-only manually\n";
}

let path = write_scratch_file("execute-beads-report.md", report);

let summary = "Execute-beads finished: closed=";
summary += closed_ids.len().to_string();
summary += " open=";
summary += still_open_ids.len().to_string();

complete(#{
    summary: summary,
    path: path,
    triage: triage.output,
    polish: if polish != () && polish.success { polish.output } else { () },
    execute: exec_summaries,
    closed_ids: closed_ids,
    still_open_ids: still_open_ids,
    compliance: compliance_out,
    handoff: if handoff_agent != () && handoff_agent.success { handoff_agent.output } else { () },
});
