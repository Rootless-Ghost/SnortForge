/* ═══════════════════════════════════════════════
   SnortForge — Application JavaScript
   ═══════════════════════════════════════════════ */

// ── State ──
const state = {
    rules: [],
    selectedRows: new Set(),
    snort3Mode: false,
};

// ── DOM Ready ──
document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initBuilder();
    initManager();
    initTemplates();
    updatePreview();
});


/* ═══════════════════════════════════════════════
   TABS
   ═══════════════════════════════════════════════ */

function initTabs() {
    document.querySelectorAll(".tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
            btn.classList.add("active");
            document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
        });
    });
}

function switchTab(tabName) {
    document.querySelectorAll(".tab-btn").forEach(b => {
        b.classList.toggle("active", b.dataset.tab === tabName);
    });
    document.querySelectorAll(".tab-content").forEach(c => {
        c.classList.toggle("active", c.id === `tab-${tabName}`);
    });
}


/* ═══════════════════════════════════════════════
   RULE BUILDER
   ═══════════════════════════════════════════════ */

const BUILDER_FIELDS = [
    "action", "protocol", "direction", "src_ip", "src_port",
    "dst_ip", "dst_port", "msg", "sid", "rev", "priority",
    "classtype",
    "threshold_type", "threshold_track", "threshold_count",
    "threshold_seconds",
];

const FLOW_CHECKBOXES = [
    "flow_established", "flow_to_server", "flow_to_client",
    "flow_from_server", "flow_from_client", "flow_stateless",
    "flow_not_established",
];

const PCRE_FLAG_CHECKBOXES = [
    "pcre_flag_i", "pcre_flag_s", "pcre_flag_m", "pcre_flag_x",
];

function initBuilder() {
    // Live preview on every input change (non-content fields)
    BUILDER_FIELDS.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener("input", updatePreview);
        if (el) el.addEventListener("change", updatePreview);
    });
    FLOW_CHECKBOXES.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener("change", updatePreview);
    });
    PCRE_FLAG_CHECKBOXES.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener("change", updatePreview);
    });

    // PCRE input
    const pcreEl = document.getElementById("pcre");
    if (pcreEl) {
        pcreEl.addEventListener("input", updatePreview);
        pcreEl.addEventListener("change", updatePreview);
    }

    // Bind events on the default content block
    bindContentBlockEvents(document.querySelector('.content-block[data-index="0"]'));

    // Add Content Match button
    document.getElementById("btnAddContent").addEventListener("click", addContentBlock);

    // Button actions
    document.getElementById("btnValidate").addEventListener("click", validateRule);
    document.getElementById("btnAddToManager").addEventListener("click", addToManager);
    document.getElementById("btnCopyRule").addEventListener("click", copyRule);
    document.getElementById("btnClearForm").addEventListener("click", clearForm);

    // Snort 3 toggle
    const snort3Toggle = document.getElementById("snort3Toggle");
    if (snort3Toggle) {
        snort3Toggle.addEventListener("change", e => {
            state.snort3Mode = e.target.checked;
            document.getElementById("snort3Label").textContent = state.snort3Mode ? "Snort 3" : "Snort 2";
            updatePreview();
        });
    }

    // Performance score button
    const btnScore = document.getElementById("btnScoreRule");
    if (btnScore) {
        btnScore.addEventListener("click", scoreRule);
    }

    // Reference add/remove
    document.getElementById("btnAddRef").addEventListener("click", addReference);
    document.getElementById("ref_value").addEventListener("keydown", e => {
        if (e.key === "Enter") { e.preventDefault(); addReference(); }
    });
}

/**
 * Build the final PCRE string from the pattern input and flag checkboxes.
 * If the user already typed a full /pattern/flags format, return it as-is.
 * Otherwise, wrap the pattern with slashes and append checked flags.
 */
function buildPcreString() {
    const raw = document.getElementById("pcre").value.trim();
    if (!raw) return "";

    // Check if user already provided full /pattern/flags format
    const fullFormatMatch = raw.match(/^\/(.+)\/([ismxAEGRBUPHMCOIDKSY]*)$/);
    if (fullFormatMatch) {
        return raw; // User typed full format, respect it
    }

    // Build flags from checkboxes
    let flags = "";
    if (document.getElementById("pcre_flag_i").checked) flags += "i";
    if (document.getElementById("pcre_flag_s").checked) flags += "s";
    if (document.getElementById("pcre_flag_m").checked) flags += "m";
    if (document.getElementById("pcre_flag_x").checked) flags += "x";

    return `/${raw}/${flags}`;
}

/* ═══════════════════════════════════════════════
   MULTI-CONTENT BLOCKS
   ═══════════════════════════════════════════════ */

function bindContentBlockEvents(block) {
    block.querySelectorAll("input").forEach(el => {
        el.addEventListener("input", updatePreview);
        el.addEventListener("change", updatePreview);
    });
}

function getContentBlockCount() {
    return document.querySelectorAll("#contentMatchesContainer .content-block").length;
}

function renumberContentBlocks() {
    document.querySelectorAll("#contentMatchesContainer .content-block").forEach((block, i) => {
        block.dataset.index = i;
        block.querySelector(".content-block-label").textContent = `Content Match #${i + 1}`;
        // Only show remove button on blocks after the first
        const removeBtn = block.querySelector(".content-block-remove");
        if (removeBtn) removeBtn.style.display = i === 0 ? "none" : "";
    });
}

function addContentBlock() {
    const container = document.getElementById("contentMatchesContainer");
    const idx = getContentBlockCount();
    const block = document.createElement("div");
    block.className = "content-block";
    block.dataset.index = idx;
    block.innerHTML = `
        <div class="content-block-header">
            <span class="content-block-label">Content Match #${idx + 1}</span>
            <button type="button" class="btn btn-danger btn-xs content-block-remove" onclick="removeContentBlock(this)">✕ Remove</button>
        </div>
        <div class="form-group full-width">
            <input type="text" data-field="content" placeholder="Chained content match (matched after previous content)">
        </div>
        <div class="form-row checkbox-row">
            <label class="checkbox-label">
                <input type="checkbox" data-field="nocase">
                <span>nocase</span>
            </label>
            <label class="checkbox-label">
                <input type="checkbox" data-field="negated">
                <span>Negated (!)</span>
            </label>
            <label class="checkbox-label">
                <input type="checkbox" data-field="http_uri">
                <span>HTTP URI</span>
            </label>
            <label class="checkbox-label">
                <input type="checkbox" data-field="http_header">
                <span>HTTP Header</span>
            </label>
        </div>
        <div class="form-row four-col">
            <div class="form-group">
                <label>Depth</label>
                <input type="number" data-field="depth" value="0" min="0">
            </div>
            <div class="form-group">
                <label>Offset</label>
                <input type="number" data-field="offset" value="0" min="0">
            </div>
            <div class="form-group">
                <label>Distance</label>
                <input type="number" data-field="distance" value="0" min="0">
            </div>
            <div class="form-group">
                <label>Within</label>
                <input type="number" data-field="within" value="0" min="0">
            </div>
        </div>
    `;
    container.appendChild(block);
    bindContentBlockEvents(block);
    renumberContentBlocks();
    updatePreview();
    block.scrollIntoView({ behavior: "smooth", block: "nearest" });
    toast(`Content Match #${idx + 1} added`, "info");
}

function removeContentBlock(btn) {
    const block = btn.closest(".content-block");
    block.remove();
    renumberContentBlocks();
    updatePreview();
    toast("Content match removed", "info");
}

function getContentMatchesFromUI() {
    const matches = [];
    document.querySelectorAll("#contentMatchesContainer .content-block").forEach(block => {
        const val = (field) => {
            const el = block.querySelector(`[data-field="${field}"]`);
            if (!el) return el;
            if (el.type === "checkbox") return el.checked;
            if (el.type === "number") return parseInt(el.value) || 0;
            return el.value.trim();
        };
        const content = val("content");
        if (content) {
            matches.push({
                content: content,
                nocase: val("nocase"),
                negated: val("negated"),
                http_uri: val("http_uri"),
                http_header: val("http_header"),
                depth: val("depth"),
                offset: val("offset"),
                distance: val("distance"),
                within: val("within"),
            });
        }
    });
    return matches;
}

function clearContentBlocks() {
    const container = document.getElementById("contentMatchesContainer");
    // Remove all blocks except the first
    const blocks = container.querySelectorAll(".content-block");
    blocks.forEach((block, i) => {
        if (i > 0) block.remove();
    });
    // Clear the first block
    const first = container.querySelector(".content-block");
    if (first) {
        first.querySelectorAll("input[type='text']").forEach(el => el.value = "");
        first.querySelectorAll("input[type='number']").forEach(el => el.value = "0");
        first.querySelectorAll("input[type='checkbox']").forEach(el => el.checked = false);
    }
    renumberContentBlocks();
}

function loadContentBlocksFromData(contents) {
    const container = document.getElementById("contentMatchesContainer");
    // Clear existing
    container.innerHTML = "";

    if (!contents || contents.length === 0) {
        // Add one empty default block
        addDefaultContentBlock(container);
        renumberContentBlocks();
        return;
    }

    contents.forEach((cm, i) => {
        const block = document.createElement("div");
        block.className = "content-block";
        block.dataset.index = i;
        const removeDisplay = i === 0 ? 'style="display:none"' : '';
        block.innerHTML = `
            <div class="content-block-header">
                <span class="content-block-label">Content Match #${i + 1}</span>
                <button type="button" class="btn btn-danger btn-xs content-block-remove" onclick="removeContentBlock(this)" ${removeDisplay}>✕ Remove</button>
            </div>
            <div class="form-group full-width">
                <input type="text" data-field="content" value="${escapeAttr(cm.content || "")}">
            </div>
            <div class="form-row checkbox-row">
                <label class="checkbox-label"><input type="checkbox" data-field="nocase" ${cm.nocase ? "checked" : ""}><span>nocase</span></label>
                <label class="checkbox-label"><input type="checkbox" data-field="negated" ${cm.negated ? "checked" : ""}><span>Negated (!)</span></label>
                <label class="checkbox-label"><input type="checkbox" data-field="http_uri" ${cm.http_uri ? "checked" : ""}><span>HTTP URI</span></label>
                <label class="checkbox-label"><input type="checkbox" data-field="http_header" ${cm.http_header ? "checked" : ""}><span>HTTP Header</span></label>
            </div>
            <div class="form-row four-col">
                <div class="form-group"><label>Depth</label><input type="number" data-field="depth" value="${cm.depth || 0}" min="0"></div>
                <div class="form-group"><label>Offset</label><input type="number" data-field="offset" value="${cm.offset || 0}" min="0"></div>
                <div class="form-group"><label>Distance</label><input type="number" data-field="distance" value="${cm.distance || 0}" min="0"></div>
                <div class="form-group"><label>Within</label><input type="number" data-field="within" value="${cm.within || 0}" min="0"></div>
            </div>
        `;
        container.appendChild(block);
        bindContentBlockEvents(block);
    });
}

function addDefaultContentBlock(container) {
    const block = document.createElement("div");
    block.className = "content-block";
    block.dataset.index = "0";
    block.innerHTML = `
        <div class="content-block-header">
            <span class="content-block-label">Content Match #1</span>
        </div>
        <div class="form-group full-width">
            <input type="text" data-field="content" placeholder="String or hex content to match (e.g., |FF|SMB or SELECT * FROM)">
        </div>
        <div class="form-row checkbox-row">
            <label class="checkbox-label"><input type="checkbox" data-field="nocase"><span>Case insensitive (nocase)</span><span class="tooltip-trigger" data-tooltip="Match content regardless of uppercase or lowercase.">?</span></label>
            <label class="checkbox-label"><input type="checkbox" data-field="negated"><span>Negated match (!)</span><span class="tooltip-trigger" data-tooltip="Alert when this content is NOT found.">?</span></label>
            <label class="checkbox-label"><input type="checkbox" data-field="http_uri"><span>HTTP URI</span><span class="tooltip-trigger" data-tooltip="Only match within the HTTP request URI.">?</span></label>
            <label class="checkbox-label"><input type="checkbox" data-field="http_header"><span>HTTP Header</span><span class="tooltip-trigger" data-tooltip="Only match within HTTP headers.">?</span></label>
        </div>
        <div class="form-row four-col">
            <div class="form-group"><label>Depth</label><input type="number" data-field="depth" value="0" min="0"></div>
            <div class="form-group"><label>Offset</label><input type="number" data-field="offset" value="0" min="0"></div>
            <div class="form-group"><label>Distance</label><input type="number" data-field="distance" value="0" min="0"></div>
            <div class="form-group"><label>Within</label><input type="number" data-field="within" value="0" min="0"></div>
        </div>
    `;
    container.appendChild(block);
    bindContentBlockEvents(block);
}

function escapeAttr(str) {
    return str.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/'/g, "&#39;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function getFormData() {
    const val = id => {
        const el = document.getElementById(id);
        if (!el) return "";
        if (el.type === "checkbox") return el.checked;
        if (el.type === "number") return parseInt(el.value) || 0;
        return el.value.trim();
    };

    // Build flow string
    const flowParts = [];
    if (val("flow_established")) flowParts.push("established");
    if (val("flow_stateless")) flowParts.push("stateless");
    if (val("flow_to_server")) flowParts.push("to_server");
    if (val("flow_to_client")) flowParts.push("to_client");
    if (val("flow_from_server")) flowParts.push("from_server");
    if (val("flow_from_client")) flowParts.push("from_client");
    if (val("flow_from_client")) flowParts.push("from_client");
    if (val("flow_not_established")) flowParts.push("not_established");

    return {
        action: val("action"),
        protocol: val("protocol"),
        src_ip: val("src_ip") || "any",
        src_port: val("src_port") || "any",
        direction: val("direction"),
        dst_ip: val("dst_ip") || "any",
        dst_port: val("dst_port") || "any",
        msg: val("msg"),
        sid: val("sid"),
        rev: val("rev"),
        classtype: val("classtype"),
        priority: val("priority"),
        references: getReferences(),
        // Legacy single-content fields (empty — multi-content takes over)
        content: "",
        content_nocase: false,
        content_negated: false,
        content_http_uri: false,
        content_http_header: false,
        depth: 0,
        offset: 0,
        distance: 0,
        within: 0,
        // Multi-content
        contents: getContentMatchesFromUI(),
        pcre: buildPcreString(),
        pcre_raw: val("pcre"),
        pcre_flag_i: val("pcre_flag_i"),
        pcre_flag_s: val("pcre_flag_s"),
        pcre_flag_m: val("pcre_flag_m"),
        pcre_flag_x: val("pcre_flag_x"),
        flow: flowParts.join(","),
        threshold_type: val("threshold_type"),
        threshold_track: val("threshold_track"),
        threshold_count: val("threshold_count"),
        threshold_seconds: val("threshold_seconds"),
        metadata: "",
    };
}

function buildRuleText(data) {
    return state.snort3Mode ? buildRuleTextSnort3(data) : buildRuleTextSnort2(data);
}

function buildRuleTextSnort2(data) {
    const header = `${data.action} ${data.protocol} ${data.src_ip} ${data.src_port} ${data.direction} ${data.dst_ip} ${data.dst_port}`;

    const opts = [];
    if (data.msg) opts.push(`msg:"${data.msg}"`);
    if (data.flow) opts.push(`flow:${data.flow}`);

    // Multi-content matches
    const matches = (data.contents && data.contents.length > 0) ? data.contents :
        (data.content ? [{
            content: data.content, nocase: data.content_nocase,
            negated: data.content_negated, http_uri: data.content_http_uri,
            http_header: data.content_http_header,
            depth: data.depth, offset: data.offset,
            distance: data.distance, within: data.within,
        }] : []);

    matches.forEach(cm => {
        if (!cm.content) return;
        const prefix = cm.negated ? "!" : "";
        let cs = `content:"${prefix}${cm.content}"`;
        if (cm.nocase) cs += "; nocase";
        if (cm.http_uri) cs += "; http_uri";
        if (cm.http_header) cs += "; http_header";
        opts.push(cs);
        if (cm.depth > 0) opts.push(`depth:${cm.depth}`);
        if (cm.offset > 0) opts.push(`offset:${cm.offset}`);
        if (cm.distance > 0) opts.push(`distance:${cm.distance}`);
        if (cm.within > 0) opts.push(`within:${cm.within}`);
    });

    if (data.pcre) opts.push(`pcre:"${data.pcre}"`);
    if (data.classtype) opts.push(`classtype:${data.classtype}`);
    if (data.priority > 0) opts.push(`priority:${data.priority}`);
    if (data.references && data.references.length > 0) {
        data.references.forEach(ref => {
            if (ref) opts.push(`reference:${ref}`);
        });
    }
    if (data.metadata) opts.push(`metadata:${data.metadata}`);
    if (data.threshold_type && data.threshold_count > 0 && data.threshold_seconds > 0) {
        opts.push(`threshold:type ${data.threshold_type}, track ${data.threshold_track}, count ${data.threshold_count}, seconds ${data.threshold_seconds}`);
    }
    opts.push(`sid:${data.sid}`);
    opts.push(`rev:${data.rev}`);

    return `${header} (${opts.join("; ")};)`;
}

function buildRuleTextSnort3(data) {
    const header = `${data.action} ${data.protocol} ${data.src_ip} ${data.src_port} ${data.direction} ${data.dst_ip} ${data.dst_port}`;

    const opts = [];
    if (data.msg) opts.push(`msg:"${data.msg}"`);
    if (data.flow) opts.push(`flow:${data.flow}`);

    // Multi-content matches — Snort 3 sticky buffers
    const matches = (data.contents && data.contents.length > 0) ? data.contents :
        (data.content ? [{
            content: data.content, nocase: data.content_nocase,
            negated: data.content_negated, http_uri: data.content_http_uri,
            http_header: data.content_http_header,
            depth: data.depth, offset: data.offset,
            distance: data.distance, within: data.within,
        }] : []);

    matches.forEach(cm => {
        if (!cm.content) return;
        const prefix = cm.negated ? "!" : "";
        if (cm.http_uri) opts.push("http.uri");
        else if (cm.http_header) opts.push("http.header");
        let cs = `content:"${prefix}${cm.content}"`;
        if (cm.nocase) cs += "; nocase";
        opts.push(cs);
        if (cm.depth > 0) opts.push(`depth ${cm.depth}`);
        if (cm.offset > 0) opts.push(`offset ${cm.offset}`);
        if (cm.distance > 0) opts.push(`distance ${cm.distance}`);
        if (cm.within > 0) opts.push(`within ${cm.within}`);
    });

    if (data.pcre) opts.push(`pcre:"${data.pcre}"`);
    if (data.classtype) opts.push(`classtype:${data.classtype}`);
    if (data.priority > 0) opts.push(`priority:${data.priority}`);
    if (data.references && data.references.length > 0) {
        data.references.forEach(ref => {
            if (ref) opts.push(`reference:${ref}`);
        });
    }
    if (data.metadata) opts.push(`metadata:${data.metadata}`);
    if (data.threshold_type && data.threshold_count > 0 && data.threshold_seconds > 0) {
        opts.push(`detection_filter:track ${data.threshold_track}, count ${data.threshold_count}, seconds ${data.threshold_seconds}`);
    }
    opts.push(`sid:${data.sid}`);
    opts.push(`rev:${data.rev}`);

    return `${header} (${opts.join("; ")};)`;
}

function updatePreview() {
    const data = getFormData();
    const ruleText = buildRuleText(data);
    document.getElementById("livePreview").textContent = ruleText;
}

async function validateRule() {
    const data = getFormData();
    try {
        const resp = await fetch("/api/validate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data),
        });
        const result = await resp.json();
        showValidation(result);
    } catch (err) {
        toast("Validation request failed", "error");
    }
}

function showValidation(result) {
    const card = document.getElementById("validationCard");
    const output = document.getElementById("validationOutput");
    card.style.display = "block";

    card.classList.remove("has-errors", "is-valid");
    card.classList.add(result.is_valid ? "is-valid" : "has-errors");

    let html = "";
    result.errors.forEach(e => {
        html += `<div class="validation-item"><span class="validation-icon">✗</span><span class="validation-error">${escapeHtml(e)}</span></div>`;
    });
    result.warnings.forEach(w => {
        html += `<div class="validation-item"><span class="validation-icon">⚠</span><span class="validation-warning">${escapeHtml(w)}</span></div>`;
    });
    if (result.is_valid && result.warnings.length === 0) {
        html = `<div class="validation-item"><span class="validation-icon">✓</span><span class="validation-success">Rule is valid — no issues detected.</span></div>`;
    } else if (result.is_valid) {
        html += `<div class="validation-item"><span class="validation-icon">✓</span><span class="validation-success">Rule is valid — review warnings above.</span></div>`;
    } else {
        html += `<div class="validation-item"><span class="validation-icon">✗</span><span class="validation-error">Rule has ${result.errors.length} error(s) — fix before deploying.</span></div>`;
    }

    output.innerHTML = html;
    card.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function scoreRule() {
    const data = getFormData();
    try {
        const resp = await fetch("/api/score", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data),
        });
        const result = await resp.json();
        showScore(result);
    } catch (err) {
        toast("Score request failed", "error");
    }
}

function showScore(result) {
    const card = document.getElementById("scoreCard");
    const output = document.getElementById("scoreOutput");
    card.style.display = "block";

    // Grade color
    const gradeColors = { A: "#22c55e", B: "#84cc16", C: "#eab308", D: "#f97316", F: "#ef4444" };
    const gradeColor = gradeColors[result.grade] || "#888";

    let html = "";

    // Score header with gauge
    html += `<div class="score-header">`;
    html += `<div class="score-gauge">`;
    html += `<svg viewBox="0 0 120 120" width="100" height="100">`;
    const pct = result.score / 100;
    const dashLen = 283 * pct;
    const dashGap = 283 - dashLen;
    html += `<circle cx="60" cy="60" r="45" fill="none" stroke="var(--surface-2, #2a2a2e)" stroke-width="10"/>`;
    html += `<circle cx="60" cy="60" r="45" fill="none" stroke="${gradeColor}" stroke-width="10" stroke-dasharray="${dashLen} ${dashGap}" stroke-linecap="round" transform="rotate(-90 60 60)" style="transition:stroke-dasharray 0.6s ease"/>`;
    html += `<text x="60" y="55" text-anchor="middle" fill="${gradeColor}" font-size="28" font-weight="700" font-family="var(--font-mono, monospace)">${result.score}</text>`;
    html += `<text x="60" y="75" text-anchor="middle" fill="var(--text-muted, #888)" font-size="13" font-family="var(--font-body, sans-serif)">/ 100</text>`;
    html += `</svg>`;
    html += `</div>`;
    html += `<div class="score-grade" style="color:${gradeColor}">Grade: ${result.grade}</div>`;
    html += `</div>`;

    // Breakdown bars
    html += `<div class="score-breakdown">`;
    result.breakdown.forEach(b => {
        const barPct = b.max > 0 ? (b.score / b.max) * 100 : 0;
        const barColor = barPct >= 80 ? "#22c55e" : barPct >= 50 ? "#eab308" : "#ef4444";
        html += `<div class="score-row">`;
        html += `<span class="score-label">${escapeHtml(b.label)}</span>`;
        html += `<div class="score-bar-track"><div class="score-bar-fill" style="width:${barPct}%;background:${barColor}"></div></div>`;
        html += `<span class="score-pts">${b.score}/${b.max}</span>`;
        html += `</div>`;
        html += `<div class="score-detail">${escapeHtml(b.details)}</div>`;
    });
    html += `</div>`;

    // Tips
    if (result.tips && result.tips.length > 0) {
        html += `<div class="score-tips">`;
        html += `<h4>Optimization Tips</h4>`;
        result.tips.forEach(t => {
            html += `<div class="score-tip">💡 ${escapeHtml(t)}</div>`;
        });
        html += `</div>`;
    }

    output.innerHTML = html;
    card.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function addToManager() {
    const data = getFormData();
    if (!data.msg) {
        toast("Message is required to add a rule", "error");
        return;
    }
    state.rules.push({ ...data });
    refreshTable();
    switchTab("manager");
    toast(`Rule added — SID:${data.sid}`, "success");
}

function copyRule() {
    const data = getFormData();
    const text = buildRuleText(data);
    navigator.clipboard.writeText(text).then(() => {
        toast("Rule copied to clipboard", "success");
    }).catch(() => {
        // Fallback
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        toast("Rule copied to clipboard", "success");
    });
}

function clearForm() {
    document.getElementById("action").value = "alert";
    document.getElementById("protocol").value = "tcp";
    document.getElementById("direction").value = "->";
    document.getElementById("src_ip").value = "any";
    document.getElementById("src_port").value = "any";
    document.getElementById("dst_ip").value = "any";
    document.getElementById("dst_port").value = "any";
    document.getElementById("msg").value = "";
    document.getElementById("sid").value = "1000001";
    document.getElementById("rev").value = "1";
    document.getElementById("priority").value = "0";
    document.getElementById("classtype").value = "";
    clearReferences();
    clearContentBlocks();
    document.getElementById("pcre").value = "";
    PCRE_FLAG_CHECKBOXES.forEach(id => document.getElementById(id).checked = false);
    FLOW_CHECKBOXES.forEach(id => document.getElementById(id).checked = false);
    document.getElementById("threshold_type").value = "";
    document.getElementById("threshold_track").value = "by_src";
    document.getElementById("threshold_count").value = "0";
    document.getElementById("threshold_seconds").value = "0";
    document.getElementById("validationCard").style.display = "none";
    document.getElementById("scoreCard").style.display = "none";
    updatePreview();
    toast("Form cleared", "info");
}

function loadRuleIntoBuilder(ruleData) {
    const setVal = (id, val) => {
        const el = document.getElementById(id);
        if (!el) return;
        if (el.type === "checkbox") el.checked = !!val;
        else el.value = val ?? "";
    };

    setVal("action", ruleData.action);
    setVal("protocol", ruleData.protocol);
    setVal("direction", ruleData.direction);
    setVal("src_ip", ruleData.src_ip);
    setVal("src_port", ruleData.src_port);
    setVal("dst_ip", ruleData.dst_ip);
    setVal("dst_port", ruleData.dst_port);
    setVal("msg", ruleData.msg);
    setVal("sid", ruleData.sid);
    setVal("rev", ruleData.rev);
    setVal("priority", ruleData.priority);
    setVal("classtype", ruleData.classtype);
    loadReferences(ruleData.references || ruleData.reference || []);

    // Load content matches — multi-content or legacy single
    if (ruleData.contents && ruleData.contents.length > 0) {
        loadContentBlocksFromData(ruleData.contents);
    } else if (ruleData.content) {
        // Legacy single-content: convert to multi-content format
        loadContentBlocksFromData([{
            content: ruleData.content,
            nocase: ruleData.content_nocase || false,
            negated: ruleData.content_negated || false,
            http_uri: ruleData.content_http_uri || false,
            http_header: ruleData.content_http_header || false,
            depth: ruleData.depth || 0,
            offset: ruleData.offset || 0,
            distance: ruleData.distance || 0,
            within: ruleData.within || 0,
        }]);
    } else {
        clearContentBlocks();
    }

    // Handle PCRE — load raw pattern into input, set flag checkboxes
    if (ruleData.pcre_raw !== undefined) {
        setVal("pcre", ruleData.pcre_raw);
        setVal("pcre_flag_i", ruleData.pcre_flag_i);
        setVal("pcre_flag_s", ruleData.pcre_flag_s);
        setVal("pcre_flag_m", ruleData.pcre_flag_m);
        setVal("pcre_flag_x", ruleData.pcre_flag_x);
    } else if (ruleData.pcre) {
        const match = ruleData.pcre.match(/^\/(.+)\/([ismxAEGRBUPHMCOIDKSY]*)$/);
        if (match) {
            setVal("pcre", match[1]);
            const flags = match[2];
            setVal("pcre_flag_i", flags.includes("i"));
            setVal("pcre_flag_s", flags.includes("s"));
            setVal("pcre_flag_m", flags.includes("m"));
            setVal("pcre_flag_x", flags.includes("x"));
        } else {
            setVal("pcre", ruleData.pcre);
            PCRE_FLAG_CHECKBOXES.forEach(id => document.getElementById(id).checked = false);
        }
    } else {
        setVal("pcre", "");
        PCRE_FLAG_CHECKBOXES.forEach(id => document.getElementById(id).checked = false);
    }

    setVal("threshold_type", ruleData.threshold_type || "");
    setVal("threshold_track", ruleData.threshold_track || "by_src");
    setVal("threshold_count", ruleData.threshold_count || 0);
    setVal("threshold_seconds", ruleData.threshold_seconds || 0);

    // Flow
    const flowParts = (ruleData.flow || "").split(",").map(s => s.trim());
    setVal("flow_established", flowParts.includes("established"));
    setVal("flow_to_server", flowParts.includes("to_server"));
    setVal("flow_to_client", flowParts.includes("to_client"));
    setVal("flow_from_server", flowParts.includes("from_server"));
    setVal("flow_from_client", flowParts.includes("from_client"));
    setVal("flow_stateless", flowParts.includes("stateless"));

    document.getElementById("validationCard").style.display = "none";
    document.getElementById("scoreCard").style.display = "none";
    updatePreview();
    switchTab("builder");
}


/* ═══════════════════════════════════════════════
   RULE MANAGER
   ═══════════════════════════════════════════════ */

function initManager() {
    document.getElementById("selectAll").addEventListener("change", e => {
        const checked = e.target.checked;
        state.selectedRows.clear();
        if (checked) {
            state.rules.forEach((_, i) => state.selectedRows.add(i));
        }
        refreshTable();
    });

    document.getElementById("btnExportRules").addEventListener("click", exportRules);
    document.getElementById("btnExportJson").addEventListener("click", exportJson);
    document.getElementById("btnEditSelected").addEventListener("click", editSelected);
    document.getElementById("btnDuplicate").addEventListener("click", duplicateSelected);
    document.getElementById("btnDeleteSelected").addEventListener("click", deleteSelected);
    document.getElementById("importRulesFile").addEventListener("change", importRulesFile);
    document.getElementById("importJsonFile").addEventListener("change", importJsonFile);
}

function refreshTable() {
    const tbody = document.getElementById("rulesTableBody");
    const empty = document.getElementById("emptyState");
    const previewCard = document.getElementById("managerPreviewCard");

    document.getElementById("ruleCount").textContent = state.rules.length;

    if (state.rules.length === 0) {
        tbody.innerHTML = "";
        empty.style.display = "block";
        previewCard.style.display = "none";
        updateStats(0, 0);
        return;
    }

    empty.style.display = "none";
    let validCount = 0;
    let html = "";

    state.rules.forEach((rule, i) => {
        // Simple client-side validation check
        const hasMsg = !!rule.msg;
        const isValid = hasMsg;
        if (isValid) validCount++;

        const selected = state.selectedRows.has(i);
        html += `
            <tr class="${selected ? 'selected' : ''}" data-index="${i}">
                <td><input type="checkbox" class="row-check" data-index="${i}" ${selected ? 'checked' : ''}></td>
                <td style="font-family:var(--font-mono);font-size:0.85rem;">${rule.sid}</td>
                <td>${rule.action}</td>
                <td>${rule.protocol}</td>
                <td style="font-size:0.85rem;">${rule.src_ip}:${rule.src_port}</td>
                <td style="font-size:0.85rem;">${rule.dst_ip}:${rule.dst_port}</td>
                <td>${escapeHtml(rule.msg || '—')}</td>
                <td><span class="${isValid ? 'status-valid' : 'status-invalid'}">${isValid ? '✓ Valid' : '✗ Error'}</span></td>
            </tr>
        `;
    });

    tbody.innerHTML = html;
    updateStats(validCount, state.rules.length - validCount);

    // Row click handlers
    tbody.querySelectorAll(".row-check").forEach(cb => {
        cb.addEventListener("change", e => {
            const idx = parseInt(e.target.dataset.index);
            if (e.target.checked) state.selectedRows.add(idx);
            else state.selectedRows.delete(idx);
            refreshTable();
        });
    });

    tbody.querySelectorAll("tr").forEach(tr => {
        tr.addEventListener("click", e => {
            if (e.target.type === "checkbox") return;
            const idx = parseInt(tr.dataset.index);
            const rule = state.rules[idx];
            const text = buildRuleText(rule);
            document.getElementById("managerPreview").textContent = text;
            previewCard.style.display = "block";
        });
    });
}

function updateStats(valid, invalid) {
    document.getElementById("statTotal").textContent = state.rules.length;
    document.getElementById("statValid").textContent = valid;
    document.getElementById("statInvalid").textContent = invalid;
}

function editSelected() {
    const rows = Array.from(state.selectedRows);
    if (rows.length !== 1) {
        toast("Select exactly one rule to edit", "error");
        return;
    }
    loadRuleIntoBuilder(state.rules[rows[0]]);
    toast("Rule loaded into builder", "info");
}

function duplicateSelected() {
    const rows = Array.from(state.selectedRows).sort((a, b) => a - b);
    if (rows.length === 0) { toast("No rules selected", "error"); return; }

    const maxSid = Math.max(...state.rules.map(r => r.sid), 1000000);
    let nextSid = maxSid + 1;

    rows.forEach(idx => {
        const clone = { ...state.rules[idx], sid: nextSid++, msg: state.rules[idx].msg + " (copy)" };
        state.rules.push(clone);
    });

    state.selectedRows.clear();
    refreshTable();
    toast(`Duplicated ${rows.length} rule(s)`, "success");
}

function deleteSelected() {
    const rows = Array.from(state.selectedRows).sort((a, b) => b - a);
    if (rows.length === 0) { toast("No rules selected", "error"); return; }
    if (!confirm(`Delete ${rows.length} selected rule(s)?`)) return;

    rows.forEach(idx => state.rules.splice(idx, 1));
    state.selectedRows.clear();
    refreshTable();
    document.getElementById("managerPreviewCard").style.display = "none";
    toast(`Deleted ${rows.length} rule(s)`, "success");
}

// ── Export ──

async function exportRules() {
    if (state.rules.length === 0) { toast("No rules to export", "error"); return; }
    try {
        const resp = await fetch("/api/export/rules", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ rules: state.rules, snort3: state.snort3Mode }),
        });
        const blob = await resp.blob();
        const label = state.snort3Mode ? "snort3" : "snort2";
        downloadBlob(blob, `snortforge_${label}_rules.rules`);
        toast(`Exported ${state.rules.length} rule(s) (${state.snort3Mode ? "Snort 3" : "Snort 2"})`, "success");
    } catch (err) {
        toast("Export failed", "error");
    }
}

async function exportJson() {
    if (state.rules.length === 0) { toast("No rules to export", "error"); return; }
    try {
        const resp = await fetch("/api/export/json", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ rules: state.rules }),
        });
        const blob = await resp.blob();
        downloadBlob(blob, "snortforge_project.json");
        toast(`Exported project with ${state.rules.length} rule(s)`, "success");
    } catch (err) {
        toast("Export failed", "error");
    }
}

// ── Import ──

async function importRulesFile(e) {
    const file = e.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    try {
        const resp = await fetch("/api/import/rules", { method: "POST", body: formData });
        const result = await resp.json();
        if (result.success) {
            state.rules.push(...result.rules);
            refreshTable();
            let msg = `Imported ${result.count} rule(s)`;
            if (result.errors.length > 0) msg += ` (${result.errors.length} parse errors)`;
            toast(msg, "success");
        } else {
            toast(`Import failed: ${result.error}`, "error");
        }
    } catch (err) {
        toast("Import failed", "error");
    }
    e.target.value = "";
}

async function importJsonFile(e) {
    const file = e.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    try {
        const resp = await fetch("/api/import/json", { method: "POST", body: formData });
        const result = await resp.json();
        if (result.success) {
            state.rules.push(...result.rules);
            refreshTable();
            toast(`Imported ${result.count} rule(s) from project`, "success");
        } else {
            toast(`Import failed: ${result.error}`, "error");
        }
    } catch (err) {
        toast("Import failed", "error");
    }
    e.target.value = "";
}


/* ═══════════════════════════════════════════════
   TEMPLATES
   ═══════════════════════════════════════════════ */

function initTemplates() {
    // Category filter
    document.getElementById("templateCategory").addEventListener("change", e => {
        const cat = e.target.value;
        let visibleCount = 0;
        document.querySelectorAll(".template-card").forEach(card => {
            const show = cat === "all" || card.dataset.category === cat;
            card.style.display = show ? "" : "none";
            if (show) visibleCount++;
        });
        document.getElementById("templateCountLabel").textContent = `${visibleCount} templates available`;
    });

    // Load into builder buttons
    document.querySelectorAll(".template-load-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const ruleData = JSON.parse(btn.dataset.rule);
            loadRuleIntoBuilder(ruleData);
            toast("Template loaded into builder", "success");
        });
    });

    // Add to manager buttons
    document.querySelectorAll(".template-add-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const ruleData = JSON.parse(btn.dataset.rule);
            state.rules.push({ ...ruleData });
            refreshTable();
            toast(`Template added — SID:${ruleData.sid}`, "success");
        });
    });
}


/* ═══════════════════════════════════════════════
   REFERENCES
   ═══════════════════════════════════════════════ */

// In-memory reference list for the builder
const _refs = [];

function addReference() {
    const typeEl = document.getElementById("ref_type");
    const valueEl = document.getElementById("ref_value");
    const value = valueEl.value.trim();
    if (!value) { toast("Enter a reference value", "error"); return; }

    const ref = `${typeEl.value},${value}`;
    _refs.push(ref);
    valueEl.value = "";
    renderReferences();
    updatePreview();
}

function removeReference(index) {
    _refs.splice(index, 1);
    renderReferences();
    updatePreview();
}

function getReferences() {
    return [..._refs];
}

function clearReferences() {
    _refs.length = 0;
    renderReferences();
}

function loadReferences(refs) {
    _refs.length = 0;
    // Handle backward compat: old single string or new array
    if (typeof refs === "string" && refs) {
        _refs.push(refs);
    } else if (Array.isArray(refs)) {
        refs.forEach(r => { if (r) _refs.push(r); });
    }
    renderReferences();
}

function renderReferences() {
    const list = document.getElementById("refList");
    if (_refs.length === 0) {
        list.innerHTML = "";
        return;
    }
    const typeLabels = {
        cve: "CVE", url: "URL", bugtraq: "Bugtraq", nessus: "Nessus",
        arachnids: "Arachnids", mcafee: "McAfee", osvdb: "OSVDB",
        msb: "MSB", system: "System",
    };
    list.innerHTML = _refs.map((ref, i) => {
        const comma = ref.indexOf(",");
        const rType = comma > -1 ? ref.substring(0, comma) : ref;
        const rValue = comma > -1 ? ref.substring(comma + 1) : "";
        const label = typeLabels[rType] || rType.toUpperCase();
        return `<span class="ref-tag"><strong>${escapeHtml(label)}</strong> ${escapeHtml(rValue)}<button type="button" class="ref-remove" onclick="removeReference(${i})">✕</button></span>`;
    }).join("");
}


/* ═══════════════════════════════════════════════
   UTILITIES
   ═══════════════════════════════════════════════ */

function toast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    const icons = { success: "✓", error: "✗", info: "ℹ" };
    const el = document.createElement("div");
    el.className = `toast toast-${type}`;
    el.innerHTML = `<span>${icons[type] || "ℹ"}</span><span>${escapeHtml(message)}</span>`;
    container.appendChild(el);
    setTimeout(() => el.remove(), 3200);
}

function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}

function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}
