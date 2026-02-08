/* ═══════════════════════════════════════════════
   SnortForge — Application JavaScript
   ═══════════════════════════════════════════════ */

// ── State ──
const state = {
    rules: [],
    selectedRows: new Set(),
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
    "classtype", "reference", "content", "content_nocase",
    "content_negated", "depth", "offset", "distance", "within",
    "pcre", "threshold_type", "threshold_track", "threshold_count",
    "threshold_seconds",
];

const FLOW_CHECKBOXES = [
    "flow_established", "flow_to_server", "flow_to_client",
    "flow_from_server", "flow_from_client", "flow_stateless",
];

function initBuilder() {
    // Live preview on every input change
    BUILDER_FIELDS.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener("input", updatePreview);
        if (el) el.addEventListener("change", updatePreview);
    });
    FLOW_CHECKBOXES.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener("change", updatePreview);
    });

    // Button actions
    document.getElementById("btnValidate").addEventListener("click", validateRule);
    document.getElementById("btnAddToManager").addEventListener("click", addToManager);
    document.getElementById("btnCopyRule").addEventListener("click", copyRule);
    document.getElementById("btnClearForm").addEventListener("click", clearForm);
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
        reference: val("reference"),
        content: val("content"),
        content_nocase: val("content_nocase"),
        content_negated: val("content_negated"),
        pcre: val("pcre"),
        depth: val("depth"),
        offset: val("offset"),
        distance: val("distance"),
        within: val("within"),
        flow: flowParts.join(","),
        threshold_type: val("threshold_type"),
        threshold_track: val("threshold_track"),
        threshold_count: val("threshold_count"),
        threshold_seconds: val("threshold_seconds"),
        metadata: "",
    };
}

function buildRuleText(data) {
    const header = `${data.action} ${data.protocol} ${data.src_ip} ${data.src_port} ${data.direction} ${data.dst_ip} ${data.dst_port}`;

    const opts = [];
    if (data.msg) opts.push(`msg:"${data.msg}"`);
    if (data.flow) opts.push(`flow:${data.flow}`);
    if (data.content) {
        const prefix = data.content_negated ? "!" : "";
        let cs = `content:"${prefix}${data.content}"`;
        if (data.content_nocase) cs += "; nocase";
        opts.push(cs);
    }
    if (data.depth > 0) opts.push(`depth:${data.depth}`);
    if (data.offset > 0) opts.push(`offset:${data.offset}`);
    if (data.distance > 0) opts.push(`distance:${data.distance}`);
    if (data.within > 0) opts.push(`within:${data.within}`);
    if (data.pcre) opts.push(`pcre:"${data.pcre}"`);
    if (data.classtype) opts.push(`classtype:${data.classtype}`);
    if (data.priority > 0) opts.push(`priority:${data.priority}`);
    if (data.reference) opts.push(`reference:${data.reference}`);
    if (data.metadata) opts.push(`metadata:${data.metadata}`);
    if (data.threshold_type && data.threshold_count > 0 && data.threshold_seconds > 0) {
        opts.push(`threshold:type ${data.threshold_type}, track ${data.threshold_track}, count ${data.threshold_count}, seconds ${data.threshold_seconds}`);
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
    document.getElementById("reference").value = "";
    document.getElementById("content").value = "";
    document.getElementById("content_nocase").checked = false;
    document.getElementById("content_negated").checked = false;
    document.getElementById("depth").value = "0";
    document.getElementById("offset").value = "0";
    document.getElementById("distance").value = "0";
    document.getElementById("within").value = "0";
    document.getElementById("pcre").value = "";
    FLOW_CHECKBOXES.forEach(id => document.getElementById(id).checked = false);
    document.getElementById("threshold_type").value = "";
    document.getElementById("threshold_track").value = "by_src";
    document.getElementById("threshold_count").value = "0";
    document.getElementById("threshold_seconds").value = "0";
    document.getElementById("validationCard").style.display = "none";
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
    setVal("reference", ruleData.reference || "");
    setVal("content", ruleData.content);
    setVal("content_nocase", ruleData.content_nocase);
    setVal("content_negated", ruleData.content_negated);
    setVal("depth", ruleData.depth);
    setVal("offset", ruleData.offset);
    setVal("distance", ruleData.distance);
    setVal("within", ruleData.within);
    setVal("pcre", ruleData.pcre || "");
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
            body: JSON.stringify({ rules: state.rules }),
        });
        const blob = await resp.blob();
        downloadBlob(blob, "snortforge_rules.rules");
        toast(`Exported ${state.rules.length} rule(s)`, "success");
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
