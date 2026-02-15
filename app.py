"""
SnortForge — Flask Web Application
Snort IDS/IPS Rule Generator & Management Tool
"""

import json
import os
import tempfile
from datetime import datetime
from flask import (
    Flask, render_template, request, jsonify, send_file, session
)
from snortforge.core.rule import SnortRule
from snortforge.core.validator import validate_rule
from snortforge.core.templates_data import (
    get_templates_json, get_template_categories, load_template, TEMPLATES
)
from snortforge.core.parser import parse_rule, parse_rules_file, ParseError

app = Flask(
    __name__,
    template_folder="snortforge/templates",
    static_folder="snortforge/static",
)
app.secret_key = os.urandom(24)


# ── Pages ──

@app.route("/")
def index():
    templates = get_templates_json()
    categories = get_template_categories()
    return render_template("index.html", templates=templates, categories=categories)


# ── API: Build Rule ──

@app.route("/api/build", methods=["POST"])
def api_build():
    data = request.get_json()
    try:
        rule = SnortRule.from_dict(data)
        return jsonify({"success": True, "rule_text": rule.build()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


# ── API: Validate Rule ──

@app.route("/api/validate", methods=["POST"])
def api_validate():
    data = request.get_json()
    try:
        rule = SnortRule.from_dict(data)
        result = validate_rule(rule)
        result["rule_text"] = rule.build()
        return jsonify(result)
    except Exception as e:
        return jsonify({"is_valid": False, "errors": [str(e)], "warnings": []}), 400


# ── API: Get Templates ──

@app.route("/api/templates")
def api_templates():
    category = request.args.get("category", "all")
    templates = get_templates_json()
    if category and category != "all":
        templates = [t for t in templates if t["category"] == category]
    return jsonify(templates)


@app.route("/api/templates/<name>")
def api_template_detail(name):
    if name not in TEMPLATES:
        return jsonify({"error": "Template not found"}), 404
    rule = load_template(name)
    data = TEMPLATES[name]
    return jsonify({
        "name": name,
        "category": data["category"],
        "description": data["description"],
        "rule_text": rule.build(),
        "rule_data": rule.to_dict(),
    })


# ── API: Export Rules ──

@app.route("/api/export/rules", methods=["POST"])
def api_export_rules():
    data = request.get_json()
    rules_data = data.get("rules", [])
    if not rules_data:
        return jsonify({"error": "No rules to export"}), 400

    lines = [
        f"# {'═' * 55}",
        f"# SnortForge — Generated Rules",
        f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Total Rules: {len(rules_data)}",
        f"# {'═' * 55}",
        "",
    ]
    for rd in rules_data:
        rule = SnortRule.from_dict(rd)
        lines.append(rule.build())

    content = "\n".join(lines) + "\n"

    tmp = tempfile.NamedTemporaryFile(
        mode='w', suffix='.rules', delete=False, prefix='snortforge_'
    )
    tmp.write(content)
    tmp.close()

    return send_file(
        tmp.name,
        as_attachment=True,
        download_name="snortforge_rules.rules",
        mimetype="text/plain",
    )


@app.route("/api/export/json", methods=["POST"])
def api_export_json():
    data = request.get_json()
    rules_data = data.get("rules", [])

    project = {
        "snortforge_version": "1.0.0",
        "exported": datetime.now().isoformat(),
        "rule_count": len(rules_data),
        "rules": rules_data,
    }

    tmp = tempfile.NamedTemporaryFile(
        mode='w', suffix='.json', delete=False, prefix='snortforge_'
    )
    json.dump(project, tmp, indent=2)
    tmp.close()

    return send_file(
        tmp.name,
        as_attachment=True,
        download_name="snortforge_project.json",
        mimetype="application/json",
    )


# ── API: Import Rules ──

@app.route("/api/import/rules", methods=["POST"])
def api_import_rules():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    tmp = tempfile.NamedTemporaryFile(
        mode='wb', suffix='.rules', delete=False
    )
    file.save(tmp.name)
    tmp.close()

    try:
        rules, errors = parse_rules_file(tmp.name)
        return jsonify({
            "success": True,
            "rules": [r.to_dict() for r in rules],
            "errors": errors,
            "count": len(rules),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400
    finally:
        os.unlink(tmp.name)


@app.route("/api/import/json", methods=["POST"])
def api_import_json():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    try:
        data = json.loads(file.read())
        rules = data.get("rules", [])
        return jsonify({
            "success": True,
            "rules": rules,
            "count": len(rules),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


if __name__ == "__main__":
    # Debug mode should not be enabled by default in production.
    # Enable it explicitly for development by setting FLASK_DEBUG=1 (or "true").
    debug_flag = os.getenv("FLASK_DEBUG", "0").lower()
    debug = debug_flag in ("1", "true", "yes", "on")
    app.run(debug=debug, port=5000)
