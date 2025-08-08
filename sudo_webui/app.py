"""
Flask-based backend for the self‑service sudo web UI.

This application exposes a REST API that allows clients to request
adding or removing a group from a set of hosts' sudoers files. It
supports optional expiry dates (if omitted, the access is permanent),
uses predefined command templates, and integrates with a Git-managed
repository and a simple SQLite audit database.  The endpoints here are
intended as a proof of concept for the overall system design.  They do
not implement authentication or asynchronous job scheduling, which
would be necessary in a production deployment.

Running this script will start a Flask development server.  In
practice, use a production WSGI server such as Gunicorn and configure
environment variables via the accompanying Ansible role.

To install dependencies:
    pip install -r requirements.txt

To run the app:
    python3 app.py
"""

from __future__ import annotations

import os
import json
import logging
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any

from flask import Flask, request, jsonify
import yaml  # PyYAML

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# The path to the Git-managed sudoers repository.  During testing you
# can point this to a local directory; in production this will be
# provided by the Ansible role and stored in an environment variable.
REPO_PATH = Path(os.environ.get("SUDO_REPO_PATH", "/tmp/sudo_repo"))
# Path to the YAML file containing Duo exclusion records.  This file
# lives inside the repository.
DUO_EXCLUSIONS_FILE = REPO_PATH / "duo_exclusions.yml"
# Path to the SQLite database for audit logging.
DB_PATH = Path(os.environ.get("SUDO_AUDIT_DB", "/tmp/sudo_audit.db"))
# Path to the YAML templates directory.
TEMPLATES_PATH = Path(os.environ.get("SUDO_TEMPLATES_PATH", "sudo_webui"))

# Ensure repository and DB directories exist during development.
REPO_PATH.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def get_db_connection() -> sqlite3.Connection:
    """Return a connection to the SQLite database, creating tables if needed."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Initialise schema if it doesn't exist
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requester TEXT NOT NULL,
                action TEXT NOT NULL,
                sudo_group TEXT NOT NULL,
                template_name TEXT,
                service_account BOOLEAN NOT NULL,
                duo_exclude BOOLEAN NOT NULL,
                expiry_date TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER NOT NULL,
                hostname TEXT NOT NULL,
                FOREIGN KEY (request_id) REFERENCES requests(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                message TEXT NOT NULL,
                logged_at TEXT NOT NULL,
                FOREIGN KEY (request_id) REFERENCES requests(id)
            )
            """
        )
    return conn


def load_templates() -> Dict[str, List[str]]:
    """Load command templates from YAML files in the templates path.

    Returns a dictionary mapping template names to lists of commands.
    """
    templates: Dict[str, List[str]] = {}
    for template_file in TEMPLATES_PATH.glob("*.yml"):
        name = template_file.stem
        with open(template_file, "r") as f:
            try:
                data = yaml.safe_load(f)
                if not isinstance(data, dict) or "commands" not in data:
                    logging.warning(
                        f"Ignoring template {template_file}: must contain a 'commands' key"
                    )
                    continue
                commands = data["commands"]
                if not isinstance(commands, list):
                    logging.warning(
                        f"Ignoring template {template_file}: 'commands' must be a list"
                    )
                    continue
                templates[name] = commands
            except yaml.YAMLError as e:
                logging.error(f"Failed to parse template {template_file}: {e}")
    return templates


def modify_sudoers_file(
    hostname: str,
    group: str,
    commands: List[str],
    action: str,
    expiry: Optional[str],
    service_account: bool,
) -> None:
    """Modify the sudoers file for the given host.

    This function opens (or creates) a file named after the hostname in
    REPO_PATH.  It either adds a new sudoers line for the given group and
    commands, or removes it, depending on the action.  An optional
    expiry comment is added if provided.  Service accounts are handled
    identically to user accounts in this simple example; in practice you
    could restrict commands or mark them in a different way.
    """
    file_path = REPO_PATH / f"{hostname}.sudoers"
    lines: List[str] = []
    if file_path.exists():
        with open(file_path, "r") as f:
            lines = f.read().splitlines()
    # Remove existing lines for this group
    prefix = f"%{group} "
    lines = [line for line in lines if not line.startswith(prefix)]
    if action == "add":
        # Build the sudoers line
        command_list = ", ".join(commands)
        sudo_line = f"%{group} ALL=(ALL) NOPASSWD: {command_list}"
        if expiry:
            sudo_line += f"  # expires={expiry}"
        lines.append(sudo_line)
    # Write the file back
    with open(file_path, "w") as f:
        f.write("\n".join(lines) + "\n")


def update_duo_exclusions(hostnames: List[str], group: str, add: bool) -> None:
    """Add or remove a group from the Duo exclusion list for each host.

    The exclusion file is a YAML mapping of hostnames to lists of
    groups.  If `add` is True, the group is appended; otherwise it is
    removed.  If a host entry becomes empty after removal, it is
    deleted.
    """
    duo_data: Dict[str, List[str]] = {}
    if DUO_EXCLUSIONS_FILE.exists():
        with open(DUO_EXCLUSIONS_FILE, "r") as f:
            try:
                duo_data = yaml.safe_load(f) or {}
            except yaml.YAMLError as e:
                logging.error(f"Failed to parse Duo exclusion file: {e}")
    # Modify entries
    for host in hostnames:
        groups = duo_data.get(host, [])
        if add:
            if group not in groups:
                groups.append(group)
        else:
            if group in groups:
                groups.remove(group)
        if groups:
            duo_data[host] = groups
        elif host in duo_data:
            del duo_data[host]
    # Write back
    with open(DUO_EXCLUSIONS_FILE, "w") as f:
        yaml.safe_dump(duo_data, f)


def create_app() -> Flask:
    """Factory function for the Flask application."""
    app = Flask(__name__)
    logging.basicConfig(level=logging.INFO)

    templates_cache = load_templates()

    @app.route("/api/templates", methods=["GET"])
    def list_templates():
        """Return available templates."""
        return jsonify(templates_cache)

    @app.route("/api/request", methods=["POST"])
    def handle_request():
        """Handle a sudo access request.

        Expected JSON payload:
        {
            "requester": "username",
            "action": "add" or "remove",
            "sudo_group": "group_name",
            "template": "template_name",   # optional for remove
            "hostnames": ["host1", "host2"],
            "service_account": true/false,
            "duo_exclude": true/false,
            "expiry_days": 7                 # optional; omitted for permanent access
        }

        If `expiry_days` is provided and positive, the expiry date will
        be calculated from today.  Otherwise, the request will have
        no expiry (permanent access).
        """
        data = request.get_json(force=True)
        # Basic validation
        required_fields = ["requester", "action", "sudo_group", "hostnames"]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        action = data["action"]
        if action not in ("add", "remove"):
            return jsonify({"error": "Invalid action: must be 'add' or 'remove'"}), 400
        group = data["sudo_group"]
        hostnames = data.get("hostnames") or []
        if not isinstance(hostnames, list) or not hostnames:
            return jsonify({"error": "Hostnames must be a non-empty list"}), 400
        service_account = bool(data.get("service_account", False))
        duo_exclude = bool(data.get("duo_exclude", False)) or service_account

        # Determine template commands
        template_name = data.get("template")
        commands: List[str] = []
        if action == "add":
            if not template_name:
                return jsonify({"error": "Template must be provided for add actions"}), 400
            commands = templates_cache.get(template_name)
            if not commands:
                return jsonify({"error": f"Unknown template: {template_name}"}), 400

        # Compute optional expiry date
        expiry_days = data.get("expiry_days")
        expiry_date: Optional[str] = None
        if isinstance(expiry_days, int) and expiry_days > 0:
            expiry_date = (datetime.utcnow() + timedelta(days=expiry_days)).strftime("%Y-%m-%d")

        # Insert request into DB
        conn = get_db_connection()
        with conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO requests (
                    requester, action, sudo_group, template_name, service_account,
                    duo_exclude, expiry_date, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["requester"],
                    action,
                    group,
                    template_name,
                    service_account,
                    duo_exclude,
                    expiry_date,
                    datetime.utcnow().isoformat(),
                ),
            )
            request_id = cur.lastrowid
            # Link targets
            for host in hostnames:
                cur.execute(
                    "INSERT INTO targets (request_id, hostname) VALUES (?, ?)",
                    (request_id, host),
                )
        logging.info(
            f"Received request {request_id}: {action} group {group} on {hostnames}"
        )

        # Modify files
        for host in hostnames:
            modify_sudoers_file(
                hostname=host,
                group=group,
                commands=commands,
                action=action,
                expiry=expiry_date,
                service_account=service_account,
            )
        # Update Duo exclusions if needed
        if duo_exclude:
            update_duo_exclusions(hostnames, group, add=(action == "add"))

        # Audit log entry
        with conn:
            conn.execute(
                "INSERT INTO audit_log (request_id, status, message, logged_at) VALUES (?, ?, ?, ?)",
                (
                    request_id,
                    "processed",
                    f"sudoers files updated for {hostnames}",
                    datetime.utcnow().isoformat(),
                ),
            )

        return jsonify({"request_id": request_id, "expiry_date": expiry_date}), 201

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)