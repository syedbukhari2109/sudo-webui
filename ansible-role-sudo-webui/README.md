Role Name
=========

sudo-webui

This Ansible role installs and configures the self‑service sudo web UI on
a RHEL 9 server.  It installs required system packages, clones the
application repository, sets up a Python virtual environment, installs
Python dependencies, and deploys a systemd service to run the Flask
application.  The role also creates a service user under which the
application runs.

Requirements
------------

This role targets RHEL 9 hosts.  It assumes access to a Git
repository containing the application.  You should provide the
repository URL and, optionally, a deploy key via variables.

Role Variables
--------------

| Variable | Default | Description |
|---------|---------|-------------|
| `sudo_webui_repo_url` | undefined | URL of the Git repository containing the sudo web UI code. |
| `sudo_webui_version` | `main` | Git branch, tag or commit to check out. |
| `sudo_webui_install_dir` | `/opt/sudo-webui` | Directory where the application will be installed. |
| `sudo_webui_user` | `sudo-webui` | Unix user to own and run the application. |
| `sudo_webui_port` | `5000` | Port on which the Flask application will listen. |
| `sudo_webui_env` | `{}` | Additional environment variables passed to the service (e.g. Satellite URL, AAP token). |

Dependencies
------------

No external roles are required.  The role uses Ansible’s package
modules and `git` module.

Example Playbook
----------------

```yaml
- hosts: sudo_server
  become: true
  vars:
    sudo_webui_repo_url: "https://git.example.com/infra/sudo-webui.git"
    sudo_webui_env:
      SUDO_REPO_PATH: "/var/lib/sudo-repo"
      SUDO_AUDIT_DB: "/var/lib/sudo-webui/audit.db"
  roles:
    - ansible-role-sudo-webui
```

License
-------

MIT