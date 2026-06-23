# Walking Skeleton -- 服务器日志智能分析系统

**Phase:** 1
**Generated:** 2026-06-23

## Capability Proven End-to-End

A classroom student accesses the external attack panel via ngrok URL, selects SQL injection attack type, clicks "Launch", the attack sends real HTTP requests to Docker nginx producing access.log entries, and the student sees live status feedback (sent count, errors, completion).

## Architectural Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Framework | Streamlit 1.29.0+ | Already the project's UI framework for the monitoring dashboard; avoids adding new dependencies; `@st.cache_resource` handles AttackSimulator singleton persistence across reruns |
| Data layer | File-based logs via Docker volume mounts | No database needed for the attack panel -- it only sends HTTP requests. Attack logs are written by Docker nginx to `logs/nginx/access.log` on the host filesystem via Docker volume mount. Downstream detection in Phase 2 reads these files. |
| Auth | None | Classroom demo per EXT-03 -- students access the panel without login. The ngrok URL is shared only within the classroom. No authentication layer is built. |
| Deployment target | Docker Compose (3 containers: nginx:8080, MySQL:3306, SSH:2222) + ngrok free tier tunnel to localhost:8502 | Zero server cost (ngrok free tier). Docker Desktop runs locally on Windows 10. ngrok provides a public HTTPS URL that tunnels to the Streamlit attack panel. |
| Directory layout | `src/` flat Python package (existing convention). New files: `src/attack_panel.py` for the external attack panel Streamlit app. Launcher scripts in project root: `run_attack_panel.bat` / `run_attack_panel.sh`. | Follows existing project structure -- no subdirectories under `src/`, snake_case filenames, launcher scripts at project root. |
| Attack engine reuse | Import `AttackSimulator` class from `src/attack_simulator.py` unchanged | The existing AttackSimulator already sends real HTTP requests with attack payloads (SQLi/XSS/CC/Brute-force) to Docker nginx. The attack panel wraps this in a Streamlit UI without modifying the attack logic. |
| ngrok integration | ngrok v3 CLI with auth token, tunnel configured to localhost:8502 | Free tier provides HTTPS URL. Launcher scripts handle ngrok startup. User must create a free ngrok account and provide auth token (human-required setup). |

## Stack Touched in Phase 1

- [x] Project scaffold -- `src/attack_panel.py` (new Streamlit app), launcher scripts
- [x] Routing -- Streamlit single-page app (attack panel is a standalone page, not multi-page)
- [x] External access -- ngrok tunnel provides public HTTPS URL to the attack panel
- [x] Real attack traffic -- AttackSimulator sends HTTP requests to Docker nginx container on localhost:8080
- [x] Status display -- Streamlit session state shows attack progress (sent count, errors, completion)
- [x] Log production -- Docker nginx writes combined-format access.log with attack records

## Out of Scope (Deferred to Later Slices)

- Monitoring dashboard updates (Phase 2: Detection & Monitoring)
- LLM-based attack analysis (Phase 2: Detection & Monitoring)
- Rescue/response automation (Phase 3: Rescue Response)
- Report generation and email notification (Phase 4: Report & Notification)
- User authentication or access control (never -- classroom demo)
- Multi-user session isolation (Streamlit is single-session per app instance)
- Attack panel customization (custom payloads, custom target IP) -- only predefined attack types with configurable attacker IP
- Attack simulation scheduling or scenarios (Phase 2+)
- HTTPS/TLS termination at the attack panel (ngrok provides HTTPS)

## Subsequent Slice Plan

Each later phase adds one vertical slice on top of this skeleton without altering its architectural decisions:

- **Phase 2: Detection & Monitoring** -- The monitoring dashboard detects attacks launched from this panel, displays real-time alerts with attacker IP and attack type classification, and refreshes automatically.
- **Phase 3: Rescue Response** -- Critical attacks from this panel auto-trigger SSH rescue commands (iptables IP blocking, nginx rule reload) on the Docker containers, with rollback support.
- **Phase 4: Report & Notification** -- Attack events originating from this panel generate automated Markdown security reports and email notifications.
