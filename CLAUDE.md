<!-- GSD:project-start source:PROJECT.md -->

## Project

**服务器日志智能分析系统**

一个面向课堂演示的 AI 驱动安全运维平台。外部用户通过浏览器访问攻击模拟面板，发起真实攻击打到 Docker 服务器；运维人员通过 Streamlit 监控大屏实时观察检测、告警、自动救援全过程。演示完整的安全事件响应闭环。

**当前阶段：** 已有本地原型（攻击模拟 + 检测引擎 + 报告生成），需要从"单机自演"升级为"外部可访问的演示平台"。

**Core Value:** 让课堂演示中的每个人都参与进来——同学发起攻击，监控屏实时响应，展示真实的安全运维工作流。

### Constraints

- **成本**: 零服务器费用，使用免费内网穿透方案（ngrok 免费版）
- **网络**: 教室局域网环境，需支持外部访问
- **平台**: Windows 10 + Docker Desktop
- **性能**: 课堂演示级别，10-20 个同学同时访问的攻击面板压力可控
- **安全**: 仅演示环境使用，不暴露到生产网络

<!-- GSD:project-end -->

<!-- GSD:stack-start source:codebase/STACK.md -->

## Technology Stack

## Languages

- Python 3.12.8 -- All application logic across `src/` (monitoring, detection, rescue, reporting, UI)
- YAML -- Configuration for rescue playbooks (`src/playbooks.yaml`) and demo scenarios (`src/scenarios.yaml`)
- Dockerfile (Bash/sh) -- Container image definitions in `docker/nginx/Dockerfile`, `docker/mysql/Dockerfile`, `docker/ssh-target/Dockerfile`
- HTML/CSS -- Demo web UI served by nginx at `docker/nginx/html/index.html`
- Batch (`run.bat`, `setup.bat`) -- Windows launcher scripts
- Bash (`run.sh`) -- Linux/Mac launcher script

## Runtime

- Python 3.12.8 (CPython)
- Virtual environment at `venv/` (Python venv), activated by launcher scripts
- pip (via `requirements.txt`)
- Lockfile: None (no requirements.lock, pip freeze not committed)

## Frameworks

- LangChain 0.3.0+ (`langchain`, `langchain-openai`) -- LLM orchestration: ParsedLogLine extraction chain in `src/log_monitor.py`, attack analysis chain with PydanticOutputParser in `src/llm_analyzer.py`, report generation chain in `src/report_generator.py`
- Streamlit 1.29.0+ -- Web-based monitoring dashboard at `src/app.py` (single-page multi-tab app with real-time log streaming, alert management, chart views, system settings)
- OpenAI SDK 1.0.0+ (`openai`) -- Underlying API client used by langchain-openai to call DeepSeek API
- None detected -- No test frameworks (pytest, unittest), no test files, no test config
- Rich 13.0.0+ -- Console output formatting in attack simulator (`src/attack_simulator.py`) and rescue executor (`src/rescue_executor.py`)
- python-dotenv 1.0.0+ -- `.env` file loading in `src/config.py`

## Key Dependencies

- watchdog 4.0.0+ -- Filesystem monitoring for real-time log tailing (`src/log_monitor.py`). The Observer watches nginx access/error log directories for modifications
- paramiko 3.4.0+ -- SSH client for executing rescue commands on the Docker SSH target container at localhost:2222 (`src/rescue_executor.py`)
- pydantic 2.5.0+ -- Data validation and serialization for all inter-module messages (LogEvent, Alert, LLMAnalysis, RescueTask, EventBusMessage in `src/models.py`)
- pyyaml 6.0+ -- Parsing playbooks (`src/playbooks.yaml`) and scenarios (`src/scenarios.yaml`)
- requests 2.31.0+ -- HTTP client for attack simulation (`src/attack_simulator.py`)
- matplotlib 3.8.0+ -- Chart generation for error trends, attack pie charts, IP bar charts, severity distributions (`src/chart_generator.py`). Uses Agg backend (non-interactive)
- pillow 10.0.0+ -- Image post-processing: watermark and timestamp annotation on generated charts (`src/chart_generator.py`)
- pyautogui 0.9.54+ -- Listed in requirements but no direct imports found in source. Intended for GUI automation scenarios
- Docker / Podman (auto-detected by launcher scripts) -- Container runtime. Launcher checks for `docker info` then `podman info`, and corresponding compose tools
- Docker Compose / podman-compose -- Multi-container orchestration via `docker/docker-compose.yml`

## Configuration

- `.env` file loaded by python-dotenv in `src/config.py`
- `.env.example` shipped as template with these configurable values:
- `src/config.py` -- Central configuration module with all thresholds, paths, regex patterns, and attack simulation parameters hardcoded as Python constants
- No build system (pip install from requirements.txt, no setup.py, no pyproject.toml)
- Runtime configuration: `src/playbooks.yaml` (rescue action sequences), `src/scenarios.yaml` (demo scenarios)
- `docker/docker-compose.yml`: MySQL `root123` / `app_pass`, SSH `admin:rescue123` / `root:rescue123`
- `src/config.py`: SSH_USERNAME="root", SSH_PASSWORD="rescue123"

## Platform Requirements

- Python 3.10+ (setup.bat checks for Python)
- Docker Desktop or Podman with compose support
- 3 Docker containers running simultaneously (nginx + MySQL + SSH target)
- Not designed for production deployment -- this is a demonstration/training project
- Single-machine operation with all containers on localhost

<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->

## Conventions

## Naming Patterns

- Use `snake_case` for all Python files in `src/`: `log_monitor.py`, `rule_engine.py`, `attack_simulator.py`, `rescue_executor.py`, `email_sender.py`, `chart_generator.py`, `event_bus.py`, `report_generator.py`, `llm_analyzer.py`, `alert_manager.py`, `log_simulator.py`, `log_rotator.py`
- YAML config files use `snake_case`: `scenarios.yaml`, `playbooks.yaml`
- Dockerfiles live in named subdirectories: `docker/nginx/Dockerfile`, `docker/mysql/Dockerfile`, `docker/ssh-target/Dockerfile`
- Use `PascalCase`: `LogSimulator`, `AttackSimulator`, `RuleEngine`, `LLMAnalyzer`, `AlertManager`, `RescueExecutor`, `ReportGenerator`, `EmailSender`, `LogMonitor`, `LogFileHandler`, `SlidingWindow`, `EventBus`
- Pydantic models in `src/models.py` use `PascalCase`: `LogEvent`, `ParsedLogLine`, `RuleMatch`, `LLMAnalysis`, `Alert`, `RescueAction`, `RescueTask`, `EventBusMessage`
- Enums use `PascalCase`: `Severity`, `AttackType`
- Use `snake_case`: `create_alert()`, `_format_logs_for_llm()`, `parse_nginx_access_line()`, `detect_attacks_in_logs()`, `rotate_log()`, `get_rotation_info()`, `manual_clear_log()`
- Private/internal methods use a single underscore prefix: `_check_frequency()`, `_check_patterns()`, `_check_error_rate()`, `_check_brute_force()`, `_fallback_analysis()`, `_fallback_report()`, `_build_html_body()`, `_format_alert_data()`, `_connect_ssh()`, `_disconnect_ssh()`, `_execute_command()`, `_find_playbook()`, `_load_playbooks()`, `_generate_nginx_log_line()`, `_generate_batch()`, `_run_loop()`, `_read_new_lines()`, `_publish_event()`, `_classify_attack_type_from_match()`, `_get_dominant_attack_types()`, `_determine_severity()`, `_save_and_annotate()`, `_signal_nginx_reopen()`, `_cleanup_old_rotations()`
- Constructor uses standard `__init__()`, no custom `__new__` patterns
- Use `snake_case`: `log_sim`, `attack_sim`, `log_mon`, `rule_eng`, `llm_analyzer`, `alert_mgr`, `rescue_exec`, `report_gen`, `email_sender`, `alert_id`, `source_ip`, `log_entries`, `dedup_cache`
- Collection variable names are descriptive plurals: `all_alerts`, `log_lines`, `rule_matches`, `suspicious_events`, `type_events`, `attack_markers`
- Use `UPPER_CASE` with underscores: `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL`, `LLM_TEMPERATURE`, `LLM_MAX_TOKENS`, `FREQ_THRESHOLD`, `WINDOW_SECONDS`, `BRUTE_FORCE_THRESHOLD`, `ERROR_RATE_THRESHOLD`, `ALERT_DEDUP_WINDOW`, `LOG_MAX_SIZE_MB`, `LOG_ROTATE_KEEP`, `NGINX_PORT`, `MYSQL_PORT`, `SSH_TARGET_PORT`, `ANALYSIS_SYSTEM_PROMPT`, `REPORT_SYSTEM_PROMPT`, `NGINX_LOG_PARSER_SYSTEM_PROMPT`
- Regex pattern lists are `UPPER_CASE`: `SQL_INJECTION_PATTERNS`, `XSS_PATTERNS`, `PATH_TRAVERSAL_PATTERNS`, `CC_PATTERNS`
- `NGINX_ACCESS_PATTERN` and `NGINX_ERROR_PATTERN` are compiled regex objects at module level

## Code Style

- No formatting tool configured. No `.editorconfig`, `pyproject.toml`, `setup.cfg`, `.flake8`, `.pylintrc`, or `mypy.ini` found in the project root.
- Indentation is consistently 4 spaces.
- Section dividers use `# ============...` style comments: `# ============================================`
- Chinese comments and docstrings are used throughout for business logic, with occasional English for technical terms.
- Line length varies; long HTML string interpolations and f-strings exceed 100 characters.
- No linting tool configured. Zero ESLint, Prettier, Biome, flake8, pylint, or mypy configuration files in the project.
- Module-level: Every `src/*.py` file starts with a descriptive module docstring in Chinese, typically naming the responsible team member (Member B/C/D) and module purpose.
- Class-level: Brief docstrings present on most classes. `class SlidingWindow` has a detailed docstring explaining its O(1) complexity and timestamp-based window design.
- Method-level: Inconsistent. Public-facing methods sometimes have docstrings (e.g., `create_alert()` in `alert_manager.py` has detailed Args/Returns). Internal methods rarely have docstrings.
- Language: Chinese for business descriptions, English for technical parameter names in docstrings.

## Import Organization

- Multiple files use `sys.path.insert(0, str(Path(__file__).resolve().parent.parent))` to add the project root to Python path, then import from `src.xxx` using absolute imports. Files using this hack: `src/app.py`, `src/log_simulator.py`, `src/attack_simulator.py`, `src/chart_generator.py`.
- Lazy imports: Some modules import heavy dependencies inside functions to avoid startup cost. Example: `src/log_monitor.py` imports LangChain components inside `_get_llm_log_parser()`.
- Some functions import locally to avoid circular imports or reduce startup overhead: `detect_attacks_in_logs()` in `app.py` does `from src.log_monitor import parse_nginx_access_line` and `from src.models import LogEvent`.
- No path aliases configured. All imports use the `src.` prefix or relative paths via `sys.path` manipulation.

## Type Hints

- Pydantic models in `src/models.py` use type hints extensively (required by Pydantic).
- Business logic modules use moderate type hints on method signatures and return types.
- Function signatures typically hint parameters and return types: `def analyze(self, event: LogEvent) -> list[RuleMatch]`
- Some files lack type hints on internal helper functions.
- `Optional[X]` used for nullable types: `def create_alert(...) -> Optional[Alert]`, `def parse_nginx_access_line(line: str) -> Optional[LogEvent]`
- PEP 604 union syntax used: `self.thread: threading.Thread | None = None`
- Collection types use generic form: `dict[str, int]`, `list[RuleMatch]`, `list[dict]`
- Lambda functions inside threading calls lack type annotations.
- Module-level constants rarely have explicit type annotations (e.g., `REPORT_SYSTEM_PROMPT` is un-annotated).

## Error Handling

- Broad `try/except Exception` is the dominant pattern throughout the codebase.
- Fallback/degradation methods: LLM-dependent modules implement `_fallback_*` methods for when the LLM call fails.
- `return None` is the standard sentinel for "no result" or "no action needed". Found in: `rule_engine.py` (lines 117, 188, 193, 197, 215), `alert_manager.py` (line 53), `log_monitor.py` (lines 134, 148, 188), `rescue_executor.py` (line 205), `log_rotator.py` (lines 58, 62, 93).
- Explicit exception types caught only in `src/email_sender.py`: `SMTPAuthenticationError`, `SMTPConnectError`, `SMTPSenderRefused` before the broad `Exception` catch.
- No custom exception classes defined anywhere in the project.
- Functions return boolean success/failure indicators: `send_alert_email() -> bool`, `send_test_email() -> bool`, `manual_clear_log() -> bool`.
- All errors are printed to stdout via `print()` with a `[ModuleName]` prefix.

## Logging

- `[ModuleName] status_emoji message`
- Status emojis: `✅` (success), `❌` (failure), `⚠` (warning), `🟢`/`🔴`/`🟡` (system status), `🚨`/`🔥` (alert), `🚑` (rescue), `🧠` (LLM), `🗑` (deletion), `📧` (email), `📄` (report), `🔄` (rotation), `🧹` (cleanup)
- Examples:
- Component initialization and shutdown
- Rule engine match results
- LLM analysis outcomes (success and failure)
- Alert creation and deduplication
- Rescue execution steps and rollbacks
- File operations (log rotation, save, clear)
- Email send results

## Comments

- Section dividers: Used liberally with `# ========...====` to separate logical sections within a file. Every file uses at least 3-4 section dividers.
- Regex patterns: Inline comments explain complex regex groups. Example:
- Configuration values: Inline comments explain threshold choices and units.
- Attack payloads: Section comments group payloads by attack type (`# SQL 注入攻击`, `# XSS 攻击`).
- Business logic: Chinese comments explain intent for complex logic branches (e.g., deduplication, attack type filtering).
- Not applicable (Python project). No Sphinx/numpydoc style used either.

## Function Design

- Named parameters with defaults for optional values: `def rotate_log(log_key: str = "nginx_access", max_size_mb: int = None, keep: int = None)`
- Configuration dicts used for batch parameter passing: `ATTACK_CONFIG`, `NORMAL_TRAFFIC_CONFIG`
- No use of `*args` or `**kwargs` anywhere in the codebase in a significant way.
- `Optional[X]` for "maybe result" patterns — widespread
- `list[X]` for collections
- `bool` for success/failure operations (email_sender, log_rotator)
- `tuple[int, list[str]]` for `read_all_logs()` in app.py
- Pydantic model instances for structured data transfer between modules

## Module Design

- Modules export classes and functions by convention (no `__all__` defined).
- Modules also define global singleton instances at module scope: `rule_engine = RuleEngine()`, `llm_analyzer = LLMAnalyzer()`, `alert_manager = AlertManager()`, `rescue_executor = RescueExecutor()`, `report_generator = ReportGenerator()`, `email_sender = EmailSender()`, `log_monitor = LogMonitor()`, `event_bus = EventBus()`
- `src/__init__.py` contains only a module-level docstring describing the system. Does not re-export any symbols.
- No `__init__.py` files in any subdirectories.
- `src/config.py`: Flat module with all config constants. No classes, no functions beyond `load_dotenv()` at import time.
- `src/scenarios.yaml`: Demo scenario definitions for presentation.
- `src/playbooks.yaml`: Rescue playbook definitions mapping attack types to remediation actions.

## Configuration Management

- `src/scenarios.yaml` — demo presentation script definitions (3 scenarios: SQL injection, CC flood, brute force)
- `src/playbooks.yaml` — rescue action definitions (5 playbooks mapping attack types to iptables/nginx commands)

## Anti-Patterns Identified

### `sys.path.insert()` Import Hack

### Hardcoded Secrets in Source

### Print-Based Logging

### Broad Exception Catching

### Module-Level Global Singletons

<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->

## Architecture

## System Overview

```text

```

## Component Responsibilities

| Component | Responsibility | File |
|-----------|----------------|------|
| Config | Global configuration, env vars, paths, thresholds | `src/config.py` |
| Models | Pydantic data models shared across all modules | `src/models.py` |
| EventBus | Async pub/sub message bus for module decoupling | `src/event_bus.py` |
| LogSimulator | Generate realistic normal-user nginx access log traffic | `src/log_simulator.py` |
| AttackSimulator | Send real malicious HTTP requests (SQLi/XSS/CC/Brute-force) to Docker nginx | `src/attack_simulator.py` |
| Attack Scenarios | Demo scenario definitions for presentation | `src/scenarios.yaml` |
| LogMonitor | watchdog-based file watcher + regex/LangChain nginx log parser | `src/log_monitor.py` |
| RuleEngine | First-tier detection: sliding-window frequency, regex pattern matching, error-rate stats | `src/rule_engine.py` |
| LLMAnalyzer | Second-tier detection: LangChain StructuredOutput LLM semantic analysis | `src/llm_analyzer.py` |
| AlertManager | Stateless alert factory with dedup, severity determination, handler callbacks | `src/alert_manager.py` |
| RescueExecutor | SSH (paramiko) into Docker containers to run iptables/nginx rescue commands | `src/rescue_executor.py` |
| Rescue Playbooks | YAML-defined rescue action sequences per attack type | `src/playbooks.yaml` |
| ReportGenerator | LLM-powered Markdown security incident report generation | `src/report_generator.py` |
| ChartGenerator | matplotlib + pillow trend/pie/bar chart generation with watermarking | `src/chart_generator.py` |
| EmailSender | SMTP HTML email with inline charts and report attachments | `src/email_sender.py` |
| LogRotator | Log file size monitoring, archival rotation, nginx reopen | `src/log_rotator.py` |
| Streamlit App | Unified dashboard: live log viewer, alert list, charts, attack controls, settings | `src/app.py` |

## Pattern Overview

- **Layered Architecture:** Presentation (Streamlit) -> Processing (Detection Pipeline) -> Response (Rescue/Report) -> Data (Logs/Charts/Reports) -> Infrastructure (Docker)
- **Pipeline Pattern:** LogEvent -> RuleEngine -> LLMAnalyzer -> AlertManager -> RescueExecutor -> ReportGenerator
- **Observer Pattern:** EventBus provides decoupled pub/sub between LogMonitor and downstream consumers
- **Strategy Pattern:** Playbooks (YAML) define pluggable rescue action sequences per attack type
- **Factory Pattern:** AlertManager creates Alert objects with dedup logic, caller owns state
- **Template Method:** Each attack simulator follows the same structure: worker threads -> stats collection
- **Fallback/Chain of Responsibility:** LLM analysis falls back to rule-engine-based heuristic when API fails
- **Dual-Mode Parser:** Log parsing defaults to regex (fast/free), with optional LangChain LLM chain

## Layers

- Purpose: User-facing dashboard for monitoring, attack control, alert review, report viewing, system configuration
- Location: `src/app.py`
- Contains: Streamlit UI code, session state management, component initialization, attack detection orchestration
- Depends on: All `src/` modules (imports all components at startup)
- Used by: End user via browser at `http://localhost:8501`
- Purpose: Parse raw logs, apply rules, invoke LLM for semantic analysis, create alerts
- Location: `src/log_monitor.py`, `src/rule_engine.py`, `src/llm_analyzer.py`, `src/alert_manager.py`
- Contains: Log parsing (regex + optional LangChain LLM), sliding-window frequency analysis, regex pattern matching (SQLi/XSS/path-traversal), LangChain StructuredOutput LLM analysis, alert creation with dedup
- Depends on: `src/models.py`, `src/config.py`, `src/event_bus.py`
- Used by: Streamlit app (via function calls in `detect_attacks_in_logs()`)
- Purpose: Execute rescue operations, generate reports, create charts, send emails
- Location: `src/rescue_executor.py`, `src/report_generator.py`, `src/chart_generator.py`, `src/email_sender.py`, `src/log_rotator.py`
- Contains: SSH-based iptables/nginx command execution, LLM report generation, matplotlib chart rendering with pillow watermarking, SMTP email dispatch, log rotation
- Depends on: `src/models.py`, `src/config.py`, YAML playbooks
- Used by: Streamlit app (via button callbacks and automatic triggers)
- Purpose: Store logs, reports, charts on the host filesystem
- Location: `logs/`, `reports/`, `charts/`, `logs/rotated/`
- Contains: nginx access/error logs, MySQL error/slow logs, SSH auth logs, generated Markdown reports, PNG charts, rotated log archives
- Depends on: Docker volume mounts from containers
- Used by: All Python modules for read/write
- Purpose: Provide real server environments that produce authentic logs
- Location: `docker/` (nginx, mysql, ssh-target)
- Contains: Dockerfiles, docker-compose.yml, nginx.conf, static HTML
- Depends on: Docker Desktop or Podman
- Used by: AttackSimulator (HTTP requests), RescueExecutor (SSH), LogSimulator (log target)

## Data Flow

### Primary Attack Detection -> Rescue -> Report Path

### Normal Traffic Flow

### Log Rotation Flow

### State Management

- **Streamlit Session State:** All runtime state (log entries, alerts, rescue tasks, LLM cache, dedup cache, system status) is stored in `st.session_state` — a per-user in-memory dictionary managed by Streamlit
- **Component Singletons:** Core components (LogSimulator, AttackSimulator, etc.) are initialized via `@st.cache_resource` to avoid re-creation on each Streamlit rerun
- **Global Singletons:** `event_bus` (`src/event_bus.py:69`), `log_monitor` (`src/log_monitor.py:304`), `rule_engine` (`src/rule_engine.py:237`), `llm_analyzer` (`src/llm_analyzer.py:193`), `alert_manager` (`src/alert_manager.py:129`), `rescue_executor` (`src/rescue_executor.py:215`), `report_generator` (`src/report_generator.py:152`), `email_sender` (`src/email_sender.py:179`) — all declared as module-level singletons
- **RuleEngine Internal State:** Mutable sliding-window counters (`_ip_windows`, `_brute_force_windows`, `_error_count`) that persist across calls — must be `reset()` when logs are cleared

## Key Abstractions

- Purpose: Standardize data exchange between all modules
- Key models: `LogEvent` (parsed log entry), `RuleMatch` (rule engine hit), `LLMAnalysis` (LLM structured output), `Alert` (unified alert), `RescueTask` + `RescueAction` (rescue execution), `EventBusMessage` (pub/sub message)
- Pattern: All models extend `pydantic.BaseModel` with type hints and `Field` defaults
- Purpose: Decoupled async message passing between LogMonitor and downstream modules
- Pattern: Pub/Sub with `subscribe(event_type, handler)` and async `publish(msg)`
- Note: Defined but not actively used in the current main flow (app.py calls module functions directly)
- Purpose: O(1) time-windowed event counter using deque
- Uses event timestamps (not `datetime.now()`) to avoid timezone mismatch between Docker UTC and host local time
- Purpose: Declarative rescue action sequences per attack type
- Each playbook defines: attack_type, min_severity, ordered list of actions (command template, rollback command, description)
- Supports `{attacker_ip}` and `{timestamp}` variable substitution
- Purpose: Pre-defined demo/presentation scenarios with expected alerts and verification steps
- Each scenario defines: attack_type, attacker_ip, duration, expected alerts with trigger times

## Entry Points

- Location: `src/app.py`
- Triggers: `streamlit run app.py` or via `run.bat`/`run.sh`
- Responsibilities: Initialize all components, render UI, orchestrate attack detection polling loop, handle user interactions
- `run.bat` / `run.sh` — Auto-detect Docker/Podman, start containers, activate venv, launch Streamlit
- `setup.bat` — Create venv, install dependencies, copy `.env.example` to `.env`
- Location: `docker/docker-compose.yml`
- Triggers: `docker compose up -d` or `podman compose up -d`
- Responsibilities: Start nginx (port 8080), MySQL (port 3306), SSH-target (port 2222) containers on a bridge network

## Architectural Constraints

- **Threading:** Log generation runs in daemon threads. Attack simulation spawns worker threads. Rescue execution is synchronous (blocking). The main Streamlit event loop is single-threaded.
- **Global state:** Nine module-level singleton instances exist. RuleEngine maintains mutable internal counters (`_ip_windows`, `_brute_force_windows`, etc.) that accumulate state across Streamlit reruns. These must be explicitly reset when logs are cleared or rotated.
- **Circular imports:** No circular dependency chains detected. Import graph is: `app.py` -> all modules -> `models.py` + `config.py`. `config.py` and `models.py` have no internal project imports. `event_bus.py` imports from `models.py` only.
- **Container dependency:** The system requires Docker or Podman running with 3 containers. All nginx log paths are hardcoded in `config.py`. SSH rescue assumes the ssh-target container is running at `localhost:2222` with `root:rescue123` credentials.
- **LLM API dependency:** The core detection intelligence (LLMAnalyzer) requires a valid DeepSeek API key. The system has a fallback mode but its accuracy is limited to rule-engine heuristics only.
- **File-based log reading:** The Streamlit app reads logs by polling file line counts (not via watchdog). The `LogMonitor` class with watchdog exists but is not the primary detection mechanism.

## Anti-Patterns

### God Component — `app.py`

### Global Mutable Singletons

### Inline Attack Detection in UI Code

### Hardcoded Credentials in Config

## Error Handling

- **LLM API Fallback:** `LLMAnalyzer.analyze()` catches all exceptions from the LangChain chain and calls `_fallback_analysis()` which uses rule-engine heuristics to approximate severity (`src/llm_analyzer.py:134-189`)
- **Log Parser Fallback:** When `LOG_PARSER_USE_LLM` is enabled and LLM parsing fails, the function falls back to regex parsing silently (`src/log_monitor.py:140-144`)
- **Report Generator Fallback:** `ReportGenerator.generate()` falls back to a template-based report when LLM generation fails (`src/report_generator.py:56-58`)
- **File Read Guards:** All file I/O is wrapped in try/except with `errors="ignore"` on encoding
- **Email Error Classification:** `EmailSender` distinguishes between authentication, connection, and sender-refused errors with specific messages (`src/email_sender.py:90-101`)
- **SSH Connection Guard:** `RescueExecutor` checks SSH connectivity before attempting commands, returns `FAILED` status on connection failure (`src/rescue_executor.py:144-148`)
- **Rescue Transaction Rollback:** When any rescue step fails, previously executed steps are rolled back in reverse order using their `rollback_command` (`src/rescue_executor.py:173-181`)

## Cross-Cutting Concerns

<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->

## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->

## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:

- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->

## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
