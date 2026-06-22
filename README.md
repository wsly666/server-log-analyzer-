# 🛡️ 服务器日志智能分析系统

> **项目06** | 技术栈：LLM + LangChain + pyautogui + pillow

一个 AI 驱动的智能运维系统，自动监控服务器日志，使用 LLM 识别异常攻击行为，
发现严重故障时自动执行救援操作，最后生成可视化报告并邮件通知管理员。

## 系统架构

```
Docker 真实环境 (nginx + MySQL + SSH靶机)
    ↓ 真实日志
Python 智能分析系统
    ├── ① 攻击模拟器 (requests 真实HTTP请求)
    ├── ② 日志监控器 (watchdog + LangChain解析)
    ├── ③ 检测引擎 (规则引擎 + LLM深度分析)
    ├── ④ 救援执行器 (paramiko SSH + 真实shell命令)
    ├── ⑤ 报告生成 (LLM + matplotlib + pillow)
    └── ⑥ Streamlit 主控台
```

## 快速启动

### 1. 环境准备

```bash
# 安装依赖
pip install -r requirements.txt

# 复制并配置环境变量
cp .env.example .env
# 编辑 .env 填入 LLM_API_KEY 和 SMTP 配置

# 安装 Docker Desktop
# https://www.docker.com/products/docker-desktop/
```

### 2. 启动 Docker 环境

```bash
cd docker
docker-compose up -d
```

### 3. 启动监控系统

```bash
# Windows
run.bat

# Linux/Mac
bash run.sh

# 或手动启动
cd src
streamlit run app.py
```

### 4. 访问

- Streamlit 界面：http://localhost:8501
- nginx 网站：http://localhost:8080
- MySQL：localhost:3306
- SSH 靶机：localhost:2222

## 项目结构

```
server-log-analyzer/
├── docker/                     # Docker 环境
│   ├── docker-compose.yml
│   ├── nginx/                  # Web服务器
│   ├── mysql/                  # 数据库
│   └── ssh-target/             # SSH靶机
├── src/                        # Python 源代码
│   ├── config.py               # 全局配置
│   ├── models.py               # 数据模型
│   ├── event_bus.py            # 事件总线
│   ├── log_simulator.py        # 正常日志生成
│   ├── attack_simulator.py     # 攻击模拟器
│   ├── scenarios.yaml          # 演示场景
│   ├── log_monitor.py          # 日志监控
│   ├── rule_engine.py          # 规则引擎
│   ├── llm_analyzer.py         # LLM分析
│   ├── alert_manager.py        # 告警管理
│   ├── rescue_executor.py      # 救援执行
│   ├── playbooks.yaml          # 救援剧本
│   ├── report_generator.py     # 报告生成
│   ├── chart_generator.py      # 图表生成
│   ├── email_sender.py         # 邮件发送
│   └── app.py                  # Streamlit主界面
├── logs/                       # 日志文件 (自动生成)
├── reports/                    # 分析报告 (自动生成)
├── charts/                     # 图表 (自动生成)
├── requirements.txt
└── README.md
```

## 四人分工

| 成员 | 角色 | 核心模块 |
|------|------|---------|
| A (组长) | 架构 + Docker + 集成 | docker-compose, playbooks.yaml, 联调 |
| B | 攻击仿真 | log_simulator, attack_simulator, scenarios |
| C | AI检测引擎 | log_monitor, rule_engine, llm_analyzer |
| D | 响应呈现 | rescue_executor, report/chart/email, Streamlit |

## 技术栈

- **LLM**: DeepSeek API (兼容 OpenAI SDK)
- **LangChain**: 日志解析链 + StructuredOutput
- **Docker**: nginx + MySQL + SSH 靶机
- **Streamlit**: 实时监控仪表盘
- **matplotlib + pillow**: 趋势图表
- **paramiko**: SSH 救援操作
- **watchdog**: 文件系统监控
