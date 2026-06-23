# Requirements: 服务器日志智能分析系统

**Defined:** 2026-06-23
**Core Value:** 让课堂演示中的每个人都参与进来——同学发起攻击，监控屏实时响应，展示真实的安全运维工作流。

## v1 Requirements

Requirements for initial release. Each maps to roadmap phases.

### 外部访问

- [ ] **EXT-01**: 外部用户可通过浏览器访问独立的攻击模拟面板页面
- [ ] **EXT-03**: 外部用户选择攻击类型后一键发起，无需登录或配置
- [ ] **EXT-04**: 攻击请求真实打到 Docker nginx，产生真实 access.log 日志
- [ ] **EXT-05**: 攻击面板实时显示攻击状态（已发送 → 执行中 → 完成）

### 检测引擎

- [ ] **DET-01**: 检测引擎正确识别外部触发的攻击并区分攻击类型
- [ ] **DET-02**: LLM 深度分析对真实攻击流量给出准确判定
- [ ] **DET-03**: 监控大屏实时刷新展示攻击者 IP、攻击类型、告警级别

### 救援响应

- [ ] **RES-01**: 严重攻击自动触发 SSH 救援（iptables 封禁 IP / nginx 规则重载）
- [ ] **RES-02**: 救援操作在监控大屏上实时可见（执行步骤、成功/失败状态）
- [ ] **RES-03**: 救援回滚机制在真实环境下正常工作

### 报告通知

- [ ] **RPT-01**: 每次攻击事件自动生成安全报告
- [ ] **RPT-02**: 邮件通知在真实攻击场景下正常工作

## Out of Scope

| Feature | Reason |
|---------|--------|
| 用户认证与权限管理 | 课堂演示无需登录 |
| 多租户隔离 | 单实例演示即可 |
| 内网穿透（ngrok/Cloudflare Tunnel）| 用户自行解决 |
| MySQL/SSH 日志监控 | 当前仅监控 nginx 日志 |
| CI/CD 管道 | 不在课程范围内 |
| 生产环境部署 | 仅课堂演示 |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| EXT-01 | Phase 1 | Pending |
| EXT-03 | Phase 1 | Pending |
| EXT-04 | Phase 1 | Pending |
| EXT-05 | Phase 1 | Pending |
| DET-01 | Phase 2 | Pending |
| DET-02 | Phase 2 | Pending |
| DET-03 | Phase 2 | Pending |
| RES-01 | Phase 3 | Pending |
| RES-02 | Phase 3 | Pending |
| RES-03 | Phase 3 | Pending |
| RPT-01 | Phase 4 | Pending |
| RPT-02 | Phase 4 | Pending |

**Coverage:**
- v1 requirements: 12 total
- Mapped to phases: 12
- Unmapped: 0

---
*Requirements defined: 2026-06-23*
*Last updated: 2026-06-23 after roadmap creation*
