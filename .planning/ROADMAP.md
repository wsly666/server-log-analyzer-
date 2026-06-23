# Roadmap: 服务器日志智能分析系统

## Overview

将已有的本地原型升级为外部可访问的课堂演示平台。从创建面向同学的攻击面板开始，到验证检测引擎在真实外部攻击下的表现，再到救援响应和报告通知的端到端闭环。四个阶段逐步扩大演示的参与范围和自动化深度。

## Phases

- [ ] **Phase 1: External Attack Panel** - 外部用户可访问的攻击模拟面板，一键发起真实攻击
- [ ] **Phase 2: Detection & Monitoring** - 检测引擎验证与监控大屏实时刷新
- [ ] **Phase 3: Rescue Response** - 自动救援执行与实时状态可见
- [ ] **Phase 4: Report & Notification** - 安全报告自动生成与邮件通知

## Phase Details

### Phase 1: External Attack Panel
**Goal**: 外部用户可通过浏览器独立访问攻击模拟面板，选择攻击类型后一键发起，攻击请求真实打到 Docker nginx 并产生日志
**Mode:** mvp
**Depends on**: Nothing (first phase)
**Requirements**: EXT-01, EXT-03, EXT-04, EXT-05
**Success Criteria** (what must be TRUE):
  1. 外部用户通过浏览器访问攻击面板页面，看到可用攻击类型列表
  2. 用户选择攻击类型后点击发起，无需登录或额外配置即可完成攻击
  3. 攻击请求到达 Docker nginx 容器，access.log 中出现对应攻击记录，携带正确的攻击源 IP
  4. 攻击面板实时显示攻击状态流转：已发送 → 执行中 → 完成
**Plans**: TBD
**UI hint**: yes

### Phase 2: Detection & Monitoring
**Goal**: 检测流水线正确识别外部触发的攻击并区分攻击类型，LLM 深度分析给出准确判定，监控大屏实时刷新展示攻击信息
**Mode:** mvp
**Depends on**: Phase 1
**Requirements**: DET-01, DET-02, DET-03
**Success Criteria** (what must be TRUE):
  1. 外部攻击面板发起的攻击触发检测告警，攻击类型分类正确（SQL注入/XSS/CC/暴力破解/路径遍历）
  2. LLM 深度分析对真实攻击流量给出准确判定，能区分攻击流量与正常流量
  3. Streamlit 监控大屏自动刷新，无需手动操作即可看到新的攻击者 IP、攻击类型、告警级别
**Plans**: TBD
**UI hint**: yes

### Phase 3: Rescue Response
**Goal**: 严重攻击自动触发 SSH 救援操作，救援步骤和结果在监控大屏上实时可见，回滚机制正常工作
**Mode:** mvp
**Depends on**: Phase 2
**Requirements**: RES-01, RES-02, RES-03
**Success Criteria** (what must be TRUE):
  1. 严重攻击（CC 洪水或暴力破解）自动触发 SSH 救援（iptables IP 封禁或 nginx 规则重载）
  2. 监控大屏实时展示救援执行步骤（连接中 → 执行 playbook → 各步骤成功/失败状态）
  3. 回滚操作成功撤销救援动作（解除 IP 封禁、恢复 nginx 配置），通过重新测试连通性验证
**Plans**: TBD
**UI hint**: yes

### Phase 4: Report & Notification
**Goal**: 每次攻击事件自动生成安全报告，邮件通知在真实攻击场景下正常工作
**Mode:** mvp
**Depends on**: Phase 2
**Requirements**: RPT-01, RPT-02
**Success Criteria** (what must be TRUE):
  1. 外部攻击事件被检测并处理后，自动生成包含事件时间线、攻击详情和响应措施的安全报告
  2. 邮件通知成功发送到配置的收件人，包含攻击摘要和报告引用
**Plans**: TBD

## Progress

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. External Attack Panel | 0/TBD | Not started | - |
| 2. Detection & Monitoring | 0/TBD | Not started | - |
| 3. Rescue Response | 0/TBD | Not started | - |
| 4. Report & Notification | 0/TBD | Not started | - |
