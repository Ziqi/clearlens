# 澄镜 ClearLens `v1.0.0`

**零后端跨境电汇欺诈（BEC）与反社工胁迫应急分诊工作台 —— 内置防御性外发敏感词阻断（Outbound DLP）、多币种内部换汇穿透剥离与双模 A4 紧急止付召回清册**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![REUSE 3.3 Compliant](https://img.shields.io/badge/REUSE-3.3%20Compliant-brightgreen)](./REUSE.toml)
[![SLSA Level 3](https://img.shields.io/badge/SLSA-Build%20Level%203-0f766e)](https://github.com/Ziqi/clearlens/attestations)
[![Zero Dependencies](https://img.shields.io/badge/零第三方依赖-Python%20Stdlib%20%2B%20原生JS-success)](./pyproject.toml)
[![在线静态工作台](https://img.shields.io/badge/在线免安装版-ziqi.github.io%2Fclearlens-1d4ed8)](https://ziqi.github.io/clearlens/)

> **语言切换 / Languages：** [**English (`README.md`)**](./README.md) | **简体中文**  
> **零后端在线工作台（全程本地内存运行，零服务器上传）：** <https://ziqi.github.io/clearlens/>（直达四舱工作台：<https://ziqi.github.io/clearlens/app.html>）

---

## 项目定位与解决痛点

在遭遇**跨境商务电邮篡改（BEC / 供应商变更收款账号截留）**、**冒充高管/机构紧急调拨欺诈**或**高压社会工程学胁迫**后的黄金 72 小时内，当事企业财务团队、涉外律师及个人家庭往往面临三大实操痛点：

1. **云端工具二次泄密风险**：将原始网银流水、受骗经过或账号回单上传至未知第三方在线转换网站或公网大模型，极易造成商业机密与个人隐私二次泄露；
2. **止付落锁前意外“打草惊蛇”（缺乏外发 DLP 护栏）**：在银行 `SWIFT gpi` 电汇召回或反诈止付指令尚未落锁的窗口期，若外发核实邮件/消息中不慎出现“报警、冻结、电汇召回、诈骗”等敏感词或泄露动态验证码、内部主账号，极易触发洗钱水房秒级分流转移；
3. **内部同名换汇中转导致“重复计损”**：跨国结算或个人归集常先经历内部同名账户换汇互转（如 `EUR -> HKD`），再向外部涉诈账户汇出。若未做穿透剥离，报案与银行申诉金额将虚高翻倍，严重拖慢合规核验与立案效率。

**澄镜 ClearLens (`v1.0.0`)** 采用 **100% 纯前端浏览器内存架构（`web/`）+ 零第三方依赖 Python `>= 3.10` 标准库命令行套件（`clearlens/`）**，通过 `<meta http-equiv="Content-Security-Policy" content="default-src 'none'...">` 实施浏览器级网络物理隔离，彻底离线解决上述三大难题。

---

## 四大确定性功能舱架构

1. **第 ① 舱 · 风险分级与邮箱/通信暗桩排查舱**：
   - 三级态势分诊（`A 级：会话进行中紧急止血` / `B 级：黄金 72h 电汇召回窗口` / `C 级：事后法务复盘举证`）；
   - 6 步驻留暗桩核查清单：排查企业/个人邮箱隐藏自动转发与静默删除规则、吊销异常 OAuth 令牌会话、切断远程控屏驻留、核查呼叫转移（`##002#`）、严格执行**「只冻结出账通道、绝不盲目销户」**（确保电汇召回原路退汇有账可落）；
   - 浏览器内存数学校验提取器：离线校验 `ISO 13616 IBAN Mod-97`、`ISO/IEC 7812 Luhn` 卡号、`ISO 9362 SWIFT/BIC` 及单据参考号。
2. **第 ② 舱 · 防御性外发敏感词阻断（Outbound DLP）与危机降噪预检舱**：
   - 纯蓝队防守视角：实时拦截包含止付泄密词、一次性验证码（OTP）、未掩码金融账号或高压情绪标点的外发草稿；
   - 支持本地确定性哈希脱敏预览，并可选连接本机回环 `http://127.0.0.1:11434` Ollama 离线模型生成中性行政批处理缓冲回复。
3. **第 ③ 舱 · 多币种流水穿透去重与净敞口核算舱**：
   - 本地内存 `blob:` 回单同屏比对视窗（关闭标签页即刻销毁）+ 跨时区 `UTC` 异常会话时间窗自动对齐；
   - 基于精确十进制运算自动剥离「内部同名调拨/换汇」与「银行风控挂账未出账项」，输出纯矢量 `<svg>` 资金流向拓扑图与防公式注入 CSV。
4. **第 ④ 舱 · 双模 A4 紧急止付召回与合规报案清册打印舱**：
   - 一键切换**「完整版：银行召回与经侦报案要素清册」**与**「脱敏版：外部律所/协作方通报简表（自动掩码付款主账号、完整保留外部涉诈账号）」**，原生浏览器 `@media print` A4 直出 PDF。

---

## 30 秒快速上手

```bash
git clone https://github.com/Ziqi/clearlens.git
cd clearlens

# 1. 审计静态工作台是否满足严格离线 CSP 与零外部追踪资源
python3 -m clearlens verify ./web

# 2. 运行 100% 净室合成跨国航运结算 BEC 演示基准（Apex Maritime GmbH）
python3 -m clearlens demo

# 3. 在本机回环地址（仅限 127.0.0.1）启动加固版静态工作台
python3 -m clearlens serve --host 127.0.0.1 --port 8765
```

---

## 生态协同与合规声明

- **双剑合璧**：澄镜 `ClearLens` 负责前端事件分诊、外发 `DLP` 护栏与多币种台账出表；底层浏览器/Electron 缓存（`IndexedDB / LevelDB .log`）删除记录提取与回单图片容器（`PNG iCCP / JPEG APP2`）篡改初筛由姊妹开源库 [**`starshield-forensics`**](https://github.com/Ziqi/starshield-forensics)（OpenSSF 银牌认证 `#16602`、Scorecard `8.0/10`）提供。
- **净室基准与免责声明**：本仓库内置演示数据（`Apex Maritime GmbH`、`DE89370400440532013000`、`6200000000000005`）均为国际标准虚构测试向量，零真实案件或个人隐私数据。本软件按 [MIT 开源协议](./LICENSE) 免费开放，仅供合规风控与法务对账辅助参考，不构成正式法律意见书。
