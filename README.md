# ad-whitelist-bot

从 **anti-AD**、**AWAvenue-Ads-Rule** 与 **AdGuard DNS filter** 三个项目的
发布产物/issue 中,自动收集"被报告为误报、且经维护者复核后处理"的域名,合并为
一份**每个域名都带 issue 溯源**、**与来源项目各自的发布产物零交集**的白名单;
同时作为消费端白名单的**唯一合成点**,收录三份策展引用源
(Cats-Team/AdRules dns-allowlist、anudeepND/whitelist、AdGuard exceptions
无注释条目——消费端不再自行拉取合成,只消费本仓产物)。

设计为 GitHub Actions 每日定时增量运行;零第三方依赖(纯 Python 标准库)。

```
误报白名单
 ├─ anti-AD:白名单 php 收割(adlist-maker 分支,带 issue 注释)+ issue 扫描(复核队列)
 ├─ AWAvenue:issue 扫描(维护者确认 + 主规则消失验证)
 ├─ AdGuard DNS filter:exclusions/exceptions 文件收割(编译期裁决,带 issue 注释)
 └─ 策展引用层(kind=referral):Cats-Team/AdRules dns-allowlist(注释 #N 转 issue
    链接)+ anudeepND/whitelist(2021-12 起冻结,仍每日跟文件)+ AdGuard exceptions
    无注释条目兜底 —— 无误报裁决语义的消费端原始源,收进本仓统一合成
```

## 列表章程(硬性规则,代码强制)

1. **溯源分层**。裁决型条目只收带 issue 溯源的域名——anti-AD 白名单 php 中
   无 issue 引用的条目(维护者内部策展,约 176 条)不进主列表,单独输出到
   `output/antiad_whitelist_without_issue_ref.txt` 供参考;
   需要放行其中某条时,加入 `data/manual_overrides.json` 的 `approve`
   (人工 `approve` 允许无 issue 号破例,产物中标注「无issue号」)。
   策展引用层(kind=referral)为文件来源,不做产物交集检查,但有三条护栏:
   不收紧其他来源的不变量检查键、不晋升/不改写 pending/rejected 记录
   (`state.merge_referral`)、与 CN 产物精确命中仅在报告中标注立场冲突。
2. **逐源源内零交集**(`invariants.enforce_invariants`,每跑强制):
   列表域名不得出现在**其来源项目自己的**发布产物中——anti-AD 条目查
   `anti-ad-domains.txt`(精确),AWAvenue 条目查主规则(精确 + 祖先
   `||rule^`),AdGuard DNS filter 条目查发布版 filter 块规则(精确),
   违者剔除并记入 `report.md` 的"冲突"节;人工 `approve`(无来源仓库)
   按最严格口径对全部产物检查,不能豁免本规则。祖先被拦但本域未拦的情形
   仅作信息标注(`partial_block` / `adguard_ancestor_block`),不剔除。
   跨源立场差异不剔除,由 `refresh_cross_status` 注记(2026-11-15 门槛
   实测:全局互检会消灭 AdGuard 新源 295/630 条价值并错杀现役 21 条)。

## 判定方法(核心)

### anti-AD(privacy-protection-tools/anti-AD)

排除名单本体:仓库 `adlist-maker` 分支的 `scripts/lib/white_domain_list.php`
(`value=0` 加白单域 / `1` 加白含全部子域 / `-1` 条目失效)。
> 旧的 dead-horse 仓(2023-08 停更)已废弃;现行源由现任维护者 **MkQtS**
> 维护,提交信息即 `fix #N` 格式。

判定"开发者已确认"的三层证据:

1. **白名单 php 收割**(权威):注释中引用 issue 号的直接关联;无注释引用的
   新增条目通过 `fix #N` 提交信息做 commit→issue 归因
   (`attributed_by: commit-message`)。
2. **issue 文本扫描**(补充):标题/正文命中误报关键词 → 拉取评论 → 仅当
   **维护者**(GitHub `author_association` ∈ OWNER/MEMBER/COLLABORATOR,或
   `MkQtS`/`gentlyxu`)评论命中接受短语且无拒收语义时判 confirmed。
   域名归属只取**判定评论 + issue 标题**——正文全局抽取会把汇总帖里的
   无关域拖进来。提交拦截域名类 issue(`[enhancement]`/`提交拦截域名`)的
   "已收录"是收进**黑名单**,已被闸门排除。
3. **人工复核**(终审):anti-AD 的 issue-only 确认**不直接进列表**——凡是
   真正加白,最终都会落进 php(被收割覆盖);issue-only 域名进入
   `report.md` 的待复核队列,由人裁决(见下文 manual_overrides)。

### AWAvenue(TG-Twilight/AWAvenue-Ads-Rule)

无白名单文件——误报处理方式是**从主规则移除**或**移入补充规则(Replenish)**:

1. issue 候选:标题/正文命中误报关键词,排除纯 `[enhancement]` 提交类
   (按标题匹配;标题含 误/BUG 字样的提交类仍放行);
2. 维护者 **TG-Twilight**(OWNER)评论命中接受短语 → confirmed;
3. **生效验证**:域名确实从当前 `||domain^` 主规则消失 → 自动进列表;
   issue 仍开或规则未重建 → 挂 pending,规则更新后自动晋升。

### 反转与冲突检测(每日自动)

- 逐源源内零交集:列表域出现在**其来源项目**的发布产物中(anti-AD 域在
  `anti-ad-domains.txt` 精确命中 / AWAvenue 域在主规则精确+祖先命中 /
  AdGuard DNS filter 域在发布版 filter 块规则精确命中)→ 标记 `conflict`,
  移出列表;上游解除后按剩余证据自动恢复(active/pending)。
  (典型案例:AWAvenue [#183](https://github.com/TG-Twilight/AWAvenue-Ads-Rule/issues/183)
  的 `feed-image.baidu.com` 先移除后加回;anti-AD 与 AWAvenue 对
  `audid-api.taobao.com`、`mobilelog.kugou.com` 等域立场相反。)
- **拒收保护**:`data/seed_rejections.json` 记录维护者明确拒绝放行的域名
  (隐私理由保留拦截的 `a0.app.xiaomi.com` 等);issue 的 `locked` 标记
  表示人工审计结论,任何扫描都不会覆盖。

### 人工复核层

`data/manual_overrides.json`:

```json
{
  "approve": [
    "example.org",
    {"domain": "legacy.org", "note": "公钥服务器被拦(#720)",
     "issues": [{"n": 720, "repo": "privacy-protection-tools/anti-AD"}]}
  ],
  "deny": ["another.net"]
}
```

字符串条目即普通批准;dict 条目可为人工决策附带 issue 归因(显示在
`whitelist_annotated.txt` 与 PROVENANCE 中,并顶替旧的无归因记录)。
下次运行自动应用;批准/拒绝都会体现在 `report.md` 与 PROVENANCE。

## 仓库结构

```
ad-whitelist-bot/
├── src/ad_whitelist_bot/        # 包源码(src-layout)
│   ├── cli.py                   # 命令行入口(seed / run)
│   ├── pipeline.py              # 编排:收割→扫描→晋升→overrides→不变量→渲染
│   ├── config.py                # 仓库/产物 URL/维护者/判定短语(唯一调参点)
│   ├── github.py                # 限速感知的 GitHub REST 客户端(纯标准库)
│   ├── extract.py               # 域名抽取 + 垃圾过滤(TLD 白名单/文件名后缀)
│   ├── verdict.py               # 维护者评论判定引擎(接受/拒收/代放行)
│   ├── state.py                 # 状态机(TypedDict 形状/原子写/合并/overrides)
│   ├── invariants.py            # 章程不变量(零交集强制)
│   ├── render.py                # 产物渲染(列表/溯源/报告/参考文件)
│   └── sources/
│       ├── base.py              # 共享 issue 扫描骨架(锁定/缓存/候选闸门)
│       ├── antiad.py            # anti-AD:php 解析/收割/commit 归因/issue 扫描
│       ├── awavenue.py          # AWAvenue:issue 扫描/主规则验证/晋升
│       └── adguardsdns.py       # AdGuard DNS filter:exclusions/exceptions 收割
├── tests/                       # unittest 套件(CI 四版本矩阵)
├── data/
│   ├── state.json               # 运行状态(CI 提交回仓库 = 跨日记忆)
│   ├── seed_awavenue_manual.json  # 人工审计种子(33 域 + 57 个锁定 issue)
│   ├── seed_rejections.json     # 拒收保护种子
│   └── manual_overrides.json    # 人工复核裁决层
├── output/                      # 生成产物(CI 提交回仓库)
└── .github/workflows/           # ci.yml(测试矩阵)+ daily.yml(定时运行)
```

## 使用

```bash
pip install -e .                      # 零第三方依赖,只是装 CLI 入口

ad-whitelist-bot seed                 # 首次:构建 data/state.json
ad-whitelist-bot run                  # 日常增量(1-3 分钟,约 5-10 次 REST + 数个 raw 下载)
ad-whitelist-bot run --full           # 全量回填(30-60 分钟,约 800 次 API)
ad-whitelist-bot -v run               # 调试日志
python -m ad_whitelist_bot run        # 不安装也能跑(需 PYTHONPATH=src)
```

需要 `GH_TOKEN`(或 `GITHUB_TOKEN`)环境变量; Actions 里用自带的
`github.token`(1000 req/h,增量足够),全量回填建议换 PAT(5000 req/h)。

### GitHub Actions

- **daily.yml**:每天 UTC 21:30(北京 05:30)自动增量运行,把
  `data/state.json` 与 `output/` 的变更提交回仓库;手动触发时可勾选全量。
- **ci.yml**:push/PR 时在 Python 3.12 单版本跑冒烟测试(全量多版本矩阵在本地跑)。

## 输出(`output/`)

| 文件 | 说明 |
|---|---|
| `merged_false_positive_whitelist.txt` | **主列表(后缀档)**,一行一个域名,放行语义覆盖全部子域 |
| `merged_false_positive_whitelist_exact.txt` | **精确档**:裸域(两段)裁决型条目,消费端须按整域精确匹配、不参与祖先连坐 |
| `whitelist_annotated.txt` | **带溯源注释版**:每行 `域名  # 仓库 issue号(报告的问题;处置)` |
| `merged_false_positive_whitelist_adguard.txt` | 主列表的 `@@||domain^` 格式(AdGuard DNS 语义本身即后缀放行,精确档不适用此格式) |
| `PROVENANCE.md` | 每个域名 → 来源仓库 → 判定依据 → issue 链接(表格版溯源) |
| `antiad_whitelist_without_issue_ref.txt` | anti-AD 无 issue 引用条目(仅参考) |
| `report.md` | 当次运行报告:新增/晋升/批准/冲突/复核队列/php 变更/策展引用并入与立场冲突 |

**双档语义**(2026-11-16):裁决型来源(anti-AD php / AWAvenue / AdGuard DNS
filter)的裸域条目,是上游项目在自家单源语义下的整域裁决;多源消费栈若按后缀
放行会连坐清除其他黑名单源的同族广告规则(tanx/yximgs/ucweb/co.in 等整族,
实测 ~1,100 条),故单列精确档。策展引用层的裸域条目(如 cloudfront.net/
amazonaws.com)本意即基础设施放行,留在主文件按后缀档处理。

## 开发

```bash
python -m unittest discover -s tests -v     # 测试(无需安装)
python -m compileall -q src                 # 语法检查
```

约定:`config.py` 是唯一的调参点(仓库、短语、维护者);三个项目的差异逻辑
各自收敛在 `sources/<project>.py`,共享机制在 `sources/base.py`;状态形状
用 `TypedDict` 描述在 `state.py`;任何行为改动先补测试。

## 已知局限

- AWAvenue 侧"无维护者评论但实际已移除"的 issue 不会被自动确认(自动化只认
  评论信号),由人工审计种子覆盖;
- `.md` 后缀按文件名处理(Moldova 国家域会被漏采,影响可忽略);
- `--full` 回填受 API 限速影响,匿名/细粒度 token 可能需要数小时(客户端会
  自动休眠到限速重置)。

## License

MIT
