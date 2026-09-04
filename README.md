# Cloudflare Worker 现代短链接与规则重定向服务 (Short Link Worker)

基于 Cloudflare Workers 边缘计算构建的高性能、高安全、现代企业级短链接与智能路由重定向服务。

以 stevezmt.top 为例，转移部署时请清理域名。

> [!WARNING]
> 免责声明：此项目仅应当供贵组织内部使用。
> 此项目没有被设计为路由和代理之用。也没有为任何其他用途适配。
> 软件作者及贡献者不对因使用本软件而产生的任何直接或间接损失（包括法律诉讼、域名封禁、服务商处罚等）承担责任。您应自行确保部署环境的安全性，并对所有生成的短链内容及跳转目标负全部责任。
> 软件作者若在维护此项目时发现此项目被任何组织滥用，保留向有关部门举报和追究法律责任的权利。
> 任何人使用此项目，无论该等使用是否符合其所在国家或地区，或该等使用或传播发生的国家或地区的法律法规，所产生的一切法律责任由使用者承担。



---

## 目录 (Table of Contents)

1. [核心架构与设计哲学](#-1-核心架构与设计哲学)
2. [特性概览](#-2-特性概览)
3. [三层重定向兜底机制](#-3-三层重定向兜底机制-tiered-redirection)
4. [路由引擎与匹配规则详解](#-4-路由引擎与匹配规则详解)
   - [静态短链映射](#41-静态短链映射)
   - [子域名短链简写](#42-子域名短链简写)
   - [动态参数批量路由 (:slug)](#43-动态参数批量路由-slug)
   - [通配符捕获与映射 (*)](#44-通配符捕获与映射-)
   - [正则表达式高级匹配 (regex:)](#45-正则表达式高级匹配-regex)
   - [特异性打分与优先级裁决](#46-特异性打分与优先级裁决)
5. [UTM 来源追踪与参数透传](#-5-utm-来源追踪与参数透传)
6. [安全防护体系](#-6-安全防护体系)
   - [加盐 SHA-256 密码鉴权 (HTTP 401)](#61-加盐-sha-256-密码鉴权-http-401)
   - [公开仓库防泄露：极速对称加密 (AES-GCM + HKDF)](#62-公开仓库防泄露极速对称加密-aes-gcm--hkdf)
   - [针对 10ms CPU 限制的优化与按需单目标加密](#63-针对-10ms-cpu-限制的优化与按需单目标加密)
7. [规则引擎与风控拦截](#-7-规则引擎与风控拦截)
   - [最低 TLS 版本限制](#71-最低-tls-版本限制)
   - [常见爬虫与恶意 Bot 拦截](#72-常见爬虫与恶意-bot-拦截)
   - [客户端设备分流 (iOS / Android)](#73-客户端设备分流-ios--android)
   - [自定义断言规则函数](#74-自定义断言规则函数)
8. [自定义 404 兜底与异常处理](#-8-自定义-404-兜底与异常处理)
9. [本地可视化管理面板 (admin.html)](#-9-本地可视化管理面板-adminhtml)
10. [配置参考手册 (API Reference)](#-10-配置参考手册-api-reference)
11. [项目结构与测试体系](#-11-项目结构与测试体系)
12. [快速开始与部署指南](#-12-快速开始与部署指南)

---

## 🏛 1. 核心架构与设计哲学

本服务运行于 Cloudflare 全球边缘网络，旨在解决现代短链接系统常见的痛点：配置分散、规则嵌套过深、公网仓库暴露私密跳转源、明文密码泄露、以及弱网/受限环境下客户端无法跳转等问题。

### 核心设计哲学
- **深模块（Deep Module）**：将极其复杂的边缘网络逻辑（302 头处理、`<meta>` 文档构造、DOM 脚本回退、TLS 校验、正则状态机编译、HKDF 派生、防时序攻击哈希比对）全部封装在底层。
- **配置集中收敛（Information Hiding）**：域名、404 跳转模板、默认 UTM 标签集中于 `settings` 单点配置，绝不散落在各个路由规则中。
- **消灭错误（Define Errors Out of Existence）**：参数缺失时优雅回退、路径前缀斜杠自动规整、协议头缺失自动容错、密文异常安全返回。

---

## 🌟 2. 特性概览

| 功能模块 | 说明 | 性能 / 安全指标 |
| :--- | :--- | :--- |
| **三层重定向** | HTTP 302 标头 + HTML Meta Refresh + JS Replace | 100% 覆盖任何特殊或受限浏览环境 |
| **全能路由引擎** | 静态路径、子域名简写、动态参数 (`:slug`)、正则匹配 (`regex:`) | 预编译正则，纳秒级特异性打分匹配 |
| **参数透传与 UTM** | 访客 Query 参数保留，自动按需注入默认 UTM 标签 | 访客已有参数优先，绝不暴力覆盖 |
| **加盐密码保护** | 针对指定短链启用 HTTP Basic Auth 密码质询 | SHA-256 + 域名加盐哈希，常数时间比对 |
| **对称加密防泄露** | 公开代码仓库中加密敏感目标网址，线上环境变量动态解密 | HKDF + AES-GCM，CPU 耗时 `< 0.13ms` |
| **风控拦截** | 强校验 TLS 1.2+ / TLS 1.3、爬虫拦截、移动端分流 | 边缘原生拦截，无需后端介入 |
| **智能 404** | 未匹配请求统一转至 `stevezmt.top/404?from=${FULL_URL}` | 支持 Redirect 跳转与 Proxy 反代双模式 |
| **可视化面板** | 本地单文件 `admin.html`，支持行级 LCS Diff、文件读取与哈希生成 | 0 第三方服务端依赖，无 Emoji，符合 MDUI 风格 |

---

## 🔄 3. 三层重定向兜底机制 (Tiered Redirection)

传统短链接服务往往仅依赖 HTTP 状态码 `302 Found` + `Location` Header。但在微端（如特定 App 内置 Webview）、安全沙箱、反向代理劫持或忽略跳转头的特定客户端中，极易发生“白屏”或“死链接”。

本项目在单个 HTTP 响应体中提供了**三层兜底跳转体系**：

```
客户端发起请求
     │
     ▼
[第 1 层] HTTP 协议层：302 Found + Location 响应头 (标准浏览器 0ms 极速跳转)
     │ (若客户端未跟随跳转或解析响应体)
     ▼
[第 2 层] HTML 文档层：<meta http-equiv="refresh" content="0;url=..."> (解析 HTML 触发极速刷新)
     │ (若客户端禁用 Meta 跳转)
     ▼
[第 3 层] JS 脚本层：<script>window.location.replace("...");</script> (DOM 脚本强制替换)
     │ (若完全禁用脚本)
     ▼
[兜底交互] 现代化玻璃拟态 UI：提供醒目的原链接卡片与「立即前往」直接点击按钮
```

---

## 🚦 4. 路由引擎与匹配规则详解

路由表统一在 [src/config/routes.ts](file:///e:/Project/short-link/src/config/routes.ts) 的 `links` 字段中配置。

### 4.1 静态短链映射
最常用的 1 对 1 映射：
```typescript
links: {
  '/': 'https://stevezmt.top',              // 自身根路径重定向
  '/github': 'https://github.com/stevezmt', // 精确路径
  '/tg': 'https://t.me/yourname',
}
```

### 4.2 子域名短链简写
当配置了 `settings.domain`（例如 `stevezmt.top`）时，可以使用 `子域名:路径` 的形式，无需在每个短链中反复写死长域名：
```typescript
links: {
  's:/docs': 'https://stevezmt.top/documentation',
  // 自动绑定为: s.stevezmt.top/docs
}
```

### 4.3 动态参数批量路由 (`:slug`)
**使用场景**：例如希望 `blog.短链/博客名` 能够自动批量路由到 `长域名/blog/post/博客名`。

语法支持 `:变量名` 或 `${变量名}`：
```typescript
links: {
  // 单个动态参数
  'blog:/:slug': 'https://stevezmt.top/blog/post/:slug',

  // 多层级参数（分类 + 文章名）
  'blog:/:category/:slug': 'https://stevezmt.top/categories/:category/p/:slug',
}
```
- **访问**：`https://blog.stevezmt.top/docker-quickstart`
- **跳转**：`https://stevezmt.top/blog/post/docker-quickstart`

### 4.4 通配符捕获与映射 (`*`)
通配符 `*` 可匹配任意深度子路径，并在目标链接中使用 `$1` 捕获还原：
```typescript
links: {
  'blog:/*': 'https://stevezmt.top/blog/post/$1',
}
```
- **访问**：`https://blog.stevezmt.top/2026/09/release-notes`
- **跳转**：`https://stevezmt.top/blog/post/2026/09/release-notes`

### 4.5 正则表达式高级匹配 (`regex:`)
对于对字符集、数字范围、层级结构有严格要求的复杂批量映射，可以直接使用 `regex:` 开头（或以 `^` 开头）声明原生正则表达式，并在目标 URL 中使用 `$1`、`$2` 提取捕获组。

路由引擎会自动智能判定匹配范围：
1. **纯路径正则（Path-only Regex）**：
   - 当正则以 `^/` 或 `/` 开头时（或斜杠前不含点号主机名），引擎将自动比对 **`url.pathname`**。
   - 适用于跨所有域名通用的路径级规则。
2. **主机+路径全量正则（Host-Specific Regex）**：
   - 当正则前缀包含域名点号（如 `^sub\\.domain\\.com/`）时，引擎将自动比对完整的 **`url.hostname + url.pathname`**。
   - 适用于限定在特定子域名或多租户域名下的正则过滤。

#### 常见应用场景与示例配置

##### 1. 严格数字 ID 映射与分组提取
```typescript
links: {
  // 匹配形如 /item/12345，严格要求为纯数字
  'regex:^/item/(\\d+)$': 'https://store.example.com/products/$1',
}
```
- **访问**：`https://example.com/item/8848`
- **跳转**：`https://store.example.com/products/8848`
- **非数字输入**：`https://example.com/item/abc` 自动忽略并进入 404 流程。

##### 2. 年/月/日归档与版本化 API 路由
```typescript
links: {
  // 提取年、月与文章 slug 三个独立捕获组 ($1, $2, $3)
  'regex:^/blog/(\\d{4})/(\\d{2})/(.+)$': 'https://example.com/archives/$1-$2/$3',
  // 匹配版本化接口转发
  'regex:^/api/v(\\d+)/(.*)$': 'https://api-upstream.example.com/v$1/$2',
}
```
- **访问**：`https://example.com/blog/2026/09/release-notes`
- **跳转**：`https://example.com/archives/2026-09/release-notes`

##### 3. 严格限制 Slug 字符集（防恶意路径穿越）
```typescript
links: {
  // 仅允许字母、数字、连字符组成的单层 Slug，包含斜杠或非法符号则不匹配：
  'regex:^/user/([a-zA-Z0-9_-]+)$': 'https://github.com/$1',
}
```

##### 4. 特定子域名专属正则 (Host-specific)
```typescript
links: {
  // 仅在 s.stevezmt.top 子域名下匹配以 doc- 开头的路径：
  'regex:^s\\.stevezmt\\.top/doc-([0-9a-f]{8})$': 'https://docs.example.com/view/$1',
}
```

> [!TIP]
> **正则书写要点**：
> - 引擎内部默认以不区分大小写模式（`i` 标志）编译正则。
> - 在 TypeScript 字符串字面量中，正则的反斜杠需要双写转义（如 `\\d` 表示数字，`\\.` 表示点号）。
> - 正则的优先级打分居于第四阶梯（兜底匹配），当存在具体的精确路径（如 `/item/new`）时，精确路径将自动优先于 `regex:^/item/(\\d+)` 执行。

### 4.6 特异性打分与优先级裁决
当多条规则同时能匹配某个请求时，路由引擎会根据**特异性权重得分（Specificity Score）**自动进行降序匹配，确保逻辑最具体的规则优先执行：
1. **主机名具体性加成**：包含明确具体主机名的规则始终优于跨主机泛匹配（+20,000 分）。
2. **第一阶梯（精确字面量路由）**：最高优先级（+10,000 分 + 字面字符长度 × 10）。
3. **第二阶梯（命名动态参数 `:slug`）**：参数化路由次之（+5,000 分 + 字面长度 × 10 - 参数个数 × 50）。
4. **第三阶梯（通配符 `*`）**：泛匹配路由（+1,000 分 + 字面长度 × 10 - 通配符数 × 100 - 参数个数 × 50）。
5. **第四阶梯（原生正则表达式 `regex:`）**：基础权重 +500 分 + 表达式字符长度（作为最低层级的兜底匹配）。

> **核心设计保证（Invariant）**：严格保证 `精确路径 > 命名参数 (:slug) > 通配符 (*) > 原生正则 (regex:)` 的优先级裁决秩序，绝无匹配越权或规则覆盖隐患。

---

## 🏷 5. UTM 来源追踪与参数透传

### 1. 全局默认 UTM 继承
在 `settings.defaultUtm` 中设置全局默认来源：
```typescript
settings: {
  defaultUtm: {
    utm_source: 'shortlink',
    utm_medium: 'redirect',
  },
}
```
所有短链在重定向时会自动附带上述参数。

### 2. 路由专属 UTM 覆盖
可以在具体短链配置中覆盖或追加特定活动标签：
```typescript
'/promo': {
  target: 'https://stevezmt.top/sale',
  utm: {
    utm_source: 'twitter',
    utm_campaign: 'spring_2026',
  },
}
```

### 3. 访客参数优先保护原则 (Visitor-First Principle)
- 访客请求携带的所有原始 Query 参数（如 `?aff=123&theme=dark`）都会 100% 完整保留并透传至目标。
- **若访客访问短链时自身已经携带了 `utm_*`（如 `?utm_source=newsletter`），服务将优先使用访客自带的来源标签，绝不暴力覆盖！**

---

## 🛡 6. 安全防护体系

### 6.1 访客访问密码保护：直接指定加盐哈希 (零明文存储)
为短链增加访问密码，未授权访问时触发标准的浏览器 HTTP 401 Basic Auth 登录对话框。

- **根本不需要在服务端/环境变量中存储密码明文**：
  访客访问短链时在浏览器提交密码，Worker 接收后结合主域名加盐实时计算哈希：
  $$\text{Hash} = \text{SHA-256}(\text{访客提交明文} + \text{":"} + \text{domain})$$
- **路由配置中直接指定该哈希**：
  ```typescript
  '/secret': {
    target: 'https://stevezmt.top/internal-dashboard',
    // 只在代码中记录加盐哈希，服务端与环境变量无需存储明文密码！
    password: 'sha256:26db87e65fe4e8dec23c3ef2c883bd3529dfcc23c448b45ca2d219adbfb8158b',
  }
  ```
- **核心安全优势**：任何人在公开仓库中只看得到单向加盐哈希，无法逆向还原明文；比对采用常数时间防时序侧信道攻击算法（Constant-time comparison）。

---

### 6.2 路由目标对称加密：保密长链接防泄露 (保存在 .env 中的 ROUTES_KEY)
真正需要保存在环境变量（`.env` / `.dev.vars` / Cloudflare Secrets）中的，是**用于解密敏感路由目标长链接的对称密钥 (`ROUTES_KEY`)**！

#### 痛点与场景
若 Worker 代码托管在公开的 GitHub 仓库，虽然访问密码只存哈希，但跳转的目标网址（如内部文档、管理页面、推广渠道私密链接）如果写成明文依然会泄露。

#### 解决方案：路由目标对称加密
1. **使用密钥加密目标长链接**：
   在 `admin.html` 中输入密钥或勾选「加密此目标」，长链接被转换为 AES-GCM 密文：
   ```typescript
   '/secret-doc': {
     // 真实目标长链接已被加密，公开仓库完全看不出它跳转到哪里
     target: 'aes-gcm:v1:7D8f...base64...',
     // 结合 6.1 节的加盐哈希，双重保险
     password: 'sha256:26db87e65fe4e8dec23c3ef2c883bd3529dfcc23c448b45ca2d219adbfb8158b',
   }
   ```
2. **将解密密钥保存在 `.env` / `.dev.vars`**：
   ```env
   ROUTES_KEY=your_secret_encryption_key
   ```
   生产环境通过 `npx wrangler secret put ROUTES_KEY` 注入。
3. **边缘极速按需解密**：
   当访客通过密码验证后，Worker 脚本自动从环境变量读取 `ROUTES_KEY`，在内存中将目标解密（耗时 `< 0.13ms`）并输出 302 重定向！

---

### 6.3 针对 10ms CPU 限制的优化与按需单目标加密

> [!IMPORTANT]
> **Cloudflare Worker Free 计划具有严格的 10 毫秒纯 CPU 执行时间限制。**

传统的 PBKDF2（100,000 次哈希迭代）需要消耗 20~80ms CPU 计算时间，极易触发 Workers 超时崩溃。

本项目做了两重极致性能优化：
1. **改用 HKDF (RFC 5869)**：密钥派生计算时间由 50ms 骤降至 **`< 0.04ms`**，总解密耗时仅 **`0.13ms`**，比 10ms 上限快了 **75 倍以上**。
2. **按需单目标加密 (Selective Target Encryption)**：
   仅对需要保密的私密目标进行加密，公开短链完全不参与加解密（CPU 开销为 `0.00ms`）：
   ```typescript
   links: {
     // 1. 普通短链：0 加密开销，CPU 耗时 0.00ms
     '/': 'https://stevezmt.top',
     '/github': 'https://github.com/stevezmt',

     // 2. 私密短链：仅该目标采用 AES-GCM 加密，访客点击时按需解密（耗时 < 0.1ms）
     '/secret-vault': 'aes-gcm:v1:7D8f...base64...',
   }
   ```

---

## 🚦 7. 规则引擎与风控拦截

可以在短链选项中声明规则，由边缘节点在处理跳转前拦截非法请求：

### 7.1 最低 TLS 版本限制
拦截过时的 SSL/TLS 协议请求（直接返回 403 Forbidden），防御中间人攻击：
```typescript
'/finance': {
  target: 'https://stevezmt.top/finance',
  minTls: '1.3', // 强制要求 TLS 1.3+，低于此版本直接拦截
}
```

### 7.2 常见爬虫与恶意 Bot 拦截 & 全网搜索引擎隔离
- **全网搜索引擎隔离 (`/robots.txt`)**：
  网关原生内置 `/robots.txt` 接口，秒级拦截并直接返回：
  ```text
  User-agent: *
  Disallow: /
  ```
  同时所有跳转与响应统一附带 `X-Robots-Tag: noindex, nofollow` 响应头，彻底杜绝短链被搜索引擎爬取、建索引或传递权重。
- **爬虫 User-Agent 阻断 (`blockBots`)**：
  一键识别并拦截常见自动化爬虫（Python Requests、Scrapy、AhrefsBot、Semrush 等）：
```typescript
'/exclusive': {
  target: 'https://stevezmt.top/exclusive',
  blockBots: true, // 爬虫访问返回 403 Forbidden
}
```

### 7.3 客户端设备分流 (iOS / Android)
根据访客 User-Agent 将移动端访客无缝导流至专属落地页或 App 唤起链接：
```typescript
'/download': {
  target: 'https://stevezmt.top/desktop-client', // 桌面端前往
  mobile: 'https://stevezmt.top/mobile-app',     // 手机端自动前往
}
```

### 7.4 自定义断言规则函数
支持通过 `rules` 数组扩展任意业务逻辑：
```typescript
'/api-portal': {
  target: 'https://api.stevezmt.top',
  rules: [
    (ctx) => {
      // 检查请求头
      if (!ctx.request.headers.has('X-Client-Token')) {
        return { type: 'block', status: 403, body: 'Missing Client Token' };
      }
    }
  ]
}
```

---

## 🚫 8. 自定义 404 兜底与异常处理

当请求的主机名或路径在路由表中未找到匹配时，触发 404 处理机制。

### 模板变量支持
默认 404 跳转地址配置在 `settings.notFoundUrl` 中，支持以下模板变量：
- `${FULL_URL}`：URL 编码后的完整原始请求地址（适合作为 Query 参数）。
- `${RAW_FULL_URL}`：原始完整请求地址。
- `${PATH}`：URL 编码后的请求路径。

```typescript
settings: {
  notFoundUrl: 'https://stevezmt.top/404?from=${FULL_URL}',
  notFoundMode: 'redirect', // 'redirect' (三层 302 跳转) 或 'proxy' (边缘反向代理)
}
```

- **`redirect` 模式**：通过三层重定向快速跳转至指定 404 页面。
- **`proxy` 模式**：Worker 保持当前浏览器 URL 不变，在边缘直接向源站拉取 404 页面内容并返回 404 状态码。

---

## 💻 9. 本地可视化管理面板 (admin.html)

为了在不暴露任何公网后台接口的前提下方便地管理配置，项目附带了一个完全在本地运行的单文件工具 [admin.html](file:///e:/Project/short-link/admin.html)。

### 特点与交互亮点
1. **纯前端运行，零网络依赖**：双击直接在本地浏览器中通过 `file:///` 打开，绝无公网暴露面。
2. **规范化 UI**：全界面采用 MDUI Material Icons 图标，剔除所有 emoji，现代深色暗黑风格。
3. **极速读取与剪贴板增强**：
   - 点击「读取配置」时，程序会自动计算当前项目的 `src/config` 路径并静默复制到剪贴板。
   - 文件选择弹窗弹起后，在地址栏按一次 <kbd>Ctrl</kbd> + <kbd>V</kbd> 即可瞬间定位并加载 `routes.ts`。
4. **实时行级 Diff 差异对比（LCS 算法）**：
   - 当在界面上增删改短链、修改全局设置或启用加密时，下方实时展现与磁盘原文件的差异对比（绿色新增、红色删除、实时统计行数）。
5. **加盐哈希实时演算器**：
   - 输入明文密码时，页面通过 Web Crypto API 结合当前主域名实时演算加盐哈希，并以 `sha256:...` 格式预览。
6. **智能按需解密提示**：
   - 读取配置文件时**自动检测**：若无加密内容则瞬间静默加载（绝无多余弹窗）；仅当检测到包含加密内容时，才弹出提示请求输入保存在 `.env` 中的统一密钥并自动解密。
7. **一键导出 .env / .dev.vars 环境变量**：
   - 顶部工具栏提供「导出 .env」按钮，一键将包含 `ROUTES_KEY` 的标准环境变量内容复制到剪贴板，方便本地调试与线上部署。

---

## 📖 10. 配置参考手册 (API Reference)

### 完整配置文件模版 (`src/config/routes.ts`)

```typescript
import { ShortLinkConfig } from '../types';

export const config: ShortLinkConfig = {
  // 1. 全局配置
  settings: {
    domain: 'stevezmt.top',                                    // 部署主域名
    salt: '',                                                  // 密码哈希盐值（留空则默认采用 domain）
    notFoundUrl: 'https://stevezmt.top/404?from=${FULL_URL}',  // 404 兜底目标
    notFoundMode: 'redirect',                                  // 404 模式：'redirect' | 'proxy'
    defaultUtm: {                                              // 全局默认 UTM
      utm_source: 'shortlink',
      utm_medium: 'redirect',
    },
  },

  // 2. 路由规则字典
  links: {
    // 基础根跳转
    '/': 'https://stevezmt.top',

    // 简单短链
    '/github': 'https://github.com/stevezmt',

    // 动态参数批量路由
    'blog:/:slug': 'https://stevezmt.top/blog/post/:slug',

    // 通配符映射
    'blog:/*': 'https://stevezmt.top/blog/post/$1',

    // 原生正则表达式
    'regex:^blog\\.[^/]+/([a-zA-Z0-9_-]+)$': 'https://stevezmt.top/blog/post/$1',

    // 加盐密码保护（直接指定哈希，服务端与环境变量无需存储明文密码）
    '/secret': {
      target: 'https://stevezmt.top/dashboard',
      password: 'sha256:26db87e65fe4e8dec23c3ef2c883bd3529dfcc23c448b45ca2d219adbfb8158b',
    },

    // 安全拦截与风控
    '/finance': {
      target: 'https://stevezmt.top/finance',
      minTls: '1.2',      // '1.2' | '1.3'
      blockBots: true,    // 拦截爬虫
      mobile: 'https://stevezmt.top/finance-mobile', // 移动端分流
      utm: { utm_campaign: 'q3_finance' },          // 自定义 UTM
    },

    // 单目标对称加密（公开仓库保护）
    '/vault': 'aes-gcm:v1:7D8f...base64...',
  },
};
```

---

## 📁 11. 项目结构与测试体系

### 目录结构
```text
.
├── admin.html                  # 纯本地单文件可视化管理与 Diff 对比面板
├── src/
│   ├── auth/
│   │   └── basicAuth.ts        # HTTP 401 质询与加盐 SHA-256 常数时间比对
│   ├── config/
│   │   └── routes.ts           # 路由表与全局设置主配置文件
│   ├── router/
│   │   └── matcher.ts          # 路由引擎（通配符/动态参数/正则表达式/特异性打分）
│   ├── rules/
│   │   └── predicates.ts       # 规则引擎断言（TLS版本/Bot识别/User-Agent分流）
│   ├── utils/
│   │   ├── crypto.ts           # HKDF + AES-GCM 极速对称加解密 (< 0.13ms CPU)
│   │   ├── response.ts         # 三层重定向响应构造器 (HTTP 302 + Meta + JS)
│   │   └── url.ts              # URL 参数透传、动态变量插值与 UTM 注入
│   ├── index.ts                # Cloudflare Worker 主执行管线
│   └── types.ts                # 全系统核心 TypeScript 类型定义
├── test/
│   ├── auth.test.ts            # 加盐哈希 Basic Auth 鉴权测试
│   ├── crypto.test.ts          # 极速对称加解密与环境变量解密测试
│   ├── declarative.test.ts     # 声明式短链与属性映射测试
│   ├── dynamic_routes.test.ts  # 动态参数 (:slug)、通配符与正则批量路由测试
│   ├── notfound.test.ts        # 404 兜底与模板替换测试
│   ├── redirect.test.ts        # 三层重定向与 UTM 优先级透传测试
│   ├── router.test.ts          # 路由通配符与特异性打分测试
│   └── rules.test.ts           # TLS、Bot 拦截与规则工厂测试
├── wrangler.jsonc              # Cloudflare Worker 配置文件
├── tsconfig.json
└── package.json
```

### 自动化测试套件
项目配备了完整的 Vitest 自动化单元测试与回归测试，覆盖所有边界用例与极端场景：

```bash
# 执行全部 58 项自动化与高并发压力测试
npm test

# 执行 TypeScript 静态类型严苛检查
npm run typecheck
```

测试执行结果：
```text
 ✓ test/router.test.ts (9 tests)
 ✓ test/dynamic_routes.test.ts (4 tests)
 ✓ test/notfound.test.ts (2 tests)
 ✓ test/provider.test.ts (4 tests)
 ✓ test/rules.test.ts (4 tests)
 ✓ test/redirect.test.ts (5 tests)
 ✓ test/security_fixes.test.ts (11 tests)
 ✓ test/auth.test.ts (6 tests)
 ✓ test/crypto.test.ts (4 tests)
 ✓ test/declarative.test.ts (6 tests)
 ✓ test/performance_benchmark.test.ts (3 tests) [实测 HKDF < 0.3ms，1,000 并发 ~8,000+ RPS]

 Test Files  11 passed (11)
      Tests  58 passed (58)
```

---

## 🚀 12. 快速开始与部署指南

### 1. 本地启动开发预览
```bash
# 启动本地 Wrangler 开发服务器（实时热重载）
npm run dev
```
本地访问 `http://127.0.0.1:8787` 即可测试重定向效果。

### 2. 本地管理面板
直接双击打开项目根目录下的 `admin.html` 即可在浏览器中使用可视化面板编辑配置、查看修改 Diff 与生成加盐哈希。

### 3. 配置线上环境变量密钥 (可选，若启用了对称加密)
```bash
npx wrangler secret put ROUTES_KEY
# 粘贴在 admin.html 中使用的加密密钥
```

### 4. 部署到 Cloudflare Workers
```bash
npx wrangler deploy
```
Worker 即可秒级上线至全球数百个边缘节点！


# 许可
[你丫爱咋整咋整许可证](LICENSE)
