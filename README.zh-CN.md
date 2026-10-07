# dsh-plugin-reverse

DeepSeek Harness 的 JavaScript 逆向工程工具包：**先评估路线，再按路线产出可交付的结果**。

[English](./README.md) · **简体中文**

- **静态还原（重点）**：把抠出来的前端混淆 JS 变成**可在纯 Node 中独立运行**的计算函数
  ——剥离 `window`/`document`/`navigator`/`canvas` 等宿主依赖，抹平环境差异，
  不需要浏览器、不需要注入页面，就能独立计算 sign、加密请求体、解密响应。
- **辅助定位**：生成 Hook 脚本，捕获函数入参与返回值**以及调用栈**，用于调试取证、定位加密入口。
- **验算**：内置 AES / RSA / MD5 / SHA / HMAC / 循环异或 / 单字节爆破 / 大数模幂，
  支持用已知密文、密钥、IV 快速复算。

> **适用范围**：本插件面向**你自己有权分析的代码**——自有项目、已授权的安全测试、
> 恶意样本分析、CTF、以及互通性研究。工具本身是通用的调试与静态分析技术，
> 不对任何特定目标做针对性绕过。Hook 会记录函数入参与返回值，可能包含凭证类数据，
> 请只在你被授权分析的环境中使用。**不要用它去处理他人的账号或系统。**

---

## 1. 能力矩阵

| 工具 | 作用 | 典型产出 |
|---|---|---|
| `rev_assess` | **每次逆向前先跑它**：判断 Hook 是否可行、静态还原是否可行，给出卡点与执行计划 | Markdown 评估报告 |
| `rev_hook_generate` | 生成浏览器可执行的 Hook 脚本（WebCrypto / CryptoJS / JSEncrypt / 网络层 + 自动发现） | 自包含 `.js` 脚本 |
| `rev_extract_pure` | **静态还原**：依赖闭包抽取 + 环境注入，产出无宿主依赖的纯算模块 | `pure.mjs` / `env.mjs` / `demo.mjs` |
| `rev_deobfuscate` | 语义等价的安全重写（转义还原、常量折叠、成员访问规范化）+ 混淆特征识别 | 重写后的源码 + 分析报告 |
| `rev_crypto_calc` | 20 种密码学验算操作，覆盖标准库与手写大数两条路径 | 结构化验算结果 |

---

## 2. 安装

需要 Node.js ≥ 24。`lib/` 构建产物已随仓库提交，从 GitHub 源码安装**不需要**任何构建授权。

**方式一：直接装（推荐）**

```sh
dsh plugin --profile web add github:wangyin572/dsh-plugin-reverse
```

**方式二：本地 clone 后安装（要改代码时用）**

```sh
git clone https://github.com/wangyin572/dsh-plugin-reverse.git
cd dsh-plugin-reverse
npm install                          # 装运行时依赖（@deepseek-ai/* 与 acorn）
dsh plugin --profile web add "$(pwd)"
```

然后重启该 profile。验证是否生效：

```sh
dsh --profile web --dump-config | grep -A3 dsh-plugin-reverse
```

> **本地路径安装时 `npm install` 不是可选项。** `dsh plugin add "$(pwd)"` 走的是 `link:`：
> pnpm 只创建符号链接，不会为它安装依赖，所以运行时用到的 `@deepseek-ai/*` 与 `acorn`
> 得由仓库自己的 `node_modules` 提供，否则报 `ERR_MODULE_NOT_FOUND`。
> `lib/` 已在版本库里，不需要再构建；只有改了 `src/` 才要 `npm run build` 并一起提交。

安装后模型侧会出现上表的 5 个工具。运行时依赖 `@deepseek-ai/cordis`、`@deepseek-ai/dsh-tools`、
`@deepseek-ai/schemastery` 与 `acorn`，全部公开在 npm 上。注意标签不同：
`dsh-tools@0.2.0-rc.2` 发布在 `next` 标签下，而 `cordis` `~4.0.4` 与 `schemastery`
`~3.18.4` 从 `latest` 解析。前三个声明为 `peerDependencies`：DSH 的 profile 解析层会把它们
指向宿主安装目录里的那一份实例（profile 里 pnpm 的 `autoInstallPeers` 是关闭的，不会装出重复实例）。

### 免构建的预打包

`npm pack` 会产出一个可直接安装的压缩包，里面已含构建好的 `lib/` 与文档：

```sh
npm pack
dsh plugin --profile web add ./dsh-plugin-reverse-0.1.0.tgz
```

### 被社区目录收录

社区插件目录靠 GitHub topic 自动发现，给仓库加上 **`dsh-plugin`** 话题即可（网页 Settings → Topics，
或 `gh repo edit --add-topic dsh-plugin`）。爬虫读取**仓库根目录**的 `package.json`，本仓库已满足：

- `dsh.bundle.patch` 指向仓库内的相对路径 → `./cordis.patch.yml` ✅
- 仓库公开、未归档；`description` 会作为目录里的一行简介 ✅

> **不要再往这个文件里加 `dsh.profile`。** 官方文档写得很明确：组合包声明 `dsh.bundle`，
> profile 声明 `dsh.profile`，**没有东西同时是两者**。`dsh.profile` 属于 profile 目录的
> `package.json`，由 `dsh plugin add` 负责写入；部分安装器（如 find-plugin）会把
> 「bundle/profile 混用」的仓库当作无效候选直接过滤掉。

### 配置

在 profile 的 `cordis.patch.yml` 里按行 `id` 覆盖：

```yaml
- id: reverse-toolkit
  name: 'dsh-plugin-reverse'
  config:
    maxSourceBytes: 2000000   # 单次分析允许的最大源码字节数
    hookLogLimit: 2000        # Hook 脚本日志缓冲区上限
    hookAutoDiscover: true    # Hook 是否默认自动发现可疑函数
```

不写 `config` 段也能用，全部字段都有默认值。

---

## 3. 使用流程

### 3.1 第一步永远是评估

```
rev_assess(code = <抠出来的那一段 JS>)
```

报告会给出四种结论之一：

| 结论 | 含义 |
|---|---|
| `static-first` | 代码静态完整可见、混淆程度低 → 直接还原 |
| `hook-then-static` | 两条路都可行 → **先 Hook 取一组真实的「输入 → 输出」**，再还原并逐字节比对 |
| `hook-first` | 存在 `eval` / `new Function` / `with`，静态看不到真实逻辑 → 只能先 Hook |
| `blocked` | 信息不足（例如逻辑在 Worker/WASM 中），需要补充材料 |

同时给出：混淆程度评分、特征清单、**入口候选排序**、必须采集的环境值、以及有序执行计划。

### 3.2 路线①：Hook 定位入口

```
rev_hook_generate(targets = [{ object: "window", method: "makeSign" }])
```

把返回的脚本保存为 `.js`，在目标页面执行（DevTools 控制台 / Sources → Snippets / CDP
`Page.addScriptToEvaluateOnNewDocument`）。执行后：

```js
__revHook.dump()    // 查看捕获记录
__revHook.save()    // 导出 JSON
__revHook.unhook()  // 还原所有被替换的方法
```

每条记录都带**调用栈**——这是定位「谁在调用加密函数」最有效的信息。

### 3.3 路线②：静态还原（重点）

```
rev_assess(code = ...)                    # 先确认可行
rev_deobfuscate(code = ...)               # 预处理：转义还原 / 常量折叠 / 成员访问规范化
rev_extract_pure(code = ..., entry = ["makeSign"])
```

产出三个文件，把它们落盘后**直接运行**验证：

```sh
node demo.mjs
```

`pure.mjs` 的形态：

```js
export function createRuntime(env) {
  // 宿主对象全部由 env 注入，而不是逐个改写引用点
  const { navigator, screen, document, btoa } = env

  // ---- 来自原文件第 4 行：_0x1a2b (function) ----
  function _0x1a2b(a, b) { /* 源码原文，未改写 */ }
  // ---- 来自原文件第 17 行：makeSign (function) ----
  function makeSign(payload) { /* 源码原文，未改写 */ }

  return { makeSign }
}
```

调用侧（完全不涉及浏览器）：

```js
import { createRuntime } from './pure.mjs'
import { createEnv } from './env.mjs'

// 采集到的真实环境值从这里注入
const runtime = createRuntime(createEnv({
  navigator: { userAgent: '真实 UA', platform: 'MacIntel' },
  document: { cookie: '真实 cookie' },
  screen: { width: 1512 },
}))

console.log(runtime.makeSign('业务参数'))
```

### 3.4 验算

```
rev_crypto_calc(operation = "aes-decrypt", data = "<密文>", passphrase = "口令", dataEncoding = "base64")
rev_crypto_calc(operation = "hash", algorithm = "md5", data = "abc")
rev_crypto_calc(operation = "rsa-manual-pow", value = "<m>", exponent = "<e>", modulus = "<n>")
rev_crypto_calc(operation = "xor-brute-force", data = "<hex>")
```

支持的 20 个操作：`hash`、`hmac`、`aes-encrypt`、`aes-decrypt`、`openssl-decrypt`、
`openssl-encrypt`、`xor`、`xor-brute-force`、`xor-recover-key`、`rsa-encrypt`、`rsa-decrypt`、
`rsa-sign`、`rsa-verify`、`rsa-public-from-modulus`、`rsa-manual-pow`、`rsa-key-info`、
`mod-pow`、`mod-inverse`、`bigint-parse`、`hex-normalize`。

**编码永远显式**（`utf8`/`hex`/`base64`/`base64url`/`latin1`）：同一个字符串按 hex 和 utf8
解释会得到完全不同的结果，静默猜测只会让人拿着错误答案以为算对了。非法 hex、奇数长度、
错长度 IV 都会**直接报错**而不是被截断。

---

## 4. 纯计算核心可单独使用

核心是**零宿主依赖的纯函数层**，不引用 cordis、不引用 DSH、不做任何 I/O。
把本包作为依赖列出的项目，可以通过它导出的子路径直接使用：

```js
import { aesDecrypt, opensslDecrypt, hmac, xorBytes, rsaManualPow } from 'dsh-plugin-reverse/core'
```

也可以把核心整个拷走：本仓库里源码位于 `src/core/`，编译产物 `lib/core/index.js` 已随仓库提交
（改了 `src/` 之后用 `npm run build` 重建）。

它遵循与本插件「静态还原产出物」完全相同的约束：无 DOM/BOM、无副作用、可独立运行。

---

## 5. 工程结构

```
src/
├── core/          纯计算核心（encoding / hash / aes / rsa / xor / errors）
├── analysis/      静态分析（ast / host / deobfuscate / extract / hook / assess）
├── services/      cordis 服务（ctx.reverseCrypto / ctx.reverseAnalysis）
├── tools/         5 个 agent 工具（defineTool）
└── index.ts       根插件：注册服务与工具
test/
├── core.test.mjs      密码学核心（含外部 OpenSSL 向量）
├── analysis.test.mjs  解混淆 / 宿主识别 / 闭包抽取 / Hook / 评估
├── plugin.test.mjs    插件契约与工具端到端链路
└── fixtures/          仿真混淆样本
```

依赖方向单向：`tools → services → analysis → core`。核心层永远不反向依赖 DSH，
因此「插件的核心」与「插件产出的纯算代码」遵循同一套无宿主约束。

---

## 6. 验证

```sh
npm run build                # TypeScript 严格模式编译
npm test                     # 运行测试套件
npm run check                # 上面两步
npm run verify:integration   # 真实启动器集成验证（隔离 DSH_HOME，约 1 分钟）
npm run verify:all           # 全部
```

集成验证会在工作区内的 `.dsh-scratch/` 建一个隔离的 `DSH_HOME`，
用随产品附带的 `web` 模板创建 profile、真实执行 `dsh plugin add`，
并断言 `--dump-config` 出现本包贡献的行、`--dump-config-schema` 能 import 本包模块。
脚本内置护栏，拒绝把临时 home 落到仓库之外，全程不触碰真实的 `~/.dsh`。

测试里几条关键判据：

- **AES/KDF 对齐外部实现**：向量由系统 OpenSSL 3.6 现场生成
  （`openssl enc -aes-256-cbc -md md5 -S ... -pass pass:...`），不是自己造自己验。
- **语义等价**：把原始混淆代码放进 `node:vm` 的模拟浏览器里跑，再把静态还原产物
  在纯 Node 里跑，断言两者输出**逐字节相同**；并断言改动环境值会改变结果。
- **生成物可执行**：Hook 脚本与还原产物都先过 AST 语法校验，再在沙箱里真实执行，
  断言「返回值不变」「可还原」「不依赖模块加载器」。
- **插件契约**：真实挂载 cordis，断言 5 个工具注册成功、两个服务可用、
  参数校验链路完整。

---

## 7. 诚实的边界

这些是**能力边界**，不是待办事项。工具会在这些情况下明确报告卡点，而不是产出一段
「能跑但算错」的代码：

| 情况 | 工具行为 |
|---|---|
| `eval` / `new Function` / `with` | 判为静态还原受阻，建议走 Hook；报告 `blocker`，不生成代码 |
| 控制流平坦化 | **不自动重排**（错误重排会静默改变语义）；报告 case 顺序供人工重建，并把置信度降为 low |
| 字符串数组 + 解码函数 | 只识别与报告，**不自动内联**（轮转偏移未完全还原前内联等于猜） |
| canvas / WebGL / Audio 指纹 | 无法在 Node 复现；`env.mjs` 里留显式占位并列入 `unmockable`，需外部采集 |
| 依赖真实浏览器实例的环境值 | 产出 `MUST_CAPTURE` 占位，**绝不编造一个"合理"的值** |
| 入口依赖了无法抽取的外层作用域 | 报告 `unresolved-reference` 卡点，说明需要补哪段代码 |
| 只给了 `(n, e, d)` 没有 CRT 参数 | 无法构造 PEM 私钥（数学上需要 p、q）；改用 `rsa-manual-pow` 直接做模幂 |

`MUST_CAPTURE` 是静态还原的**固有边界**而非实现缺陷：签名里如果混入了
`navigator.userAgent` 或 canvas 指纹，任何「模拟一个值」的做法都只会得到一个
看起来对、实际错的签名。正确做法是在浏览器里采集一次，然后注入。

---

## 8. 许可

MIT
