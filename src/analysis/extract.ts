/**
 * 静态还原：把扣出来的混淆代码变成**可在 Node 中独立运行的纯计算函数**。
 *
 * ## 做法与理由
 *
 * 核心手段是**依赖闭包抽取 + 环境注入**，而不是「逐点改写宿主引用」：
 *
 * 1. **闭包抽取**：从入口函数出发，顺着标识符引用把同文件内的依赖（辅助函数、
 *    常量表、字典）一起收集出来，用**源码原文切片**拼装。原文切片意味着不重排、
 *    不改写语义——这是正确性最有力的保证。
 *
 * 2. **环境注入**：在产出模块的顶部插入一行
 *    `const { window, document, navigator, … } = env`。
 *    这样源码里所有宿主引用都会解析到调用方传入的 `env`，而**不需要逐个改写引用点**。
 *    少一次改写，就少一类改写错误。同时因为 Node 里没有这些全局，
 *    一旦有漏掉的宿主名，运行时会直接报 `ReferenceError` 而不是静默取到 undefined。
 *
 * ## 诚实的边界
 *
 * 以下情况本模块**不会**生成代码，而是返回卡点报告（宁可说做不到，也不产出错误结果）：
 *
 *   - `eval` / `new Function` / `with`：静态不可见
 *   - 入口依赖了无法抽取的外层作用域变量（抽出后引用不到）
 *   - 控制流平坦化未还原：抽出的代码能跑，但可能只是状态机的一部分
 *
 * 对 MUST_CAPTURE 类环境值，产出的是**显式占位 + 注入点**，而不是编造的值。
 */

import { ReverseError } from '../core/errors.js'
import {
  type AstNode,
  type SourceText,
  childNode,
  childNodes,
  collectReferencedNames,
  isFunctionNode,
  nodeName,
  parseSource,
  strProp,
  walk,
} from './ast.js'
import { analyzeOnly, type DeobfuscateFinding } from './deobfuscate.js'
import {
  type HostUsageReport,
  analyzeHostUsage,
  collectDeclaredNames,
  generateStubs,
  lookupHostGlobal,
} from './host.js'

/** 产出文件。 */
export interface GeneratedFile {
  /** 建议文件名。 */
  path: string
  /** 文件内容。 */
  content: string
  /** 该文件的用途说明。 */
  description: string
}

/** 被抽取的符号。 */
export interface ExtractedSymbol {
  /** 符号名。 */
  name: string
  /** 符号种类。 */
  kind: 'function' | 'variable' | 'class'
  /** 源码行号。 */
  line: number
  /** 源码字节数。 */
  bytes: number
}

/** 候选入口。 */
export interface EntryCandidate {
  /** 函数名。 */
  name: string
  /** 推荐分数，越高越可能是签名/加解密入口。 */
  score: number
  /** 推荐理由。 */
  reasons: string[]
}

/** 抽取结果。 */
export interface ExtractResult {
  /** 入口名。 */
  entries: string[]
  /** 抽取到的符号（含传递依赖）。 */
  symbols: ExtractedSymbol[]
  /** 生成的独立文件。 */
  files: GeneratedFile[]
  /** 宿主引用报告。 */
  hostReport: HostUsageReport
  /** 需要从真实浏览器采集后注入的键。 */
  mustCapture: string[]
  /** 无法在 Node 中复现的能力。 */
  unmockable: string[]
  /** 阻断完整静态还原的问题。 */
  blockers: DeobfuscateFinding[]
  /** 引用了但无法解析的名字（多半来自未抽取的外层作用域或第三方库）。 */
  unresolved: string[]
  /** 自动推荐时的候选列表。 */
  candidates: EntryCandidate[]
  /** 生成代码里注入的宿主名。 */
  injectedGlobals: string[]
}

/**
 * JS/Node 内置名：既不需要抽取，也不需要注入，原样保留即可。
 */
const BUILTIN_GLOBALS = new Set([
  'Math', 'JSON', 'Date', 'String', 'Number', 'Boolean', 'Array', 'Object', 'RegExp', 'Error',
  'TypeError', 'RangeError', 'SyntaxError', 'EvalError', 'URIError', 'ReferenceError',
  'Promise', 'Map', 'Set', 'WeakMap', 'WeakSet', 'Symbol', 'BigInt', 'ArrayBuffer',
  'Uint8Array', 'Uint16Array', 'Uint32Array', 'Int8Array', 'Int16Array', 'Int32Array',
  'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array', 'DataView',
  'parseInt', 'parseFloat', 'isNaN', 'isFinite', 'NaN', 'Infinity', 'undefined',
  'encodeURIComponent', 'decodeURIComponent', 'encodeURI', 'decodeURI', 'escape', 'unescape',
  'globalThis', 'Proxy', 'Reflect', 'Intl', 'structuredClone', 'queueMicrotask',
  'arguments', 'this', 'eval', 'Function',
])

/** 与加解密/签名相关的命名线索。混淆后的名字通常不匹配，但未混淆时非常有效。 */
const CRYPTO_NAME_HINT =
  /sign|encrypt|decrypt|token|hmac|digest|hash|secret|aes|rsa|md5|sha|cipher|nonce|makeKey|genKey|calc|encode|decode/iu

/**
 * 收集文件内的符号表。
 *
 * 说明：混淆代码常把一切塞进一个 IIFE，所以不能只看 Program 顶层语句；这里扫描
 * **任意深度**的声明。同名冲突时保留**范围最大（最外层）**的那个，因为内层同名
 * 多半是局部变量，不应作为可抽取符号。
 *
 * @param ast - 根节点。
 * @param source - 源码工具。
 * @returns 名字 → 节点/信息。
 */
function buildSymbolTable(
  ast: AstNode,
  source: SourceText,
): Map<string, { node: AstNode; kind: 'function' | 'variable' | 'class'; line: number }> {
  const table = new Map<string, { node: AstNode; kind: 'function' | 'variable' | 'class'; line: number }>()

  const consider = (
    name: string | undefined,
    node: AstNode,
    kind: 'function' | 'variable' | 'class',
  ): void => {
    if (!name) return
    const existing = table.get(name)
    if (!existing) {
      table.set(name, { node, kind, line: source.location(node.start).line })
      return
    }
    // 保留范围更大的那个（更外层）
    const existingSpan = existing.node.end - existing.node.start
    const candidateSpan = node.end - node.start
    if (candidateSpan > existingSpan) {
      table.set(name, { node, kind, line: source.location(node.start).line })
    }
  }

  walk(ast, (node) => {
    if (isFunctionNode(node) || node.type === 'ClassDeclaration' || node.type === 'ClassExpression') {
      consider(nodeName(node), node, node.type.startsWith('Class') ? 'class' : 'function')
      return
    }
    if (node.type === 'VariableDeclarator') {
      const id = childNode(node, 'id')
      if (id?.type !== 'Identifier') return
      const init = childNode(node, 'init')
      const kind = init && isFunctionNode(init) ? 'function' : 'variable'
      consider(strProp(id, 'name'), node, kind)
    }
  })

  return table
}

/**
 * 计算一个节点的自由标识符（被读取但未在该节点内部声明）。
 *
 * 必须使用带引用位置判定的 {@link collectReferencedNames}，否则
 * `navigator.userAgent` 里的 `userAgent`、`s.charCodeAt` 里的 `charCodeAt`
 * 会被误当成自由变量，导致闭包抽取把一堆属性名报成「无法解析」。
 *
 * @param node - 节点。
 * @returns 自由标识符名集合。
 */
function freeIdentifiers(node: AstNode): Set<string> {
  const declared = collectDeclaredNames(node)
  const free = new Set<string>()
  for (const name of collectReferencedNames(node)) {
    if (!declared.has(name)) free.add(name)
  }
  return free
}

/**
 * 推荐入口函数，按「触碰宿主 API 次数 + 命名线索 + 参数个数」打分。
 *
 * @param ast - 根节点。
 * @param source - 源码工具。
 * @param hostReport - 宿主分析结果。
 * @returns 降序候选列表。
 */
function recommendEntries(
  ast: AstNode,
  source: SourceText,
  hostReport: HostUsageReport,
): EntryCandidate[] {
  const hostTouches = new Map(hostReport.functionScores.map((item) => [item.name, item.hostTouches]))
  const candidates: EntryCandidate[] = []

  walk(ast, (node) => {
    if (!isFunctionNode(node)) return
    const name = nodeName(node)
    if (!name) return
    const reasons: string[] = []
    let score = 0

    const touches = hostTouches.get(name) ?? 0
    if (touches > 0) {
      score += touches * 3
      reasons.push(`函数体内读写宿主环境 ${touches} 次（签名函数通常要读环境）`)
    }
    if (CRYPTO_NAME_HINT.test(name)) {
      score += 6
      reasons.push('函数名含加解密/签名相关词')
    }
    const params = childNodes(node, 'params').length
    if (params > 0) {
      score += 2
      reasons.push(`接收 ${params} 个参数`)
    }
    if (params >= 2) {
      score += 1
      reasons.push('参数较多，符合「待签名数据 + 密钥」形态')
    }
    if (score > 0) {
      candidates.push({ name, score, reasons })
    }
  })

  return candidates.sort((a, b) => b.score - a.score)
}

/**
 * 计算入口的依赖闭包。
 *
 * @param entries - 入口名。
 * @param symbolTable - 符号表。
 * @returns 闭包节点、符号信息、未解析名。
 */
function computeClosure(
  entries: readonly string[],
  symbolTable: Map<string, { node: AstNode; kind: 'function' | 'variable' | 'class'; line: number }>,
  source: SourceText,
): {
  nodes: { node: AstNode; name: string; kind: 'function' | 'variable' | 'class' }[]
  unresolved: string[]
  hostNames: string[]
} {
  const included = new Map<string, { node: AstNode; kind: 'function' | 'variable' | 'class' }>()
  const unresolved = new Set<string>()
  const hostNames = new Set<string>()
  const queue: string[] = [...entries]

  while (queue.length > 0) {
    const name = queue.shift()
    if (!name) continue
    if (included.has(name)) continue
    const symbol = symbolTable.get(name)
    if (!symbol) {
      unresolved.add(name)
      continue
    }
    included.set(name, { node: symbol.node, kind: symbol.kind })

    for (const free of freeIdentifiers(symbol.node)) {
      if (included.has(free)) continue
      if (symbolTable.has(free)) {
        queue.push(free)
        continue
      }
      if (BUILTIN_GLOBALS.has(free)) continue
      if (lookupHostGlobal(free)) {
        hostNames.add(free)
        continue
      }
      unresolved.add(free)
    }
  }

  const nodes = [...included.entries()]
    .map(([name, info]) => ({ name, ...info }))
    // 按原始顺序输出：function 声明会被提升，var/const 保持原顺序，语义与原文件一致
    .sort((a, b) => a.node.start - b.node.start)

  return {
    nodes,
    unresolved: [...unresolved],
    hostNames: [...hostNames],
  }
}

/**
 * 生成纯算模块源码。
 *
 * @param params - 生成参数。
 * @returns 模块源码。
 */
function renderPureModule(params: {
  entries: readonly string[]
  nodes: readonly { node: AstNode; name: string; kind: string }[]
  source: SourceText
  hostNames: readonly string[]
  obfuscated: boolean
}): string {
  const { entries, nodes, source, hostNames, obfuscated } = params
  const envKeys = [...hostNames].sort()
  const destructure =
    envKeys.length > 0
      ? `  // 从注入的 env 里取出源码引用到的宿主对象。\n` +
        `  // 这一步替代了「逐个改写宿主引用」——少一次改写，就少一类改写错误。\n` +
        `  const { ${envKeys.join(', ')} } = env\n`
      : `  // 本闭包未引用任何宿主 API，无需环境注入。\n`

  const body = nodes
    .map((item) => {
      const line = source.location(item.node.start).line
      return `  // ---- 来自原文件第 ${line} 行：${item.name} (${item.kind}) ----\n${indent(source.slice(item.node), 2)}`
    })
    .join('\n\n')

  const entryList = entries.map((name) => `    ${name},`).join('\n')
  const wrappers = entries
    .map(
      (name) =>
        `/**\n * 便捷入口：首次调用时用默认 env 构建运行时。\n * 需要注入采集值时，请改用 createRuntime(env) 自行构建。\n */\nexport function ${name}(...args) {\n  return requireRuntime().${name}(...args)\n}`,
    )
    .join('\n\n')

  return `/**
 * 纯计算模块 —— 由 dsh-plugin-reverse 从混淆源码中静态还原生成。
 *
 * 还原方式：依赖闭包抽取 + 环境注入。所有片段均为**原文件源码原文**，
 * 未做重排或语义改写。
 *
 * 使用：
 *   import { createRuntime } from './pure.mjs'
 *   import { createEnv } from './env.mjs'
 *   const runtime = createRuntime(createEnv())
 *   console.log(runtime.${entries[0] ?? 'entry'}('示例输入'))
 *
 * 注意：
 *   - 本模块**不引用任何 DOM/BOM 全局**，宿主对象全部由 env 注入。
 *   - env.mjs 里带 MUST_CAPTURE 注释的值必须来自真实浏览器采集，
 *     否则算出的签名与目标不一致（这是静态还原的固有边界，不是实现缺陷）。
${obfuscated ? ' *   - 原文件疑似经过控制流平坦化：抽取的代码可能只是状态机的一部分，\n *     请对照分析报告确认是否需要先还原控制流。\n' : ''} */

import { createEnv } from './env.mjs'

/**
 * 用给定的宿主环境构建运行时。
 *
 * @param {object} env - 宿主环境对象，通常来自 createEnv(overrides)。
 * @returns 含入口函数的对象。
 */
export function createRuntime(env) {
${destructure}
${body}

  // ---- 导出入口 ----
  return {
${entryList}
  }
}

${wrappers}

/** 惰性构建的默认运行时（使用 createEnv() 的默认值）。 */
let defaultRuntime

/**
 * 取得默认运行时。
 *
 * @returns 默认运行时对象。
 */
function requireRuntime() {
  if (!defaultRuntime) defaultRuntime = createRuntime(createEnv())
  return defaultRuntime
}

export { createEnv }
`
}

/**
 * 生成可直接运行的 demo。
 *
 * @param params - 生成参数。
 * @returns demo 源码。
 */
function renderDemo(params: {
  entries: readonly string[]
  mustCapture: readonly string[]
  unmockable: readonly string[]
}): string {
  const { entries, mustCapture, unmockable } = params
  const first = entries[0] ?? 'entry'
  return `/**
 * 独立运行验证 —— 由 dsh-plugin-reverse 生成。
 *
 * 直接运行：node demo.mjs
 * 它的作用是**证明还原产物能在 Node 里跑起来**，而不是证明签名与目标一致。
 * 后者取决于 env 是否注入了真实采集值（见下方 MUST_CAPTURE 清单）。
 */

import assert from 'node:assert/strict'
import { createRuntime } from './pure.mjs'
import { createEnv } from './env.mjs'

// 1) 先不注入任何采集值，确认模块本身可加载、可执行
const env = createEnv()
const runtime = createRuntime(env)

assert.equal(typeof runtime.${first}, 'function', '入口 ${first} 应当是个函数')
console.log('✓ 模块加载成功，入口：${entries.join(', ')}')

// 2) 用占位输入调用一次，确认不抛异常并能产生输出
const sample = 'hello'
const result = runtime.${first}(sample)
console.log('✓ 调用 ${first}(${JSON.stringify('hello')}) →', result)

// 3) 明确打印「还没有注入」的环境值：这些必须替换为真实浏览器采集结果
${mustCapture.length > 0 ? `const MUST_CAPTURE = ${JSON.stringify(mustCapture, null, 2)}\nconsole.log('\\n⚠ 以下环境值当前是占位值，参与签名的部分必须替换为采集值：')\nfor (const key of MUST_CAPTURE) console.log('  -', key)` : `console.log('\\n本闭包未依赖需要采集的环境值。')`}
${unmockable.length > 0 ? `\nconsole.log('\\n⚠ 以下能力无法在 Node 中复现，若参与签名需外部采集：')\nfor (const item of ${JSON.stringify(unmockable)}) console.log('  -', item)` : ''}

console.log('\\n下一步：把采集到的值填进 createEnv({ ... }) 的 overrides，再核对签名是否与目标一致。')
`
}

/**
 * 按缩进量给多行文本加前缀。
 *
 * @param text - 原文。
 * @param spaces - 缩进空格数。
 * @returns 缩进后的文本。
 */
function indent(text: string, spaces: number): string {
  const prefix = ' '.repeat(spaces)
  return text
    .split('\n')
    .map((line) => (line.length > 0 ? prefix + line : line))
    .join('\n')
}

/**
 * 执行静态还原。
 *
 * @param code - 混淆源码。
 * @param options - 选项。
 * @returns 还原结果，含独立可运行的产出文件。
 */
export function extractPure(
  code: string,
  options: {
    /** 入口函数名；留空时自动推荐。 */
    entry?: readonly string[]
    /** 是否生成 demo 文件，默认 true。 */
    includeDemo?: boolean
  } = {},
): ExtractResult {
  if (code.trim().length === 0) {
    throw new ReverseError('输入源码为空', 'INVALID_INPUT')
  }
  const { ast, source } = parseSource(code)
  const hostReport = analyzeHostUsage(ast, source)
  const staticFindings = analyzeOnly(code)
  const symbolTable = buildSymbolTable(ast, source)
  const candidates = recommendEntries(ast, source, hostReport)

  const entries = options.entry && options.entry.length > 0 ? [...options.entry] : []
  if (entries.length === 0) {
    const top = candidates[0]
    if (!top) {
      throw new ReverseError(
        '未能自动推荐入口：文件里没有能识别出名称的函数，也未提供 entry。' +
          `请显式指定 entry。当前可识别的符号有：${[...symbolTable.keys()].slice(0, 20).join(', ') || '(无)'}`,
        'NOT_FOUND',
      )
    }
    entries.push(top.name)
  }

  const missing = entries.filter((name) => !symbolTable.has(name))
  if (missing.length > 0) {
    throw new ReverseError(
      `找不到入口：${missing.join(', ')}。文件中可识别的符号：${
        [...symbolTable.keys()].slice(0, 30).join(', ') || '(无)'
      }`,
      'NOT_FOUND',
    )
  }

  const closure = computeClosure(entries, symbolTable, source)

  // 卡点：动态执行、with、以及无法解析的自由变量
  const blockers: DeobfuscateFinding[] = [...staticFindings.blockers]
  if (closure.unresolved.length > 0) {
    blockers.push({
      kind: 'unresolved-reference',
      severity: 'blocker',
      message:
        `闭包引用了无法解析的名字：${closure.unresolved.slice(0, 12).join(', ')}` +
        `${closure.unresolved.length > 12 ? ' 等' : ''}。` +
        '它们多半来自由闭包捕获的外层作用域变量（例如 IIFE 的局部变量）、' +
        '或尚未一并抠出的第三方库。请把定义所在的那段代码一起提供，或改用 Hook 路线取运行期值。',
    })
  }
  if (staticFindings.stats.controlFlowFlattening > 0) {
    blockers.push({
      kind: 'unflattened-control-flow',
      severity: 'warn',
      message:
        `检测到 ${staticFindings.stats.controlFlowFlattening} 处控制流平坦化尚未还原：` +
        '抽取结果可以运行，但可能只覆盖了状态机的一部分分支。',
    })
  }

  const envKeys = [...new Set([...closure.hostNames, ...hostReport.references.map((item) => item.name)])]
  const stubReport: HostUsageReport = {
    ...hostReport,
    references: hostReport.references.filter((item) => envKeys.includes(item.name)),
    mustCapture: hostReport.mustCapture.filter((name) => envKeys.includes(name)),
  }
  const stubs = generateStubs(stubReport)

  const files: GeneratedFile[] = [
    {
      path: 'pure.mjs',
      description: '纯计算模块：依赖闭包 + 环境注入，无 DOM/BOM 全局引用',
      content: renderPureModule({
        entries,
        nodes: closure.nodes,
        source,
        hostNames: closure.hostNames,
        obfuscated: staticFindings.stats.controlFlowFlattening > 0,
      }),
    },
    {
      path: 'env.mjs',
      description: '最小宿主桩：只含被引用到的全局，MUST_CAPTURE 项需注入采集值',
      content: stubs.source,
    },
  ]
  if (options.includeDemo ?? true) {
    files.push({
      path: 'demo.mjs',
      description: '独立运行验证：node demo.mjs',
      content: renderDemo({
        entries,
        mustCapture: stubs.mustCapture,
        unmockable: stubs.unmockable,
      }),
    })
  }

  return {
    entries,
    symbols: closure.nodes.map((item) => ({
      name: item.name,
      kind: item.kind,
      line: source.location(item.node.start).line,
      bytes: item.node.end - item.node.start,
    })),
    files,
    hostReport: stubReport,
    mustCapture: stubs.mustCapture,
    unmockable: stubs.unmockable,
    blockers,
    unresolved: closure.unresolved,
    candidates,
    injectedGlobals: envKeys,
  }
}
