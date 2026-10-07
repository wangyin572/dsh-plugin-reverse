/**
 * 词法预处理与解混淆。
 *
 * ## 设计立场：只做「保证语义不变」的变换
 *
 * 解混淆最大的风险不是「做得不够」，而是**做错了却看起来更干净**。把控制流平坦化的
 * 状态机自动重排、把字符串数组全部内联回使用点，这类变换一旦有边界情况没覆盖，
 * 产出的代码依然能跑，但算出来的结果已经不是原来的结果了——这种错误极难发现。
 *
 * 因此本模块把能力分成三档，并在输出里明确标注每一条属于哪一档：
 *
 * | 档位 | 变换 | 为什么安全 |
 * |---|---|---|
 * | 安全重写 | 字符串转义还原、常量折叠、`obj['abc']`→`obj.abc` | 逐节点替换，语义等价可证 |
 * | 只读识别 | 字符串数组、控制流平坦化、eval/VM 检测 | 只报告位置与结构，**不改代码** |
 * | 判定为卡点 | VM 解释器、动态 key 访问 window、`debugger` 反调试 | 无法保证等价，交由人处理 |
 *
 * 第三档会进「分析报告」的 blockers，而不是生成一段可能错误的代码。
 */

import { ReverseError } from '../core/errors.js'
import {
  type AstNode,
  type SourceText,
  childNode,
  childNodes,
  collect,
  isFunctionNode,
  nodeName,
  parseSource,
  prop,
  strProp,
  walk,
} from './ast.js'

/** 一次安全重写的记录。 */
export interface DeobfuscateChange {
  /** 变换类别。 */
  kind: 'literal-unescape' | 'constant-fold' | 'member-access'
  /** 所在行。 */
  line: number
  /** 变换前源码。 */
  before: string
  /** 变换后源码。 */
  after: string
}

/** 严重程度。 */
export type FindingSeverity = 'info' | 'warn' | 'blocker'

/** 一条发现。 */
export interface DeobfuscateFinding {
  /** 类别标识。 */
  kind: string
  /** 严重程度；`blocker` 表示静态还原会因此受阻。 */
  severity: FindingSeverity
  /** 人类可读说明。 */
  message: string
  /** 所在行（能确定时）。 */
  line?: number
  /** 附加结构信息。 */
  detail?: string
}

/** 源码统计量，用于给混淆程度打分。 */
export interface DeobfuscateStats {
  /** 形如 `_0x1a2b` 的标识符占比。 */
  identifierObfuscationRatio: number
  /** 疑似字符串数组的候选数量。 */
  stringArrayCandidates: number
  /** 疑似控制流平坦化的循环数量。 */
  controlFlowFlattening: number
  /** eval / Function 构造 等动态执行点数量。 */
  dynamicExecution: number
  /** debugger 语句数量。 */
  debuggerStatements: number
  /** 总节点数，用于判断文件规模。 */
  nodeCount: number
}

/** 解混淆结果。 */
export interface DeobfuscateResult {
  /** 重写后的源码。 */
  code: string
  /** 依次记录的安全重写。 */
  changes: DeobfuscateChange[]
  /** 发现清单（含卡点）。 */
  findings: DeobfuscateFinding[]
  /** 统计量。 */
  stats: DeobfuscateStats
  /** 混淆程度 0-100，越高越难静态还原。 */
  obfuscationScore: number
  /** 明确无法自动处理、需要人工介入的点。 */
  blockers: DeobfuscateFinding[]
}

/** 一处待应用的源码替换。 */
interface Edit {
  start: number
  end: number
  text: string
}

/**
 * 从后向前应用替换，避免偏移失效；并用重叠保护兜住嵌套替换。
 *
 * 排序依据是 **`end` 降序**，而不是 `start` 降序。这一点很关键：
 * `!![]` 会被同时规划出「外层整体 ⇒ `true`」和「内层 `![]` ⇒ `false`」两条编辑，
 * 内层的 `start` 更大，若按 `start` 降序就会先应用内层，把结果变成 `!false`（错误）。
 * 按 `end` 降序则外层先应用，内层因落在已替换区间内而被丢弃——**更宽的匹配优先**，
 * 这正是嵌套表达式折叠该有的语义。
 *
 * 这里刻意用字符串拼接而不是 `String.replace`：替换文本里若含 `$&`、`$1` 等
 * 会被 replace 当成替换模式解释，从而悄悄改坏代码。
 *
 * @param code - 原源码。
 * @param edits - 替换列表。
 * @returns 替换后的源码。
 */
function applyEdits(code: string, edits: readonly Edit[]): string {
  const sorted = [...edits].sort((a, b) => b.end - a.end)
  let out = code
  let lastStart = Number.POSITIVE_INFINITY
  for (const edit of sorted) {
    if (edit.end > lastStart) continue // 与前一处替换重叠，跳过以保证安全
    out = out.slice(0, edit.start) + edit.text + out.slice(edit.end)
    lastStart = edit.start
  }
  return out
}

/**
 * 还原字符串字面量里的转义序列。
 *
 * 混淆器常把 `"abc"` 写成 `"\x61\x62\x63"` 或 `"\u0061\u0062\u0063"`。AST 的
 * `value` 已经是解码后的真实字符串，所以用 `JSON.stringify(value)` 回写即可
 * **精确等价**——这不是猜测，是同一个值换一种写法。
 *
 * @param ast - 根节点。
 * @param source - 源码工具。
 * @returns 替换列表与变更记录。
 */
function planLiteralUnescape(
  ast: AstNode,
  source: SourceText,
): { edits: Edit[]; changes: DeobfuscateChange[] } {
  const edits: Edit[] = []
  const changes: DeobfuscateChange[] = []
  walk(ast, (node) => {
    if (node.type !== 'Literal') return
    const raw = strProp(node, 'raw')
    const value = prop(node, 'value')
    if (typeof raw !== 'string' || typeof value !== 'string') return
    const replacement = JSON.stringify(value)
    if (replacement === raw) return
    edits.push({ start: node.start, end: node.end, text: replacement })
    changes.push({
      kind: 'literal-unescape',
      line: source.location(node.start).line,
      before: raw,
      after: replacement,
    })
  })
  return { edits, changes }
}

/**
 * 折叠混淆器生成的常量写法。
 *
 * 覆盖 `!0`→`true`、`!1`→`false`、`!![]`→`true`、`![]`→`false`、`void 0`→`undefined`，
 * 以及相邻字符串字面量拼接。这些都是**逐节点可证的等价变换**。
 *
 * @param ast - 根节点。
 * @param source - 源码工具。
 * @returns 替换列表与变更记录。
 */
function planConstantFold(
  ast: AstNode,
  source: SourceText,
): { edits: Edit[]; changes: DeobfuscateChange[] } {
  const edits: Edit[] = []
  const changes: DeobfuscateChange[] = []

  const literalValue = (node: AstNode | undefined): unknown => {
    if (!node || node.type !== 'Literal') return undefined
    return prop(node, 'value')
  }

  walk(ast, (node) => {
    // !0 / !1 / ![] / !{} / !![] / !!{}
    if (node.type === 'UnaryExpression' && strProp(node, 'operator') === '!') {
      const argument = childNode(node, 'argument')
      if (!argument) return
      const push = (text: string): void => {
        edits.push({ start: node.start, end: node.end, text })
        changes.push({
          kind: 'constant-fold',
          line: source.location(node.start).line,
          before: source.snippet(node.start, node.end, 40),
          after: text,
        })
      }
      if (argument.type === 'Literal') {
        const value = literalValue(argument)
        if (value === 0) push('true')
        else if (value === 1) push('false')
        return
      }
      if (argument.type === 'ArrayExpression' && childNodes(argument, 'elements').length === 0) {
        push('false')
        return
      }
      if (argument.type === 'ObjectExpression' && childNodes(argument, 'properties').length === 0) {
        push('false')
        return
      }
      if (argument.type === 'UnaryExpression' && strProp(argument, 'operator') === '!') {
        const inner = childNode(argument, 'argument')
        const innerValue = literalValue(inner)
        if (innerValue === 0) push('true')
        else if (innerValue === 1) push('false')
        else if (inner && inner.type === 'ArrayExpression' && childNodes(inner, 'elements').length === 0) {
          push('true')
        } else if (inner && inner.type === 'ObjectExpression' && childNodes(inner, 'properties').length === 0) {
          push('true')
        }
      }
      return
    }

    // void 0 → undefined
    if (node.type === 'UnaryExpression' && strProp(node, 'operator') === 'void') {
      const argument = childNode(node, 'argument')
      if (literalValue(argument) === 0) {
        edits.push({ start: node.start, end: node.end, text: 'undefined' })
        changes.push({
          kind: 'constant-fold',
          line: source.location(node.start).line,
          before: source.snippet(node.start, node.end, 40),
          after: 'undefined',
        })
      }
      return
    }

    // 'a' + 'b' → 'ab'
    if (node.type === 'BinaryExpression' && strProp(node, 'operator') === '+') {
      const left = childNode(node, 'left')
      const right = childNode(node, 'right')
      const leftValue = literalValue(left)
      const rightValue = literalValue(right)
      if (typeof leftValue === 'string' && typeof rightValue === 'string') {
        const text = JSON.stringify(leftValue + rightValue)
        edits.push({ start: node.start, end: node.end, text })
        changes.push({
          kind: 'constant-fold',
          line: source.location(node.start).line,
          before: source.snippet(node.start, node.end, 40),
          after: text,
        })
      }
    }
  })

  return { edits, changes }
}

/**
 * 把 `obj['abc']` 规范为 `obj.abc`。
 *
 * 替换范围必须是**从对象末尾到属性末尾**（即连同方括号一起），而不是只替换属性节点。
 * 只替换属性节点会把 `obj['abc']` 变成 `obj[abc]` —— 字符串键变成变量引用，
 * 语义被悄悄改掉。这是一个不报错、但结果必错的典型陷阱。
 *
 * @param ast - 根节点。
 * @param source - 源码工具。
 * @returns 替换列表与变更记录。
 */
function planMemberAccess(
  ast: AstNode,
  source: SourceText,
): { edits: Edit[]; changes: DeobfuscateChange[] } {
  const edits: Edit[] = []
  const changes: DeobfuscateChange[] = []
  walk(ast, (node) => {
    if (node.type !== 'MemberExpression') return
    if (prop(node, 'computed') !== true) return
    const object = childNode(node, 'object')
    const property = childNode(node, 'property')
    if (!object || !property || property.type !== 'Literal') return
    const name = prop(property, 'value')
    if (typeof name !== 'string' || !/^[A-Za-z_$][A-Za-z0-9_$]*$/u.test(name)) return
    // 可选链要保留 `?.`，否则 obj?.['a'] 会被改成 obj.a，丢掉短路语义
    const optional = prop(node, 'optional') === true
    // 范围必须覆盖 `[...]` 整个后缀（含结尾的 `]`），到 node.end 为止。
    // 早先只替换到 property.end，会漏掉 `]`，产出 `obj.name]` 这种非法代码。
    edits.push({
      start: object.end,
      end: node.end,
      text: `${optional ? '?.' : '.'}${name}`,
    })
    changes.push({
      kind: 'member-access',
      line: source.location(node.start).line,
      before: source.snippet(object.end, node.end, 40),
      after: `${optional ? '?.' : '.'}${name}`,
    })
  })
  return { edits, changes }
}

/**
 * 识别字符串数组（obfuscator.io 这类工具的典型产物）。
 *
 * 只识别与报告，**不做内联替换**。原因：字符串数组几乎总与一个带轮转偏移的解码函数
 * 配对，偏移量还可能在运行期变化；在没完全还原解码函数之前内联，等于猜。
 *
 * @param ast - 根节点。
 * @param source - 源码工具。
 * @returns 发现清单与候选数量。
 */
function detectStringArrays(
  ast: AstNode,
  source: SourceText,
): { findings: DeobfuscateFinding[]; candidates: number } {
  const findings: DeobfuscateFinding[] = []
  let candidates = 0

  walk(ast, (node) => {
    if (node.type !== 'VariableDeclarator') return
    const init = childNode(node, 'init')
    if (!init || init.type !== 'ArrayExpression') return
    const elements = childNodes(init, 'elements')
    if (elements.length < 8) return
    const allStrings = elements.every((element) => {
      if (element.type !== 'Literal') return false
      return typeof prop(element, 'value') === 'string'
    })
    if (!allStrings) return
    candidates += 1
    const name = nodeName(childNode(node, 'id') ?? node) ?? '<anonymous>'
    findings.push({
      kind: 'string-array',
      severity: 'info',
      line: source.location(node.start).line,
      message: `疑似字符串数组 "${name}"（${elements.length} 项）。这类数组通常配一个带偏移的解码函数，需先还原该函数再谈内联。`,
      detail: elements
        .slice(0, 6)
        .map((element) => JSON.stringify(prop(element, 'value')))
        .join(', ') + (elements.length > 6 ? ', …' : ''),
    })
  })

  return { findings, candidates }
}

/**
 * 识别控制流平坦化（CFF）。
 *
 * 特征：一个 `while`/`for` 循环体里是 `switch`，判别式是一个在 case 内部被反复赋值的
 * 变量，case 数量较多。这里报告**位置、case 数量与 case 顺序**，让人可以据此手工重排；
 * 自动重排不在此模块职责内（见文件头说明）。
 *
 * @param ast - 根节点。
 * @param source - 源码工具。
 * @returns 发现清单与命中数量。
 */
function detectControlFlowFlattening(
  ast: AstNode,
  source: SourceText,
): { findings: DeobfuscateFinding[]; count: number } {
  const findings: DeobfuscateFinding[] = []
  let count = 0

  walk(ast, (node) => {
    if (node.type !== 'WhileStatement' && node.type !== 'ForStatement') return
    const body = childNode(node, 'body')
    if (!body) return
    const switchNode =
      body.type === 'SwitchStatement'
        ? body
        : childNodes(body, 'body').find((statement) => statement.type === 'SwitchStatement')
    if (!switchNode || switchNode.type !== 'SwitchStatement') return
    const cases = childNodes(switchNode, 'cases')
    if (cases.length < 5) return

    count += 1
    const testValues = cases
      .map((caseNode) => {
        const test = childNode(caseNode, 'test')
        const value = test ? prop(test, 'value') : undefined
        if (typeof value === 'string' || typeof value === 'number') return String(value)
        return '?'
      })
      .join(' → ')
    findings.push({
      kind: 'control-flow-flattening',
      severity: 'warn',
      line: source.location(node.start).line,
      message:
        `疑似控制流平坦化：${cases.length} 个 case 的分发循环。` +
        '自动重排需要完整还原状态变量与跳转顺序，本工具不做（错误重排会静默改变语义）。' +
        '建议按下方 case 顺序手工重建线性流程，或改用运行时 Hook 取中间值。',
      detail: `case 顺序：${testValues.slice(0, 400)}`,
    })
  })

  return { findings, count }
}

/**
 * 识别会阻断静态还原的动态特性。
 *
 * @param ast - 根节点。
 * @param source - 源码工具。
 * @returns 发现清单、动态执行点数量、debugger 数量。
 */
function detectBlockers(
  ast: AstNode,
  source: SourceText,
): { findings: DeobfuscateFinding[]; dynamicExecution: number; debuggerStatements: number } {
  const findings: DeobfuscateFinding[] = []
  let dynamicExecution = 0
  let debuggerStatements = 0

  walk(ast, (node) => {
    if (node.type === 'DebuggerStatement') {
      debuggerStatements += 1
      findings.push({
        kind: 'debugger',
        severity: 'warn',
        line: source.location(node.start).line,
        message: '存在 debugger 语句（反调试）。静态还原时应删除；Hook 场景下需处理断点。',
      })
      return
    }

    if (node.type === 'WithStatement') {
      findings.push({
        kind: 'with-statement',
        severity: 'blocker',
        line: source.location(node.start).line,
        message: '存在 with 语句：作用域无法静态确定，依赖闭包抽取的还原方式会失效。',
      })
      return
    }

    const callee = node.type === 'CallExpression' || node.type === 'NewExpression' ? childNode(node, 'callee') : undefined
    if (!callee) return
    const name = callee.type === 'Identifier' ? strProp(callee, 'name') : undefined
    if (name === 'eval') {
      dynamicExecution += 1
      findings.push({
        kind: 'eval',
        severity: 'blocker',
        line: source.location(node.start).line,
        message:
          '存在 eval 调用：代码在运行期才生成，静态分析看不到真实逻辑。' +
          '此时应改走 Hook 路线，或把 eval 的实参打印出来再单独分析。',
      })
      return
    }
    if (name === 'Function') {
      dynamicExecution += 1
      findings.push({
        kind: 'function-constructor',
        severity: 'blocker',
        line: source.location(node.start).line,
        message:
          '存在 new Function(...) 动态构造：与 eval 同类，静态不可见，需运行时取值。',
      })
    }
  })

  // 动态 key 访问 window（如 window['_0x' + n]）会让「哪些宿主属性被读取」变得不可确定
  walk(ast, (node) => {
    if (node.type !== 'MemberExpression') return
    const object = childNode(node, 'object')
    if (!object || object.type !== 'Identifier') return
    const objectName = strProp(object, 'name')
    if (objectName !== 'window' && objectName !== 'document' && objectName !== 'navigator') return
    if (prop(node, 'computed') !== true) return
    const property = childNode(node, 'property')
    const staticKey = property?.type === 'Literal'
    if (staticKey) return
    findings.push({
      kind: 'dynamic-host-access',
      severity: 'warn',
      line: source.location(node.start).line,
      message: `以动态键访问 ${objectName}（如 ${objectName}[expr]）：无法静态穷举它读取了哪些环境值，桩可能需要扩大覆盖范围。`,
    })
  })

  return { findings, dynamicExecution, debuggerStatements }
}

/**
 * 统计标识符混淆比例。
 *
 * 判据：以 `_0x` 开头，或为单个十六进制/短随机名。
 *
 * @param ast - 根节点。
 * @returns 比例与总数。
 */
function measureIdentifierObfuscation(ast: AstNode): { ratio: number; total: number } {
  const names = new Set<string>()
  walk(ast, (node) => {
    if (node.type !== 'Identifier') return
    const name = strProp(node, 'name')
    if (name) names.add(name)
  })
  if (names.size === 0) return { ratio: 0, total: 0 }
  let obfuscated = 0
  for (const name of names) {
    if (/^_0x[0-9a-f]+$/iu.test(name)) obfuscated += 1
  }
  return { ratio: obfuscated / names.size, total: names.size }
}

/**
 * 执行解混淆流水线。
 *
 * @param code - 源码文本。
 * @param options - 选项。
 * @returns 结果，含重写后的代码、变更记录、发现与评分。
 */
export function deobfuscate(
  code: string,
  options: {
    /** 是否应用安全重写；`false` 时只做分析与报告。默认 `true`。 */
    rewrite?: boolean
    /** 连续折叠的轮数，默认 3（`!![]` 这类需要多轮）。 */
    foldRounds?: number
  } = {},
): DeobfuscateResult {
  if (code.trim().length === 0) {
    throw new ReverseError('输入源码为空', 'INVALID_INPUT')
  }
  const rewrite = options.rewrite ?? true
  const rounds = Math.max(1, options.foldRounds ?? 3)

  let current = code
  const allChanges: DeobfuscateChange[] = []
  let lastAst: AstNode | undefined
  let lastSource: SourceText | undefined

  const passes = rewrite ? rounds : 1
  for (let round = 0; round < passes; round += 1) {
    const { ast, source } = parseSource(current)
    lastAst = ast
    lastSource = source
    if (!rewrite) break

    const unescape = planLiteralUnescape(ast, source)
    const fold = planConstantFold(ast, source)
    const member = planMemberAccess(ast, source)
    const edits = [...unescape.edits, ...fold.edits, ...member.edits]
    if (edits.length === 0) break
    allChanges.push(...unescape.changes, ...fold.changes, ...member.changes)
    current = applyEdits(current, edits)
  }

  if (!lastAst || !lastSource) {
    const { ast, source } = parseSource(current)
    lastAst = ast
    lastSource = source
  }

  // 识别阶段始终基于**最终代码**重新解析，保证报告里的行号与产出文件一致。
  const { ast: finalAst, source: finalSource } = rewrite && current !== code ? parseSource(current) : { ast: lastAst, source: lastSource }

  const stringArrays = detectStringArrays(finalAst, finalSource)
  const cff = detectControlFlowFlattening(finalAst, finalSource)
  const blockers = detectBlockers(finalAst, finalSource)
  const identifierStats = measureIdentifierObfuscation(finalAst)

  const nodeCount = collect(finalAst).length
  const stats: DeobfuscateStats = {
    identifierObfuscationRatio: Number(identifierStats.ratio.toFixed(4)),
    stringArrayCandidates: stringArrays.candidates,
    controlFlowFlattening: cff.count,
    dynamicExecution: blockers.dynamicExecution,
    debuggerStatements: blockers.debuggerStatements,
    nodeCount,
  }

  // 评分：各特征加权。这里给的是**定性参考**，不是精确度量。
  const score = Math.min(
    100,
    Math.round(
      stats.identifierObfuscationRatio * 40 +
        Math.min(20, stats.stringArrayCandidates * 10) +
        Math.min(25, stats.controlFlowFlattening * 12) +
        Math.min(15, stats.dynamicExecution * 15) +
        Math.min(5, stats.debuggerStatements * 2),
    ),
  )

  const findings = [...stringArrays.findings, ...cff.findings, ...blockers.findings]
  return {
    code: current,
    changes: allChanges,
    findings,
    stats,
    obfuscationScore: score,
    blockers: findings.filter((finding) => finding.severity === 'blocker'),
  }
}

/**
 * 只做分析、不改代码的便捷入口。
 *
 * @param code - 源码文本。
 * @returns 结果（`code` 字段等于输入）。
 */
export function analyzeOnly(code: string): DeobfuscateResult {
  return deobfuscate(code, { rewrite: false })
}

/**
 * 判断一个节点是否是可被抽取的「顶层符号」（函数或变量初始化）。
 *
 * 供 closure 抽取复用。
 *
 * @param node - 节点。
 * @returns 是否是顶层符号定义。
 */
export function isExtractableSymbol(node: AstNode): boolean {
  return (
    isFunctionNode(node) ||
    node.type === 'ClassDeclaration' ||
    node.type === 'VariableDeclaration'
  )
}
