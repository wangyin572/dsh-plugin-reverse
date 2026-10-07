/**
 * 需求评估：先判断「该走哪条路」，再谈怎么做。
 *
 * ## 为什么必须有这一步
 *
 * 逆向任务最常见的浪费是**路线选错**：明明一段 20 行的混淆代码可以直接静态还原，
 * 却花半天写 Hook 注入；或者反过来，一个 VM 解释器 + eval 的目标，硬做静态还原，
 * 最后产出一堆「能跑但算错」的代码。
 *
 * 所以这个模块回答三个问题，并把结论和依据一起给出：
 *   1. Hook 可行吗？—— 几乎总是可行，但有反调试时需要额外处理。
 *   2. 静态还原可行吗？—— 取决于混淆特征与是否存在 eval/with 这类动态执行。
 *   3. 推荐哪条路？—— 给出有序步骤，而不是「都可以」。
 *
 * 结论是**启发式**的，依据（每个判断的理由）会一并输出，便于人工推翻。
 */

import { type DeobfuscateFinding, type DeobfuscateStats, analyzeOnly } from './deobfuscate.js'
import { type EntryCandidate, extractPure } from './extract.js'
import { type HostUsageReport, analyzeHostUsage } from './host.js'
import { parseSource } from './ast.js'

/** 置信度。 */
export type Confidence = 'high' | 'medium' | 'low'

/** 一条可行性结论。 */
export interface Feasibility {
  /** 是否可行。 */
  feasible: boolean
  /** 置信度。 */
  confidence: Confidence
  /** 判断依据（逐条给出，便于人工复核）。 */
  reasons: string[]
}

/** 推荐路线。 */
export type Verdict = 'static-first' | 'hook-first' | 'hook-then-static' | 'blocked'

/** 评估报告。 */
export interface AssessmentReport {
  /** 推荐路线。 */
  verdict: Verdict
  /** 一句话结论。 */
  summary: string
  /** Hook 可行性。 */
  hook: Feasibility
  /** 静态还原可行性。 */
  static: Feasibility
  /** 混淆程度（0-100）。 */
  obfuscation: { score: number; features: string[]; stats: DeobfuscateStats }
  /** 卡点清单。 */
  blockers: DeobfuscateFinding[]
  /** 全部发现。 */
  findings: DeobfuscateFinding[]
  /** 宿主环境依赖概况。 */
  host: {
    /** 参与计算但必须采集的环境值。 */
    mustCapture: string[]
    /** 可移除的副作用。 */
    removable: string[]
    /** 无法在 Node 复现的能力。 */
    unmockable: string[]
    /** 触碰宿主 API 最多的函数（最可能是签名入口）。 */
    topFunctions: { name: string; hostTouches: number; line: number }[]
  }
  /** 推荐入口候选。 */
  recommendedEntries: EntryCandidate[]
  /** 有序的执行计划。 */
  plan: string[]
}

/**
 * 生成需求评估报告。
 *
 * @param code - 待评估源码。
 * @param options - 选项。
 * @returns 评估报告。
 */
export function assess(
  code: string,
  options: { maxFindings?: number } = {},
): AssessmentReport {
  const maxFindings = options.maxFindings ?? 40
  const staticResult = analyzeOnly(code)
  const { ast, source } = parseSource(code)
  const hostReport: HostUsageReport = analyzeHostUsage(ast, source)

  // 入口候选：为拿到打分需要走一次抽取，但把「找不到入口」视为正常情况而非错误
  let candidates: EntryCandidate[] = []
  try {
    candidates = extractPure(code, { includeDemo: false }).candidates
  } catch {
    candidates = []
  }

  const stats = staticResult.stats
  const features: string[] = []
  if (stats.identifierObfuscationRatio > 0.3) {
    features.push(`标识符被批量重命名（_0x 形态占 ${(stats.identifierObfuscationRatio * 100).toFixed(0)}%）`)
  }
  if (stats.stringArrayCandidates > 0) features.push(`字符串数组 ${stats.stringArrayCandidates} 处`)
  if (stats.controlFlowFlattening > 0) features.push(`控制流平坦化 ${stats.controlFlowFlattening} 处`)
  if (stats.dynamicExecution > 0) features.push(`动态执行（eval / new Function）${stats.dynamicExecution} 处`)
  if (stats.debuggerStatements > 0) features.push(`debugger 反调试 ${stats.debuggerStatements} 处`)
  if (hostReport.references.length > 0) features.push(`宿主 API 引用 ${hostReport.references.length} 类`)
  if (features.length === 0) features.push('未发现明显混淆特征')

  // ---------------- Hook 可行性 ----------------
  const hookReasons: string[] = []
  let hookFeasible = true
  let hookConfidence: Confidence = 'high'

  hookReasons.push('Hook 运行在目标自身的浏览器环境里，天然拥有全部正确的环境值（无需采集指纹）')
  if (hostReport.mustCapture.length > 0) {
    hookReasons.push(
      `目标依赖 ${hostReport.mustCapture.length} 类环境相关值（如 ${hostReport.mustCapture.slice(0, 4).join('、')}），` +
        'Hook 路线无需处理它们',
    )
  }
  if (stats.debuggerStatements > 0) {
    hookConfidence = 'medium'
    hookReasons.push(
      `存在 ${stats.debuggerStatements} 处 debugger：DevTools 会被反复断住，` +
        '需要在 Sources 面板关闭断点（Deactivate breakpoints）后再执行 Hook',
    )
  }
  if (stats.dynamicExecution > 0) {
    hookReasons.push(
      '存在动态执行：Hook 依然有效（它在运行期观察真实调用），这正是动态执行场景下的首选路线',
    )
  }
  if (hostReport.references.length === 0 && stats.dynamicExecution === 0) {
    hookFeasible = false
    hookConfidence = 'high'
    hookReasons.push(
      '源码本身没有可见的宿主交互，也没有动态执行 —— 说明待分析逻辑可能是纯函数库，' +
        '直接把库代码取下来即可，不需要 Hook',
    )
  }

  // ---------------- 静态还原可行性 ----------------
  const staticReasons: string[] = []
  let staticFeasible = true
  let staticConfidence: Confidence = 'high'

  const hardBlockers = staticResult.blockers.filter(
    (finding) => finding.kind === 'eval' || finding.kind === 'function-constructor' || finding.kind === 'with-statement',
  )
  if (hardBlockers.length > 0) {
    staticFeasible = false
    staticConfidence = 'high'
    staticReasons.push(
      `存在 ${hardBlockers.length} 处动态执行/动态作用域（${hardBlockers
        .map((item) => item.kind)
        .join('、')}）：代码在运行期才成形，静态分析看不到真实逻辑`,
    )
  } else {
    staticReasons.push('未发现 eval / new Function / with，代码在静态层面是完整可见的')
  }

  // 置信度降级工具：只往下调，不往上抬，避免后面的判断把前面的悲观结论冲掉。
  const rank: Record<Confidence, number> = { high: 2, medium: 1, low: 0 }
  const downgrade = (target: Confidence): void => {
    if (rank[target] < rank[staticConfidence]) staticConfidence = target
  }

  if (stats.controlFlowFlattening > 0) {
    // 注意：控制流平坦化并不等于「不可还原」——闭包能抽出来，只是流程需要人工重建。
    // 所以这里只降置信度，不把 feasible 置否；真正的否决留给 eval/with。
    downgrade('low')
    staticReasons.push(
      `存在 ${stats.controlFlowFlattening} 处控制流平坦化：可以抽出依赖闭包，` +
        '但需要人工按 case 顺序还原流程，否则可能只覆盖部分分支',
    )
  }
  if (stats.stringArrayCandidates > 0) {
    downgrade('medium')
    staticReasons.push(
      `存在 ${stats.stringArrayCandidates} 处字符串数组：需要先还原解码函数与轮转偏移，` +
        '否则常量取值不确定',
    )
  }
  if (hostReport.unmockable.length > 0) {
    downgrade('medium')
    staticReasons.push(
      `依赖 ${hostReport.unmockable.length} 项无法在 Node 复现的能力（如 ${hostReport.unmockable
        .slice(0, 3)
        .join('、')}）：静态还原后仍需外部采集这些值`,
    )
  }
  if (stats.identifierObfuscationRatio > 0.5) {
    staticReasons.push(
      `标识符混淆比例较高（${(stats.identifierObfuscationRatio * 100).toFixed(0)}%）：` +
        '不改动命名可读性差，但闭包抽取不受影响',
    )
  }

  // ---------------- 路线结论 ----------------
  let verdict: Verdict
  let summary: string
  if (!staticFeasible && hookFeasible) {
    verdict = 'hook-first'
    summary =
      '静态还原受阻（动态执行/动态作用域），建议先走 Hook 路线定位入口并取运行期输入输出，' +
      '再评估是否值得对取到的具体片段做还原。'
  } else if (!staticFeasible && !hookFeasible) {
    verdict = 'blocked'
    summary = '两条路线都缺少必要条件：请补充可分析的源码，或说明运行环境（是否在 Worker/WASM 中执行）。'
  } else if (hookFeasible && staticConfidence !== 'high') {
    verdict = 'hook-then-static'
    summary =
      '两条路线都可行。建议**先 Hook 取一次真实的「输入 → 输出」对**，' +
      '再据此做静态还原并逐字节比对；这样还原结果是否等价是可验证的，而不是靠肉眼看。'
  } else if (hookFeasible && staticConfidence === 'high') {
    verdict = 'static-first'
    summary =
      '代码在静态层面完整可见、混淆程度低，建议直接静态还原为纯计算函数；' +
      '仅在还原结果与观测不符时再启用 Hook 交叉验证。'
  } else {
    verdict = 'static-first'
    summary = '源码中未见宿主交互，按纯算法库处理即可。'
  }

  // ---------------- 执行计划 ----------------
  const plan: string[] = []
  if (verdict === 'hook-then-static' || verdict === 'hook-first') {
    plan.push('用 rev_hook_generate 生成 Hook 脚本，在目标页面执行，捕获加密函数的入参与返回值')
    plan.push('从捕获记录的「调用栈」里定位真正的加密入口函数名')
    plan.push('记录至少一组完整的「输入 → 输出」，作为后续比对的基准向量')
  }
  if (verdict !== 'hook-first') {
    plan.push('用 rev_deobfuscate 做词法预处理（转义还原、常量折叠、成员访问规范化）')
    if (stats.stringArrayCandidates > 0) {
      plan.push('手工还原字符串数组的解码函数与轮转偏移，把常量取值确定下来')
    }
    if (stats.controlFlowFlattening > 0) {
      plan.push('按报告里的 case 顺序手工重建线性控制流（工具不自动重排，避免静默改变语义）')
    }
    plan.push('用 rev_extract_pure 抽取依赖闭包，产出 pure.mjs / env.mjs / demo.mjs')
    plan.push('在浏览器中采集 MUST_CAPTURE 列出的环境值，通过 createEnv(overrides) 注入')
  }
  plan.push('用 rev_crypto_calc 复算关键中间量（哈希、AES、RSA、异或），与还原结果逐步对齐')
  if (verdict === 'hook-then-static') {
    plan.push('把还原结果与 Hook 捕获的基准向量逐字节比对，一致才算还原成功')
  }
  plan.push('把最终纯算代码连同 demo 一起交付；若中途遇到卡点，保留分析报告与最小测试桩')

  return {
    verdict,
    summary,
    hook: { feasible: hookFeasible, confidence: hookConfidence, reasons: hookReasons },
    static: { feasible: staticFeasible, confidence: staticConfidence, reasons: staticReasons },
    obfuscation: { score: staticResult.obfuscationScore, features, stats },
    blockers: staticResult.blockers,
    findings: staticResult.findings.slice(0, maxFindings),
    host: {
      mustCapture: hostReport.mustCapture,
      removable: hostReport.removable,
      unmockable: hostReport.unmockable,
      topFunctions: hostReport.functionScores.slice(0, 8),
    },
    recommendedEntries: candidates.slice(0, 8),
    plan,
  }
}

/**
 * 把评估报告渲染成便于阅读的 Markdown 文本。
 *
 * 工具返回值需要给模型看，段落化比裸 JSON 更省 token 也更好读。
 *
 * @param report - 评估报告。
 * @returns Markdown 文本。
 */
export function renderAssessment(report: AssessmentReport): string {
  const lines: string[] = []
  const verdictLabel: Record<Verdict, string> = {
    'static-first': '✅ 直接静态还原',
    'hook-first': '🔌 Hook 优先',
    'hook-then-static': '🔁 Hook 取基准 → 静态还原 → 比对',
    blocked: '⛔ 信息不足',
  }

  lines.push(`## 需求评估报告`)
  lines.push('')
  lines.push(`**推荐路线：${verdictLabel[report.verdict]}**`)
  lines.push('')
  lines.push(report.summary)
  lines.push('')
  lines.push(`### 混淆程度：${report.obfuscation.score}/100`)
  for (const feature of report.obfuscation.features) lines.push(`- ${feature}`)
  lines.push('')
  lines.push(`### Hook 可行性：${report.hook.feasible ? '可行' : '不必要/不可行'}（置信度 ${report.hook.confidence}）`)
  for (const reason of report.hook.reasons) lines.push(`- ${reason}`)
  lines.push('')
  lines.push(
    `### 静态还原可行性：${report.static.feasible ? '可行' : '受阻'}（置信度 ${report.static.confidence}）`,
  )
  for (const reason of report.static.reasons) lines.push(`- ${reason}`)

  if (report.blockers.length > 0) {
    lines.push('')
    lines.push(`### 卡点（${report.blockers.length}）`)
    for (const blocker of report.blockers) {
      lines.push(`- **${blocker.kind}**${blocker.line ? `（第 ${blocker.line} 行）` : ''}：${blocker.message}`)
    }
  }

  if (report.recommendedEntries.length > 0) {
    lines.push('')
    lines.push('### 疑似加密入口（按可能性排序）')
    for (const entry of report.recommendedEntries) {
      lines.push(`- \`${entry.name}\`（${entry.score} 分）：${entry.reasons.join('；')}`)
    }
  }

  if (report.host.mustCapture.length > 0) {
    lines.push('')
    lines.push('### 必须采集的环境值（静态还原后需注入）')
    for (const item of report.host.mustCapture) lines.push(`- ${item}`)
  }
  if (report.host.unmockable.length > 0) {
    lines.push('')
    lines.push('### 无法在 Node 复现的能力')
    for (const item of report.host.unmockable) lines.push(`- ${item}`)
  }

  lines.push('')
  lines.push('### 执行计划')
  report.plan.forEach((step, index) => lines.push(`${index + 1}. ${step}`))

  return lines.join('\n')
}
