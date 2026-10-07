/**
 * 工具 `rev_deobfuscate`：词法预处理与解混淆。
 *
 * 关键设计：把「安全重写」与「只读识别」分开呈现。模型看完报告后能明确知道
 * 哪些问题是工具已经解决的，哪些必须人工介入——这比给一个「看起来更干净但可能
 * 语义已变」的代码块要诚实得多。
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'

import { ReverseError } from '../core/errors.js'
import type { ReverseAnalysisService } from '../services/analysis-service.js'

/** 工具插件。 */
export const name = 'tool-rev-deobfuscate'

/** 依赖。 */
export const inject = ['tools', 'reverseAnalysis']

/**
 * 注册 `rev_deobfuscate`。
 *
 * @param ctx - 上下文。
 */
export function apply(ctx: Context): void {
  const service: ReverseAnalysisService = ctx.reverseAnalysis

  ctx.tools.register(
    defineTool({
      name: 'rev_deobfuscate',
      description:
        'Lexically preprocess obfuscated JavaScript: restore escaped string literals, fold ' +
        'obfuscator constants (!0, !1, void 0, !![]), normalise obj["key"] to obj.key, and report ' +
        '(without rewriting) string arrays, control-flow flattening, eval/Function/with and ' +
        'debugger statements. Only semantics-preserving rewrites are applied; anything that ' +
        'cannot be proven equivalent is reported as a blocker instead of being "fixed".',
      parameters: {
        code: { type: 'string', required: true, description: 'The obfuscated JavaScript source.' },
        rewrite: {
          type: 'boolean',
          description:
            'Apply the safe rewrites to the returned code. Set false to get analysis only. Default true.',
        },
        foldRounds: {
          type: 'integer',
          description: 'How many constant-folding passes to run (nested patterns like !![] need 2+). Default 3.',
        },
        includeCode: {
          type: 'boolean',
          description: 'Include the rewritten source in the result. Default true.',
        },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: false,
          properties: {
            summary: { type: 'string', required: true },
            obfuscationScore: { type: 'integer', required: true },
            changeCount: { type: 'integer', required: true },
            changes: { type: 'array', required: true, items: { type: 'string' } },
            findings: { type: 'array', required: true, items: { type: 'string' } },
            blockers: { type: 'array', required: true, items: { type: 'string' } },
            stats: { type: 'json', required: true },
            code: { type: 'string' },
          },
        },
        render: (_args, value) => {
          const lines: string[] = [value.summary, '']
          lines.push(`混淆程度：${value.obfuscationScore}/100`)
          lines.push(`安全重写：${value.changeCount} 处`)
          for (const change of value.changes.slice(0, 25)) lines.push(`  · ${change}`)
          if (value.changeCount > 25) lines.push(`  · …另有 ${value.changeCount - 25} 处`)
          if (value.findings.length > 0) {
            lines.push('', `发现（只读识别，未改代码）：`)
            for (const finding of value.findings) lines.push(`  · ${finding}`)
          }
          if (value.blockers.length > 0) {
            lines.push('', `卡点（需要人工介入）：`)
            for (const blocker of value.blockers) lines.push(`  · ${blocker}`)
          }
          if (value.code) {
            lines.push('', '--- 重写后的源码 ---', value.code)
          }
          return [{ type: 'text', text: lines.join('\n') }]
        },
      },
      async execute(args) {
        try {
          const result = service.runDeobfuscate(args.code, {
            rewrite: args.rewrite,
            foldRounds: args.foldRounds,
          })
          const includeCode = args.includeCode !== false
          return {
            summary:
              `安全重写 ${result.changes.length} 处（转义还原 / 常量折叠 / 成员访问规范化），` +
              `发现 ${result.findings.length} 条，卡点 ${result.blockers.length} 条`,
            obfuscationScore: result.obfuscationScore,
            changeCount: result.changes.length,
            changes: result.changes
              .slice(0, 200)
              .map((change) => `第 ${change.line} 行 ${change.kind}: ${change.before} → ${change.after}`),
            findings: result.findings.map(
              (finding) => `[${finding.severity}] ${finding.kind}${finding.line ? `@${finding.line}` : ''}: ${finding.message}`,
            ),
            blockers: result.blockers.map((blocker) => `${blocker.kind}: ${blocker.message}`),
            // 逐字段显式展开成新对象字面量：DSH schema 子集里的 `json` 在类型上是
            // JsonValue，具名 interface 不能直接赋给它（缺索引签名），新字面量可以。
            stats: {
              identifierObfuscationRatio: result.stats.identifierObfuscationRatio,
              stringArrayCandidates: result.stats.stringArrayCandidates,
              controlFlowFlattening: result.stats.controlFlowFlattening,
              dynamicExecution: result.stats.dynamicExecution,
              debuggerStatements: result.stats.debuggerStatements,
              nodeCount: result.stats.nodeCount,
            },
            ...(includeCode ? { code: result.code } : {}),
          }
        } catch (error) {
          if (error instanceof ReverseError) throw new Error(`[${error.code}] ${error.message}`)
          throw error
        }
      },
    }),
  )
}
