/**
 * 工具 `rev_assess`：逆向任务的需求评估。
 *
 * 这是**所有逆向任务的第一步**。它先判断该走 Hook 还是静态还原，再给执行计划——
 * 避免在错误的路线上浪费时间（例如对着一个 VM 解释器硬做静态还原）。
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'

import { ReverseError } from '../core/errors.js'
import { renderAssessment } from '../analysis/assess.js'
import type { ReverseAnalysisService } from '../services/analysis-service.js'

/** 工具插件。 */
export const name = 'tool-rev-assess'

/** 依赖。 */
export const inject = ['tools', 'reverseAnalysis']

/**
 * 注册 `rev_assess`。
 *
 * @param ctx - 上下文。
 */
export function apply(ctx: Context): void {
  const service: ReverseAnalysisService = ctx.reverseAnalysis

  ctx.tools.register(
    defineTool({
      name: 'rev_assess',
      description:
        'ALWAYS call this first for any JavaScript reverse-engineering task. It inspects the ' +
        'obfuscated source and answers: is hooking feasible, is static restoration feasible, ' +
        'which route to take, plus the blockers and an ordered plan. Output is a Markdown ' +
        'assessment report. Do not start writing hook scripts or restored code before running it.',
      parameters: {
        code: {
          type: 'string',
          required: true,
          description:
            'The JavaScript source to assess. Pass the file that actually contains the entry ' +
            'logic (usually the one that reads window/navigator/document), not the whole bundle.',
        },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: false,
          properties: {
            verdict: { type: 'string', required: true },
            hookFeasible: { type: 'boolean', required: true },
            staticFeasible: { type: 'boolean', required: true },
            obfuscationScore: { type: 'integer', required: true },
            report: { type: 'string', required: true },
            blockers: { type: 'array', required: true, items: { type: 'string' } },
            plan: { type: 'array', required: true, items: { type: 'string' } },
            mustCapture: { type: 'array', required: true, items: { type: 'string' } },
          },
        },
        render: (_args, value) => [
          {
            type: 'text',
            text:
              `${value.report}\n\n---\nverdict: ${value.verdict} | ` +
              `hook: ${value.hookFeasible ? '可行' : '不建议'} | ` +
              `静态还原: ${value.staticFeasible ? '可行' : '受阻'} | ` +
              `混淆分: ${value.obfuscationScore}`,
          },
        ],
      },
      async execute(args) {
        try {
          const report = service.runAssess(args.code)
          return {
            verdict: report.verdict,
            hookFeasible: report.hook.feasible,
            staticFeasible: report.static.feasible,
            obfuscationScore: report.obfuscation.score,
            report: renderAssessment(report),
            blockers: report.blockers.map(
              (blocker) => `${blocker.kind}${blocker.line ? `@${blocker.line}` : ''}: ${blocker.message}`,
            ),
            plan: report.plan,
            mustCapture: report.host.mustCapture,
          }
        } catch (error) {
          if (error instanceof ReverseError) throw new Error(`[${error.code}] ${error.message}`)
          throw error
        }
      },
    }),
  )
}
