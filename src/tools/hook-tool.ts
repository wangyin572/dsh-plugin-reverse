/**
 * 工具 `rev_hook_generate`：生成用于**调试取证**的函数 Hook 脚本。
 *
 * 定位说明（也会写进工具描述，因为模型需要据此选择路线）：
 *   Hook 用于「定位加密入口」——观察函数的入参、返回值与调用栈。
 *   它不产出可交付的纯算代码；那条路由 `rev_extract_pure` 负责。
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import Schema from '@deepseek-ai/schemastery'

import type { ReverseAnalysisService } from '../services/analysis-service.js'

/** 工具插件配置（由根插件下发）。 */
export interface HookToolConfig {
  /** 日志缓冲区上限。 */
  logLimit: number
  /** 是否默认开启自动发现。 */
  autoDiscover: boolean
}

/** 工具插件。 */
export const name = 'tool-rev-hook'

/** 依赖。 */
export const inject = ['tools', 'reverseAnalysis']

/** 配置 schema。 */
export const Config = Schema.object({
  logLimit: Schema.natural().default(2000),
  autoDiscover: Schema.boolean().default(true),
})

/**
 * 注册 `rev_hook_generate`。
 *
 * @param ctx - 上下文。
 * @param config - 插件配置。
 */
export function apply(ctx: Context, config: HookToolConfig): void {
  const service: ReverseAnalysisService = ctx.reverseAnalysis

  ctx.tools.register(
    defineTool({
      name: 'rev_hook_generate',
      description:
        'Generate a self-contained browser Hook script for DEBUGGING AND FORENSICS ONLY, to locate ' +
        'where an encryption/signature entry point lives. It wraps WebCrypto (crypto.subtle), ' +
        'CryptoJS, JSEncrypt, btoa/atob, XHR/fetch/WebSocket, auto-discovers window functions with ' +
        'crypto-ish names, and records arguments, return values and — most importantly — the call ' +
        'stack, so you can see which function invokes the encryption. Use this when the assessment ' +
        'says hooking is the viable route (eval/VM/anti-debug present). It does NOT produce ' +
        'deliverable pure-computation code; use rev_extract_pure for that. Only run it on pages you ' +
        'are authorised to analyse: hook logs can contain credentials.',
      parameters: {
        targets: {
          type: 'array',
          description:
            'Explicit targets to hook, e.g. [{"object":"window","method":"makeSign"}]. ' +
            'Paths like "CryptoJS.AES" or "XMLHttpRequest.prototype" are accepted.',
          items: {
            type: 'object',
            additionalProperties: false,
            properties: {
              object: { type: 'string', required: true, description: 'Object path, e.g. window.crypto.subtle' },
              method: { type: 'string', required: true, description: 'Method name, e.g. encrypt' },
              label: { type: 'string', description: 'Label used in the log output.' },
            },
          },
        },
        autoDiscover: {
          type: 'boolean',
          description: 'Scan window for functions whose names look crypto-related and hook them. Default true.',
        },
        includeNetwork: {
          type: 'boolean',
          description: 'Also hook XMLHttpRequest/fetch/WebSocket/sendBeacon. Default true.',
        },
        stealth: {
          type: 'boolean',
          description:
            'Spoof Function.prototype.toString so "was this function patched" checks see the original. Default true.',
        },
        presets: {
          type: 'array',
          items: { type: 'string', enum: ['webcrypto', 'cryptojs', 'jsencrypt', 'encoding'] },
          description: 'Which built-in preset groups to install. Default all.',
        },
        maxValueLength: { type: 'integer', description: 'Max characters per logged argument. Default 500.' },
        logLimit: { type: 'integer', description: 'Log ring-buffer size. Defaults to the plugin config value.' },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: false,
          properties: {
            summary: { type: 'string', required: true },
            plannedTargets: { type: 'array', required: true, items: { type: 'string' } },
            usage: { type: 'array', required: true, items: { type: 'string' } },
            notes: { type: 'array', required: true, items: { type: 'string' } },
            script: { type: 'string', required: true },
          },
        },
        render: (_args, value) => {
          const lines: string[] = [value.summary, '']
          lines.push('将尝试挂钩：')
          for (const target of value.plannedTargets) lines.push(`  · ${target}`)
          lines.push('', '使用方式：')
          for (const item of value.usage) lines.push(`  · ${item}`)
          if (value.notes.length > 0) {
            lines.push('', '注意事项：')
            for (const note of value.notes) lines.push(`  · ${note}`)
          }
          lines.push('', '--- 脚本（请保存为 .js 后使用）---', value.script)
          return [{ type: 'text', text: lines.join('\n') }]
        },
      },
      async execute(args) {
        const hook = service.runHook({
          targets: args.targets,
          autoDiscover: args.autoDiscover ?? config.autoDiscover,
          includeNetwork: args.includeNetwork,
          stealth: args.stealth,
          presets: args.presets,
          maxValueLength: args.maxValueLength,
          logLimit: args.logLimit ?? config.logLimit,
        })
        return {
          summary:
            `已生成 Hook 脚本（${hook.script.length} 字节，计划挂钩 ${hook.plannedTargets.length} 类目标）。` +
            '记得从捕获记录的「调用栈」里读出真正的加密入口。',
          plannedTargets: hook.plannedTargets,
          usage: hook.usage,
          notes: hook.notes,
          script: hook.script,
        }
      },
    }),
  )
}
