/**
 * 逆向分析服务：把分析层包装成 cordis 服务 `ctx.reverseAnalysis`。
 *
 * 之所以把「源码规模上限」放在服务配置里而不是工具里：工具是给模型用的外层，
 * 服务是真正的执行边界。把闸门放在执行边界上，任何调用方（工具、其他插件、
 * 后续新增的入口）都绕不过去。
 */

import { Service } from '@deepseek-ai/cordis'
import type { Context } from '@deepseek-ai/cordis'
import Schema from '@deepseek-ai/schemastery'

import { ReverseError } from '../core/errors.js'
import { type AssessmentReport, assess } from '../analysis/assess.js'
import {
  type DeobfuscateResult,
  deobfuscate,
} from '../analysis/deobfuscate.js'
import { type ExtractResult, extractPure } from '../analysis/extract.js'
import { type HookOptions, type HookScript, generateHookScript } from '../analysis/hook.js'
import { type HostUsageReport, analyzeHostUsage } from '../analysis/host.js'
import { parseSource } from '../analysis/ast.js'

/** 服务配置。 */
export interface AnalysisServiceConfig {
  /** 单次分析允许的最大源码字节数，默认 2MB。 */
  maxSourceBytes: number
}

/** 逆向分析服务。 */
export class ReverseAnalysisService extends Service {
  /** 配置 schema：由 cordis 在挂载前校验并补默认值。 */
  static Config = Schema.object({
    maxSourceBytes: Schema.natural().default(2_000_000),
  })

  /** 源码规模上限。 */
  private readonly maxSourceBytes: number

  /**
   * @param ctx - 宿主上下文。
   * @param config - 已校验的配置。
   */
  constructor(ctx: Context, config: AnalysisServiceConfig) {
    super(ctx, 'reverseAnalysis')
    this.maxSourceBytes = config.maxSourceBytes
  }

  /**
   * 校验源码规模，避免把巨型 bundle 塞进同步分析里拖垮宿主进程。
   *
   * @param code - 源码。
   * @param what - 操作名，用于错误信息。
   */
  private guardSource(code: string, what: string): void {
    if (code.trim().length === 0) {
      throw new ReverseError(`${what}：输入源码为空`, 'INVALID_INPUT')
    }
    const bytes = Buffer.byteLength(code, 'utf8')
    if (bytes > this.maxSourceBytes) {
      throw new ReverseError(
        `${what}：源码 ${bytes} 字节超过上限 ${this.maxSourceBytes} 字节。` +
          '请先把目标文件切分到「真正参与计算的那一段」再分析——' +
          '整包分析既慢又没有意义（依赖闭包只关心入口用到的那部分）。' +
          '需要放宽时调整插件配置 maxSourceBytes。',
        'INVALID_INPUT',
      )
    }
  }

  /**
   * 需求评估：先判断走哪条路。
   *
   * @param code - 源码。
   * @returns 评估报告。
   */
  runAssess(code: string): AssessmentReport {
    this.guardSource(code, '需求评估')
    return assess(code)
  }

  /**
   * 词法预处理与解混淆。
   *
   * @param code - 源码。
   * @param options - 选项。
   * @returns 结果。
   */
  runDeobfuscate(code: string, options: { rewrite?: boolean; foldRounds?: number } = {}): DeobfuscateResult {
    this.guardSource(code, '解混淆')
    return deobfuscate(code, options)
  }

  /**
   * 静态还原为纯计算模块。
   *
   * @param code - 源码。
   * @param options - 选项。
   * @returns 结果，含独立可运行文件。
   */
  runExtract(code: string, options: { entry?: readonly string[]; includeDemo?: boolean } = {}): ExtractResult {
    this.guardSource(code, '静态还原')
    return extractPure(code, options)
  }

  /**
   * 生成 Hook 脚本。
   *
   * @param options - 选项。
   * @returns 脚本与说明。
   */
  runHook(options: HookOptions): HookScript {
    return generateHookScript(options)
  }

  /**
   * 只做宿主引用分析。
   *
   * @param code - 源码。
   * @returns 报告。
   */
  runHostAnalysis(code: string): HostUsageReport {
    this.guardSource(code, '宿主分析')
    const { ast, source } = parseSource(code)
    return analyzeHostUsage(ast, source)
  }
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    /** 逆向分析服务。 */
    reverseAnalysis: ReverseAnalysisService
  }
}
