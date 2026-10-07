/**
 * 逆向分析服务：把分析层包装成 cordis 服务 `ctx.reverseAnalysis`。
 *
 * 之所以把「源码规模上限」放在服务配置里而不是工具里：工具是给模型用的外层，
 * 服务是真正的执行边界。把闸门放在执行边界上，任何调用方（工具、其他插件、
 * 后续新增的入口）都绕不过去。
 */
import { Service } from '@deepseek-ai/cordis';
import type { Context } from '@deepseek-ai/cordis';
import Schema from '@deepseek-ai/schemastery';
import { type AssessmentReport } from '../analysis/assess.js';
import { type DeobfuscateResult } from '../analysis/deobfuscate.js';
import { type ExtractResult } from '../analysis/extract.js';
import { type HookOptions, type HookScript } from '../analysis/hook.js';
import { type HostUsageReport } from '../analysis/host.js';
/** 服务配置。 */
export interface AnalysisServiceConfig {
    /** 单次分析允许的最大源码字节数，默认 2MB。 */
    maxSourceBytes: number;
}
/** 逆向分析服务。 */
export declare class ReverseAnalysisService extends Service {
    /** 配置 schema：由 cordis 在挂载前校验并补默认值。 */
    static Config: Schema<Schemastery.ObjectS<NoInfer<{
        maxSourceBytes: Schema<number, number, "defined">;
    }>>, Schemastery.ObjectT<NoInfer<{
        maxSourceBytes: Schema<number, number, "defined">;
    }>>, "plain">;
    /** 源码规模上限。 */
    private readonly maxSourceBytes;
    /**
     * @param ctx - 宿主上下文。
     * @param config - 已校验的配置。
     */
    constructor(ctx: Context, config: AnalysisServiceConfig);
    /**
     * 校验源码规模，避免把巨型 bundle 塞进同步分析里拖垮宿主进程。
     *
     * @param code - 源码。
     * @param what - 操作名，用于错误信息。
     */
    private guardSource;
    /**
     * 需求评估：先判断走哪条路。
     *
     * @param code - 源码。
     * @returns 评估报告。
     */
    runAssess(code: string): AssessmentReport;
    /**
     * 词法预处理与解混淆。
     *
     * @param code - 源码。
     * @param options - 选项。
     * @returns 结果。
     */
    runDeobfuscate(code: string, options?: {
        rewrite?: boolean;
        foldRounds?: number;
    }): DeobfuscateResult;
    /**
     * 静态还原为纯计算模块。
     *
     * @param code - 源码。
     * @param options - 选项。
     * @returns 结果，含独立可运行文件。
     */
    runExtract(code: string, options?: {
        entry?: readonly string[];
        includeDemo?: boolean;
    }): ExtractResult;
    /**
     * 生成 Hook 脚本。
     *
     * @param options - 选项。
     * @returns 脚本与说明。
     */
    runHook(options: HookOptions): HookScript;
    /**
     * 只做宿主引用分析。
     *
     * @param code - 源码。
     * @returns 报告。
     */
    runHostAnalysis(code: string): HostUsageReport;
}
declare module '@deepseek-ai/cordis' {
    interface Context {
        /** 逆向分析服务。 */
        reverseAnalysis: ReverseAnalysisService;
    }
}
