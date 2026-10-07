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
import { type DeobfuscateFinding, type DeobfuscateStats } from './deobfuscate.js';
import { type EntryCandidate } from './extract.js';
/** 置信度。 */
export type Confidence = 'high' | 'medium' | 'low';
/** 一条可行性结论。 */
export interface Feasibility {
    /** 是否可行。 */
    feasible: boolean;
    /** 置信度。 */
    confidence: Confidence;
    /** 判断依据（逐条给出，便于人工复核）。 */
    reasons: string[];
}
/** 推荐路线。 */
export type Verdict = 'static-first' | 'hook-first' | 'hook-then-static' | 'blocked';
/** 评估报告。 */
export interface AssessmentReport {
    /** 推荐路线。 */
    verdict: Verdict;
    /** 一句话结论。 */
    summary: string;
    /** Hook 可行性。 */
    hook: Feasibility;
    /** 静态还原可行性。 */
    static: Feasibility;
    /** 混淆程度（0-100）。 */
    obfuscation: {
        score: number;
        features: string[];
        stats: DeobfuscateStats;
    };
    /** 卡点清单。 */
    blockers: DeobfuscateFinding[];
    /** 全部发现。 */
    findings: DeobfuscateFinding[];
    /** 宿主环境依赖概况。 */
    host: {
        /** 参与计算但必须采集的环境值。 */
        mustCapture: string[];
        /** 可移除的副作用。 */
        removable: string[];
        /** 无法在 Node 复现的能力。 */
        unmockable: string[];
        /** 触碰宿主 API 最多的函数（最可能是签名入口）。 */
        topFunctions: {
            name: string;
            hostTouches: number;
            line: number;
        }[];
    };
    /** 推荐入口候选。 */
    recommendedEntries: EntryCandidate[];
    /** 有序的执行计划。 */
    plan: string[];
}
/**
 * 生成需求评估报告。
 *
 * @param code - 待评估源码。
 * @param options - 选项。
 * @returns 评估报告。
 */
export declare function assess(code: string, options?: {
    maxFindings?: number;
}): AssessmentReport;
/**
 * 把评估报告渲染成便于阅读的 Markdown 文本。
 *
 * 工具返回值需要给模型看，段落化比裸 JSON 更省 token 也更好读。
 *
 * @param report - 评估报告。
 * @returns Markdown 文本。
 */
export declare function renderAssessment(report: AssessmentReport): string;
