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
import { type AstNode } from './ast.js';
/** 一次安全重写的记录。 */
export interface DeobfuscateChange {
    /** 变换类别。 */
    kind: 'literal-unescape' | 'constant-fold' | 'member-access';
    /** 所在行。 */
    line: number;
    /** 变换前源码。 */
    before: string;
    /** 变换后源码。 */
    after: string;
}
/** 严重程度。 */
export type FindingSeverity = 'info' | 'warn' | 'blocker';
/** 一条发现。 */
export interface DeobfuscateFinding {
    /** 类别标识。 */
    kind: string;
    /** 严重程度；`blocker` 表示静态还原会因此受阻。 */
    severity: FindingSeverity;
    /** 人类可读说明。 */
    message: string;
    /** 所在行（能确定时）。 */
    line?: number;
    /** 附加结构信息。 */
    detail?: string;
}
/** 源码统计量，用于给混淆程度打分。 */
export interface DeobfuscateStats {
    /** 形如 `_0x1a2b` 的标识符占比。 */
    identifierObfuscationRatio: number;
    /** 疑似字符串数组的候选数量。 */
    stringArrayCandidates: number;
    /** 疑似控制流平坦化的循环数量。 */
    controlFlowFlattening: number;
    /** eval / Function 构造 等动态执行点数量。 */
    dynamicExecution: number;
    /** debugger 语句数量。 */
    debuggerStatements: number;
    /** 总节点数，用于判断文件规模。 */
    nodeCount: number;
}
/** 解混淆结果。 */
export interface DeobfuscateResult {
    /** 重写后的源码。 */
    code: string;
    /** 依次记录的安全重写。 */
    changes: DeobfuscateChange[];
    /** 发现清单（含卡点）。 */
    findings: DeobfuscateFinding[];
    /** 统计量。 */
    stats: DeobfuscateStats;
    /** 混淆程度 0-100，越高越难静态还原。 */
    obfuscationScore: number;
    /** 明确无法自动处理、需要人工介入的点。 */
    blockers: DeobfuscateFinding[];
}
/**
 * 执行解混淆流水线。
 *
 * @param code - 源码文本。
 * @param options - 选项。
 * @returns 结果，含重写后的代码、变更记录、发现与评分。
 */
export declare function deobfuscate(code: string, options?: {
    /** 是否应用安全重写；`false` 时只做分析与报告。默认 `true`。 */
    rewrite?: boolean;
    /** 连续折叠的轮数，默认 3（`!![]` 这类需要多轮）。 */
    foldRounds?: number;
}): DeobfuscateResult;
/**
 * 只做分析、不改代码的便捷入口。
 *
 * @param code - 源码文本。
 * @returns 结果（`code` 字段等于输入）。
 */
export declare function analyzeOnly(code: string): DeobfuscateResult;
/**
 * 判断一个节点是否是可被抽取的「顶层符号」（函数或变量初始化）。
 *
 * 供 closure 抽取复用。
 *
 * @param node - 节点。
 * @returns 是否是顶层符号定义。
 */
export declare function isExtractableSymbol(node: AstNode): boolean;
