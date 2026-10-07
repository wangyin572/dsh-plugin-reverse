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
import { type DeobfuscateFinding } from './deobfuscate.js';
import { type HostUsageReport } from './host.js';
/** 产出文件。 */
export interface GeneratedFile {
    /** 建议文件名。 */
    path: string;
    /** 文件内容。 */
    content: string;
    /** 该文件的用途说明。 */
    description: string;
}
/** 被抽取的符号。 */
export interface ExtractedSymbol {
    /** 符号名。 */
    name: string;
    /** 符号种类。 */
    kind: 'function' | 'variable' | 'class';
    /** 源码行号。 */
    line: number;
    /** 源码字节数。 */
    bytes: number;
}
/** 候选入口。 */
export interface EntryCandidate {
    /** 函数名。 */
    name: string;
    /** 推荐分数，越高越可能是签名/加解密入口。 */
    score: number;
    /** 推荐理由。 */
    reasons: string[];
}
/** 抽取结果。 */
export interface ExtractResult {
    /** 入口名。 */
    entries: string[];
    /** 抽取到的符号（含传递依赖）。 */
    symbols: ExtractedSymbol[];
    /** 生成的独立文件。 */
    files: GeneratedFile[];
    /** 宿主引用报告。 */
    hostReport: HostUsageReport;
    /** 需要从真实浏览器采集后注入的键。 */
    mustCapture: string[];
    /** 无法在 Node 中复现的能力。 */
    unmockable: string[];
    /** 阻断完整静态还原的问题。 */
    blockers: DeobfuscateFinding[];
    /** 引用了但无法解析的名字（多半来自未抽取的外层作用域或第三方库）。 */
    unresolved: string[];
    /** 自动推荐时的候选列表。 */
    candidates: EntryCandidate[];
    /** 生成代码里注入的宿主名。 */
    injectedGlobals: string[];
}
/**
 * 执行静态还原。
 *
 * @param code - 混淆源码。
 * @param options - 选项。
 * @returns 还原结果，含独立可运行的产出文件。
 */
export declare function extractPure(code: string, options?: {
    /** 入口函数名；留空时自动推荐。 */
    entry?: readonly string[];
    /** 是否生成 demo 文件，默认 true。 */
    includeDemo?: boolean;
}): ExtractResult;
