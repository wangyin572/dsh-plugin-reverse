/**
 * 工具 `rev_deobfuscate`：词法预处理与解混淆。
 *
 * 关键设计：把「安全重写」与「只读识别」分开呈现。模型看完报告后能明确知道
 * 哪些问题是工具已经解决的，哪些必须人工介入——这比给一个「看起来更干净但可能
 * 语义已变」的代码块要诚实得多。
 */
import type { Context } from '@deepseek-ai/cordis';
/** 工具插件。 */
export declare const name = "tool-rev-deobfuscate";
/** 依赖。 */
export declare const inject: string[];
/**
 * 注册 `rev_deobfuscate`。
 *
 * @param ctx - 上下文。
 */
export declare function apply(ctx: Context): void;
