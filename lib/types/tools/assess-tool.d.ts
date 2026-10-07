/**
 * 工具 `rev_assess`：逆向任务的需求评估。
 *
 * 这是**所有逆向任务的第一步**。它先判断该走 Hook 还是静态还原，再给执行计划——
 * 避免在错误的路线上浪费时间（例如对着一个 VM 解释器硬做静态还原）。
 */
import type { Context } from '@deepseek-ai/cordis';
/** 工具插件。 */
export declare const name = "tool-rev-assess";
/** 依赖。 */
export declare const inject: string[];
/**
 * 注册 `rev_assess`。
 *
 * @param ctx - 上下文。
 */
export declare function apply(ctx: Context): void;
