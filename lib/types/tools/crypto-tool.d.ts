/**
 * 工具 `rev_crypto_calc`：密码学快速验算。
 *
 * 用途是「手上有一段密文/一个已知摘要，想立刻确认自己的算法理解对不对」。
 * 所有参数都是扁平的，靠 `operation` 分派——这样模型一次调用就能完成验算，
 * 不必先猜结构再补调用。
 */
import type { Context } from '@deepseek-ai/cordis';
/** 工具插件。 */
export declare const name = "tool-rev-crypto";
/** 依赖：工具注册表 + 密码学服务。 */
export declare const inject: string[];
/**
 * 注册 `rev_crypto_calc`。
 *
 * @param ctx - 已满足依赖的上下文。
 */
export declare function apply(ctx: Context): void;
