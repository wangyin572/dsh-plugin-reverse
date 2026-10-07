/**
 * 工具 `rev_extract_pure`：把混淆代码静态还原为可在 Node 独立运行的纯计算模块。
 *
 * 这是本插件的重点能力。它返回**三个可直接落盘的文件**：
 *   pure.mjs  依赖闭包 + 环境注入，无任何 DOM/BOM 全局引用
 *   env.mjs   最小宿主桩，只含被引用到的全局，MUST_CAPTURE 项留显式占位
 *   demo.mjs  可直接 `node demo.mjs` 跑通的验证入口
 *
 * 工具本身**不写磁盘**：文件内容随结果返回，由调用方用常规文件工具落盘。
 * 这样插件的执行不越过沙箱与审批策略，也便于调用方自行决定输出位置。
 */
import type { Context } from '@deepseek-ai/cordis';
/** 工具插件。 */
export declare const name = "tool-rev-extract-pure";
/** 依赖。 */
export declare const inject: string[];
/**
 * 注册 `rev_extract_pure`。
 *
 * @param ctx - 上下文。
 */
export declare function apply(ctx: Context): void;
