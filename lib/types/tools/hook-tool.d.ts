/**
 * 工具 `rev_hook_generate`：生成用于**调试取证**的函数 Hook 脚本。
 *
 * 定位说明（也会写进工具描述，因为模型需要据此选择路线）：
 *   Hook 用于「定位加密入口」——观察函数的入参、返回值与调用栈。
 *   它不产出可交付的纯算代码；那条路由 `rev_extract_pure` 负责。
 */
import type { Context } from '@deepseek-ai/cordis';
import Schema from '@deepseek-ai/schemastery';
/** 工具插件配置（由根插件下发）。 */
export interface HookToolConfig {
    /** 日志缓冲区上限。 */
    logLimit: number;
    /** 是否默认开启自动发现。 */
    autoDiscover: boolean;
}
/** 工具插件。 */
export declare const name = "tool-rev-hook";
/** 依赖。 */
export declare const inject: string[];
/** 配置 schema。 */
export declare const Config: Schema<Schemastery.ObjectS<NoInfer<{
    logLimit: Schema<number, number, "defined">;
    autoDiscover: Schema<boolean, boolean, "defined">;
}>>, Schemastery.ObjectT<NoInfer<{
    logLimit: Schema<number, number, "defined">;
    autoDiscover: Schema<boolean, boolean, "defined">;
}>>, "plain">;
/**
 * 注册 `rev_hook_generate`。
 *
 * @param ctx - 上下文。
 * @param config - 插件配置。
 */
export declare function apply(ctx: Context, config: HookToolConfig): void;
