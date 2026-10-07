/**
 * `dsh-plugin-reverse` —— DeepSeek Harness 逆向工程工具包。
 *
 * ## 能力
 *
 * 两条互补的工作流，外加一个「先判断走哪条路」的评估入口：
 *
 * | 路线 | 工具 | 产出 |
 * |---|---|---|
 * | 评估 | `rev_assess` | 需求评估报告：Hook 是否可行、静态还原是否可行、卡点与执行计划 |
 * | ① 辅助定位 | `rev_hook_generate` | 浏览器可执行的 Hook 脚本（调试取证用，附调用栈） |
 * | ② 静态还原 | `rev_extract_pure` | 无宿主依赖的纯算模块 `pure.mjs` / `env.mjs` / `demo.mjs` |
 * | 预处理 | `rev_deobfuscate` | 语义等价的安全重写 + 只读的混淆特征识别 |
 * | 验算 | `rev_crypto_calc` | AES / RSA / MD5 / SHA / HMAC / 异或 的快速复算 |
 *
 * ## 分层
 *
 * ```
 * src/core/        纯函数核心，不依赖 cordis / DSH，可单独复制出去在 Node 里用
 * src/analysis/    基于 acorn 的静态分析、解混淆、闭包抽取、Hook 生成
 * src/services/    把上面两层包装成 cordis 服务（ctx.reverseCrypto / ctx.reverseAnalysis）
 * src/tools/       面向模型的 agent 工具（defineTool）
 * ```
 *
 * 依赖方向是单向的：tools → services → analysis/core。核心层永远不会反向依赖 DSH，
 * 因此「静态还原产出的纯算代码」与「本插件自己的核心」遵循同一套无宿主约束。
 *
 * ## 适用范围
 *
 * 本插件面向**你自己有权分析的代码**：自有项目、已授权的测试、恶意样本分析、
 * CTF、以及互通性研究。Hook 与静态还原都是通用调试技术，不对特定目标做任何针对性绕过。
 */
import Schema from '@deepseek-ai/schemastery';
import { ReverseAnalysisService } from './services/analysis-service.js';
import { ReverseCryptoService } from './services/crypto-service.js';
import * as assessTool from './tools/assess-tool.js';
import * as cryptoTool from './tools/crypto-tool.js';
import * as deobfuscateTool from './tools/deobfuscate-tool.js';
import * as extractTool from './tools/extract-tool.js';
import * as hookTool from './tools/hook-tool.js';
/**
 * 插件身份。
 *
 * 与 `cordis.patch.yml` 里的行 `id`（`reverse-toolkit`）保持一致，便于排查加载问题。
 */
export const name = 'reverse-toolkit';
/**
 * 依赖 `tools` 服务：本插件注册的全是 agent 工具，没有工具注册表就没有意义。
 *
 * 内部各工具还会各自声明对 `reverseCrypto` / `reverseAnalysis` 的依赖，
 * 由 cordis 保证「服务就绪后才挂载工具」的顺序，无需手工编排。
 */
export const inject = ['tools'];
/**
 * 配置 schema。
 *
 * 有默认值，因此在 `cordis.patch.yml` 里可以不写 `config` 段直接使用。
 */
export const Config = Schema.object({
    maxSourceBytes: Schema.natural().default(2_000_000),
    hookLogLimit: Schema.natural().default(2000),
    hookAutoDiscover: Schema.boolean().default(true),
});
/**
 * 挂载插件。
 *
 * @param ctx - 已具备 `tools` 服务的上下文。
 * @param config - 已校验并补齐默认值的配置。
 */
export function apply(ctx, config) {
    // 服务层：先挂服务，工具层的 inject 会等它们就绪。
    ctx.plugin(ReverseCryptoService);
    ctx.plugin(ReverseAnalysisService, { maxSourceBytes: config.maxSourceBytes });
    // 工具层：用显式描述对象挂载，而不是直接挂 ESM 模块命名空间。
    // 命名空间对象是冻结的，而插件注册表在规范化元数据时可能写入字段；
    // 显式描述对象既避开这类边界，也让每个工具的依赖一眼可见。
    ctx.plugin({ name: cryptoTool.name, inject: cryptoTool.inject, apply: cryptoTool.apply });
    ctx.plugin({ name: assessTool.name, inject: assessTool.inject, apply: assessTool.apply });
    ctx.plugin({ name: deobfuscateTool.name, inject: deobfuscateTool.inject, apply: deobfuscateTool.apply });
    ctx.plugin({ name: extractTool.name, inject: extractTool.inject, apply: extractTool.apply });
    ctx.plugin({
        name: hookTool.name,
        inject: hookTool.inject,
        Config: hookTool.Config,
        apply: hookTool.apply,
    }, { logLimit: config.hookLogLimit, autoDiscover: config.hookAutoDiscover });
}
export { ReverseAnalysisService, ReverseCryptoService };
