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
import { defineTool } from '@deepseek-ai/dsh-tools';
import { ReverseError } from '../core/errors.js';
/** 单个文件在渲染时允许内联的最大字符数。 */
const RENDER_LIMIT = 60_000;
/**
 * 把 `json` 类型的结果收窄成文件列表。
 *
 * `type: 'json'` 在类型上是 `JsonValue`，渲染前必须显式收窄——这也顺带保证了
 * 即使产出结构意外变化，渲染也不会抛异常。
 *
 * @param value - schema 校验通过后的 json 值。
 * @returns 文件列表（结构不符的条目被丢弃）。
 */
function asFileList(value) {
    if (!Array.isArray(value))
        return [];
    const files = [];
    for (const item of value) {
        if (typeof item !== 'object' || item === null || Array.isArray(item))
            continue;
        const record = item;
        const path = typeof record.path === 'string' ? record.path : '';
        if (path === '')
            continue;
        files.push({
            path,
            description: typeof record.description === 'string' ? record.description : '',
            ...(typeof record.content === 'string' ? { content: record.content } : {}),
        });
    }
    return files;
}
/** 工具插件。 */
export const name = 'tool-rev-extract-pure';
/** 依赖。 */
export const inject = ['tools', 'reverseAnalysis'];
/**
 * 注册 `rev_extract_pure`。
 *
 * @param ctx - 上下文。
 */
export function apply(ctx) {
    const service = ctx.reverseAnalysis;
    ctx.tools.register(defineTool({
        name: 'rev_extract_pure',
        description: 'Static restoration: turn obfuscated browser JavaScript into standalone pure-computation ' +
            'modules that run in plain Node with no DOM/BOM globals. It computes the dependency closure ' +
            'of the entry function (verbatim source slices, no rewriting), injects every host object from ' +
            'an `env` argument instead of rewriting each reference, and emits pure.mjs + env.mjs + demo.mjs. ' +
            'Environment values that depend on a real browser instance (userAgent, cookie, canvas ' +
            'fingerprints…) are emitted as explicit MUST_CAPTURE placeholders rather than invented values. ' +
            'When the code cannot be restored faithfully (eval/Function/with, unresolvable outer scope), ' +
            'it returns a blocker report instead of code that silently computes the wrong result.',
        parameters: {
            code: { type: 'string', required: true, description: 'The extracted front-end JavaScript source.' },
            entry: {
                type: 'array',
                items: { type: 'string' },
                description: 'Entry function name(s) to restore. Omit to auto-recommend: functions that read host APIs ' +
                    'and/or carry crypto-ish names score highest.',
            },
            includeDemo: {
                type: 'boolean',
                description: 'Emit demo.mjs with a runnable self-check. Default true.',
            },
            includeContents: {
                type: 'boolean',
                description: 'Include full file contents in the result so they can be written to disk. Default true.',
            },
        },
        output: {
            schema: {
                type: 'object',
                additionalProperties: false,
                properties: {
                    summary: { type: 'string', required: true },
                    entries: { type: 'array', required: true, items: { type: 'string' } },
                    symbols: { type: 'array', required: true, items: { type: 'string' } },
                    injectedGlobals: { type: 'array', required: true, items: { type: 'string' } },
                    mustCapture: { type: 'array', required: true, items: { type: 'string' } },
                    unmockable: { type: 'array', required: true, items: { type: 'string' } },
                    unresolved: { type: 'array', required: true, items: { type: 'string' } },
                    blockers: { type: 'array', required: true, items: { type: 'string' } },
                    candidates: { type: 'array', required: true, items: { type: 'string' } },
                    files: { type: 'json', required: true },
                },
            },
            render: (_args, value) => {
                const lines = [value.summary, ''];
                lines.push(`入口：${value.entries.join(', ')}`);
                lines.push(`依赖闭包（${value.symbols.length}）：${value.symbols.slice(0, 12).join(', ')}${value.symbols.length > 12 ? ' …' : ''}`);
                lines.push(`注入的宿主对象：${value.injectedGlobals.join(', ') || '(无)'}`);
                if (value.mustCapture.length > 0) {
                    lines.push('', '必须从真实浏览器采集后注入（否则签名不一致）：');
                    for (const item of value.mustCapture)
                        lines.push(`  · ${item}`);
                }
                if (value.unmockable.length > 0) {
                    lines.push('', '无法在 Node 复现，需外部采集：');
                    for (const item of value.unmockable)
                        lines.push(`  · ${item}`);
                }
                if (value.blockers.length > 0) {
                    lines.push('', '卡点（请先处理这些，不要直接使用产出代码）：');
                    for (const blocker of value.blockers)
                        lines.push(`  · ${blocker}`);
                }
                if (value.unresolved.length > 0) {
                    lines.push('', `无法解析的名字：${value.unresolved.slice(0, 15).join(', ')}`);
                }
                const files = asFileList(value.files);
                if (files.length > 0) {
                    lines.push('', '--- 产出文件（请用文件工具落盘后运行 demo.mjs 验证）---');
                    for (const file of files) {
                        const content = typeof file.content === 'string' ? file.content : '';
                        lines.push('', `===== ${file.path} — ${file.description} =====`, content.length > RENDER_LIMIT
                            ? `${content.slice(0, RENDER_LIMIT)}\n…（已截断，请用 includeContents=false 并另行获取）`
                            : content);
                    }
                }
                return [{ type: 'text', text: lines.join('\n') }];
            },
        },
        async execute(args) {
            try {
                const result = service.runExtract(args.code, {
                    entry: args.entry,
                    includeDemo: args.includeDemo,
                });
                const includeContents = args.includeContents !== false;
                return {
                    summary: `已还原 ${result.entries.length} 个入口，依赖闭包 ${result.symbols.length} 个符号，` +
                        `生成 ${result.files.length} 个文件；卡点 ${result.blockers.length} 条`,
                    entries: [...result.entries],
                    symbols: result.symbols.map((symbol) => `${symbol.name}(${symbol.kind}, 第${symbol.line}行)`),
                    injectedGlobals: result.injectedGlobals,
                    mustCapture: result.mustCapture,
                    unmockable: result.unmockable,
                    unresolved: result.unresolved,
                    blockers: result.blockers.map((blocker) => `${blocker.kind}: ${blocker.message}`),
                    candidates: result.candidates
                        .slice(0, 8)
                        .map((candidate) => `${candidate.name}(${candidate.score}): ${candidate.reasons.join('；')}`),
                    files: result.files.map((file) => ({
                        path: file.path,
                        description: file.description,
                        ...(includeContents ? { content: file.content } : {}),
                    })),
                };
            }
            catch (error) {
                if (error instanceof ReverseError)
                    throw new Error(`[${error.code}] ${error.message}`);
                throw error;
            }
        },
    }));
}
