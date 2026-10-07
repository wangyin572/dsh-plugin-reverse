/**
 * 宿主环境（DOM/BOM）识别与最小桩生成。
 *
 * ## 这个文件要解决的核心问题
 *
 * 抠出来的前端代码之所以在 Node 里跑不起来，是因为它默认自己活在浏览器里：
 * `window`、`document`、`navigator`、`canvas` 全是现成的。想让它变成纯计算函数，
 * 必须先回答两个不同的问题——**混淆点在于它们经常被混为一谈**：
 *
 *   1. **可以去掉的**：只为了与页面交互、上报、渲染而存在的调用（`addEventListener`、
 *      `appendChild`、`sendBeacon`…）。这些对计算结果没有贡献，桩成 no-op 即可。
 *
 *   2. **不能凭空造的**：参与签名计算的环境输入（`navigator.userAgent`、
 *      `screen.width`、canvas 指纹、`performance.now()`…）。这些**必须从真实浏览器里
 *      采集后注入**，任何「模拟一个值」的做法都会算出与目标不一致的签名。
 *
 * 所以本模块的输出不是一个「浏览器模拟器」，而是：
 *   - 一份**引用清单**（谁被引用了、在哪个函数里、属于上面哪一类）；
 *   - 一个**最小 env 工厂**（只含被引用到的全局，no-op 与可计算的部分给真实实现，
 *     必须采集的部分留成显式占位并标注 `MUST_CAPTURE`）。
 *
 * 明确不做的事：不引入 jsdom / happy-dom 之类的浏览器模拟库。理由同上——模拟器会
 * 给出**看似合理但错误**的指纹值，反而把「算错了」伪装成「算对了」。
 */
import { type AstNode, type SourceText } from './ast.js';
/** 宿主 API 的类别。 */
export type HostCategory = 'dom' | 'bom' | 'storage' | 'network' | 'graphics' | 'timing' | 'crypto' | 'encoding' | 'platform' | 'diagnostic';
/**
 * 该宿主 API 对「纯计算」的意义。
 *
 * - `removable`：移除或桩成 no-op 不影响计算结果，纯副作用。
 * - `capturable`：值参与计算但可在 Node 中确定复现（如字符集、编解码）。
 * - `must-capture`：值参与计算且**依赖真实浏览器实例**，必须采集后注入。
 * - `diagnostic`：仅日志/调试用途。
 */
export type HostRelevance = 'removable' | 'capturable' | 'must-capture' | 'diagnostic';
/** 一条宿主全局的描述。 */
export interface HostGlobalSpec {
    /** 全局名。 */
    name: string;
    /** 类别。 */
    category: HostCategory;
    /** 对纯计算的意义。 */
    relevance: HostRelevance;
    /** 为什么这样归类（会进报告，供人复核）。 */
    note: string;
}
/**
 * 宿主全局目录。
 *
 * 只收录**在真实混淆代码里高频出现**的项，而不是把浏览器 API 全表抄一遍——
 * 清单越长越难维护，而实际会拦住静态还原的就那几十个。
 */
export declare const HOST_GLOBALS: readonly HostGlobalSpec[];
/**
 * 判断一个标识符名是否为已知宿主全局。
 *
 * @param name - 标识符名。
 * @returns 目录项，未收录时为 `undefined`。
 */
export declare function lookupHostGlobal(name: string): HostGlobalSpec | undefined;
/** 单个宿主引用的聚合信息。 */
export interface HostReference {
    /** 全局名。 */
    name: string;
    /** 类别。 */
    category: HostCategory;
    /** 对纯计算的意义。 */
    relevance: HostRelevance;
    /** 归类理由。 */
    note: string;
    /** 引用次数。 */
    count: number;
    /** 观察到的成员访问路径，如 `navigator.userAgent`。 */
    memberPaths: string[];
    /** 引用位置（最多保留 5 处）。 */
    locations: {
        line: number;
        column: number;
        snippet: string;
        enclosing: string;
    }[];
}
/** 宿主引用分析结果。 */
export interface HostUsageReport {
    /** 按引用次数降序的引用列表。 */
    references: HostReference[];
    /** 需要采集真实值才能复现签名的全局名。 */
    mustCapture: string[];
    /** 可以安全移除或 no-op 的全局名。 */
    removable: string[];
    /** 无法在 Node 中复现、也无法可靠桩化的能力（如 canvas 指纹）。 */
    unmockable: string[];
    /** 每个函数体内触碰宿主 API 的次数，用于定位「最像签名入口」的函数。 */
    functionScores: {
        name: string;
        hostTouches: number;
        line: number;
    }[];
}
/**
 * 收集源码里所有被声明的绑定名（变量、函数、类、参数、catch、import）。
 *
 * 注意：这是**文件级**的扁平集合，只适合回答「这个名字在本文件里是否被声明过」
 * （例如闭包抽取判断某个符号是否存在）。判断「某处引用是否被遮蔽」必须用
 * {@link buildScopeBindings} + {@link isShadowed}，否则会漏检宿主依赖。
 *
 * @param root - 根节点。
 * @returns 被声明的名字集合。
 */
export declare function collectDeclaredNames(root: AstNode): Set<string>;
/**
 * 分析源码里的宿主环境引用。
 *
 * @param ast - 已解析的根节点。
 * @param source - 源码工具。
 * @returns 分析结果。
 */
export declare function analyzeHostUsage(ast: AstNode, source: SourceText): HostUsageReport;
/** 最小宿主桩的生成结果。 */
export interface StubGenerationResult {
    /** `env.mjs` 的完整源码。 */
    source: string;
    /** 需要从真实浏览器采集的键（形如 `navigator.userAgent`）。 */
    mustCapture: string[];
    /** 无法在 Node 中复现的键。 */
    unmockable: string[];
    /** 被写入桩文件的全局名。 */
    injected: string[];
}
/**
 * 生成最小 env 工厂源码。
 *
 * 只包含**实际被引用到**的全局；每个 `must-capture` 项都带 `MUST_CAPTURE` 注释，
 * 提示必须用真实浏览器采集到的值覆盖，否则签名会不一致。
 *
 * @param report - {@link analyzeHostUsage} 的结果。
 * @param options - 生成选项。
 * @returns 桩源码与清单。
 */
export declare function generateStubs(report: HostUsageReport, options?: {
    seed?: number;
}): StubGenerationResult;
/**
 * 校验宿主报告非空。
 *
 * @param report - 报告。
 */
export declare function assertHasHostReferences(report: HostUsageReport): void;
