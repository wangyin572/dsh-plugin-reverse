/**
 * AST 基础设施：acorn 解析、通用遍历、源码定位。
 *
 * 类型策略：acorn 自带完整的 ESTree 接口，但节点是一大堆互不兼容的联合类型，
 * 在严格模式下逐节点窄化会让业务代码淹没在类型体操里。这里采用**单点收口**：
 * 在 `parseSource` 处做一次显式断言，之后统一用 {@link AstNode}（带 `type`/`start`/`end`
 * 的宽松节点）与 {@link prop}/{@link childNodes} 访问器操作。
 *
 * 这样 `any` 只出现在被注释说明的那一个转换点上，其余代码仍然是严格类型。
 */
/**
 * 统一使用的宽松 AST 节点视图。
 *
 * 之所以不用 acorn 的联合类型：本模块只关心「节点类型 + 属性名 + 源码位置」，
 * 而联合类型要求对每种节点单独收窄，会让通用遍历器无法实现。
 */
export interface AstNode {
    type: string;
    start: number;
    end: number;
    [key: string]: unknown;
}
/** 解析选项。 */
export interface ParseOptions {
    /** 优先按脚本解析，失败再按模块解析（混淆代码两种都有）。 */
    sourceType?: 'script' | 'module' | 'auto';
    /** 允许顶层 return（很多混淆文件被包在 IIFE 里被裁出来后会有）。 */
    allowReturnOutsideFunction?: boolean;
}
/**
 * 判断一个未知值是否是 AST 节点。
 *
 * @param value - 待判断值。
 * @returns 是否是节点。
 */
export declare function isNode(value: unknown): value is AstNode;
/**
 * 读取节点属性。
 *
 * @param node - 节点。
 * @param key - 属性名。
 * @returns 属性值（`unknown`，需调用方窄化）。
 */
export declare function prop(node: AstNode, key: string): unknown;
/**
 * 读取字符串属性。
 *
 * @param node - 节点。
 * @param key - 属性名。
 * @returns 字符串，或 `undefined`。
 */
export declare function strProp(node: AstNode, key: string): string | undefined;
/**
 * 读取布尔属性。
 *
 * @param node - 节点。
 * @param key - 属性名。
 * @returns 布尔值，或 `undefined`。
 */
export declare function boolProp(node: AstNode, key: string): boolean | undefined;
/**
 * 读取子节点属性。
 *
 * @param node - 节点。
 * @param key - 属性名。
 * @returns 子节点，或 `undefined`。
 */
export declare function childNode(node: AstNode, key: string): AstNode | undefined;
/**
 * 读取子节点数组属性。
 *
 * @param node - 节点。
 * @param key - 属性名。
 * @returns 子节点数组（非数组时为空数组）。
 */
export declare function childNodes(node: AstNode, key: string): AstNode[];
/**
 * 深度遍历一个节点（含自身），先序。
 *
 * @param root - 根节点。
 * @param visit - 访问回调；返回 `false` 可跳过该节点的子树。
 */
export declare function walk(root: AstNode, visit: (node: AstNode) => boolean | void): void;
/**
 * 收集一个节点及其所有后代。
 *
 * @param root - 根节点。
 * @returns 全部节点（先序）。
 */
export declare function collect(root: AstNode): AstNode[];
/**
 * 深度遍历并携带父节点与所在属性名。
 *
 * 与 {@link walk} 的区别：需要区分「标识符是引用」还是「标识符是属性名/声明名」时
 * （例如 `document.cookie` 里的 `cookie` 不是变量引用），必须知道父节点与键名，
 * 所以单独提供这个带上下文的遍历器。
 *
 * @param root - 根节点。
 * @param visit - 访问回调；返回 `false` 可跳过该节点子树。
 * @param parent - 内部递归用，调用方无需传入。
 * @param key - 内部递归用，调用方无需传入。
 */
export declare function walkDetailed(root: AstNode, visit: (node: AstNode, parent: AstNode | undefined, key: string | undefined) => boolean | void, parent?: AstNode, key?: string): void;
/**
 * 判断标识符在语法上是否是一次**变量读取**（而非声明名、属性名、标签名）。
 *
 * 说明：这不是完整的绑定解析，而是一个覆盖常见语法的实用判据。目标是让
 * 「宿主引用识别」和「自由变量计算」不把 `document.cookie` 里的 `cookie`
 * 误当成变量。误判会在报告的源码片段里暴露，便于人工复核。
 *
 * @param node - 标识符节点。
 * @param parent - 父节点。
 * @param key - 在父节点里的键名。
 * @returns 是否应视为变量读取。
 */
export declare function isReferencePosition(node: AstNode, parent: AstNode | undefined, key: string | undefined): boolean;
/**
 * 收集一个子树里所有被**读取**的标识符名（不含声明名与属性名）。
 *
 * @param root - 子树根。
 * @returns 被读取的名字集合。
 */
export declare function collectReferencedNames(root: AstNode): Set<string>;
/** 源码定位与切片工具。 */
export declare class SourceText {
    readonly code: string;
    /** 每一行起始偏移，用于把 `start` 换算成行列。 */
    private readonly lineStarts;
    /**
     * @param code - 原始源码。
     */
    constructor(code: string);
    /**
     * 把字符偏移换算为 1 基行列。
     *
     * @param offset - 字符偏移。
     * @returns 行列信息。
     */
    location(offset: number): {
        line: number;
        column: number;
    };
    /**
     * 取一段源码并压缩空白，用于报告里的示例片段。
     *
     * @param start - 起始偏移。
     * @param end - 结束偏移。
     * @param maxLength - 最大长度。
     * @returns 单行示例片段。
     */
    snippet(start: number, end: number, maxLength?: number): string;
    /**
     * 取原样源码片段。
     *
     * @param node - 节点。
     * @returns 该节点对应的源文本。
     */
    slice(node: {
        start: number;
        end: number;
    }): string;
}
/**
 * 解析源码为 AST。
 *
 * 混淆代码可能是脚本也可能是模块，这里按 `auto` 依次尝试，并在两次都失败时给出
 * 带行列的清晰报错——「解析不了」是逆向里最常见的第一个卡点，需要让人一眼看出位置。
 *
 * @param code - 源码文本。
 * @param options - 解析选项。
 * @returns 根节点与使用的源码类型。
 */
export declare function parseSource(code: string, options?: ParseOptions): {
    ast: AstNode;
    sourceType: 'script' | 'module';
    source: SourceText;
};
/**
 * 判断节点是否为函数（声明/表达式/箭头）。
 *
 * @param node - 节点。
 * @returns 是否是函数节点。
 */
export declare function isFunctionNode(node: AstNode): boolean;
/**
 * 取函数的参数名列表。
 *
 * @param fn - 函数节点。
 * @returns 参数名（解构参数会被压成占位名）。
 */
export declare function parameterNames(fn: AstNode): string[];
/**
 * 取节点的名字（标识符、成员属性、变量声明等场景）。
 *
 * @param node - 节点。
 * @returns 名字，取不到时为 `undefined`。
 */
export declare function nodeName(node: AstNode): string | undefined;
