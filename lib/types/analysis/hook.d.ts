/**
 * Hook 脚本生成（辅助定位路线）。
 *
 * ## 定位
 *
 * 明确一点：Hook 脚本**只用于调试与取证**——在你自己有权分析的页面里观察
 * 「哪个函数被调用、入参是什么、返回值是什么」，从而定位加密入口。它不产出可交付的
 * 纯算代码；那条路由 {@link ../analysis/extract} 负责。
 *
 * ## 为什么生成的不是一段「裸 wrap」
 *
 * 真实网站上直接 wrap 一个方法，经常会遇到两件事：
 *   1. 目标把 `window` 上的方法引用提前缓存了（`var _e = window.encrypt`），
 *      只替换 `window.encrypt` 抓不到调用；
 *   2. 目标用 `Function.prototype.toString` 校验「函数有没有被改过」。
 *
 * 所以生成物包含：**多路径覆盖**（同时挂到缓存别名与原型上）、**调用栈记录**
 * （用来反推是谁调用了加密函数，这才是定位入口的关键信息）、以及可选的
 * `toString` 伪装。这些都是浏览器调试器里公开可见、日常排查手段的一部分。
 *
 * 生成物是一个自包含 IIFE，不依赖任何库，可直接粘进 DevTools 控制台。
 */
/** 一个待 Hook 的目标。 */
export interface HookTarget {
    /** 对象路径，如 `window.crypto.subtle`、`CryptoJS.AES`、`XMLHttpRequest.prototype`。 */
    object: string;
    /** 方法名，如 `encrypt`。 */
    method: string;
    /** 日志里的显示名，留空自动生成。 */
    label?: string;
}
/** Hook 生成选项。 */
export interface HookOptions {
    /** 显式目标；留空时按内置预设 + 自动发现。 */
    targets?: readonly HookTarget[];
    /** 是否扫描 window 上名字可疑的函数并挂 Hook，默认 true。 */
    autoDiscover?: boolean;
    /** 是否包含网络层（XHR / fetch / WebSocket / sendBeacon），默认 true。 */
    includeNetwork?: boolean;
    /** 是否对 `Function.prototype.toString` 做伪装，默认 true。 */
    stealth?: boolean;
    /** 单个参数序列化后的最大字符数，默认 500。 */
    maxValueLength?: number;
    /** 日志缓冲区上限，默认 2000 条。 */
    logLimit?: number;
    /** 内置预设名；默认全开。 */
    presets?: readonly ('webcrypto' | 'cryptojs' | 'jsencrypt' | 'encoding')[];
}
/** 生成结果。 */
export interface HookScript {
    /** 可直接粘贴执行的脚本。 */
    script: string;
    /** 使用说明。 */
    usage: string[];
    /** 该脚本会尝试 Hook 的目标（供预览）。 */
    plannedTargets: string[];
    /** 注意事项。 */
    notes: string[];
}
/**
 * 生成浏览器可用的 Hook 脚本。
 *
 * 生成物内部刻意只用字符串拼接、不使用模板字符串，这样外层 TypeScript 模板里
 * 不必出现转义地狱，生成的代码也更容易人工审阅。
 *
 * @param options - 生成选项。
 * @returns 脚本与说明。
 */
export declare function generateHookScript(options?: HookOptions): HookScript;
