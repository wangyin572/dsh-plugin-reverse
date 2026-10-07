/**
 * 插件统一的错误类型。
 *
 * 逆向工具最常见的问题是「输入格式不对却静默算出垃圾结果」——比如把非法 hex 交给
 * Buffer 会被悄悄截断。因此核心层一律用带 `code` 的显式错误，让调用方能区分
 * 「参数不合法」与「算法算不出来」。
 */
/** 错误分类，供工具层转成人类可读的诊断。 */
export type ReverseErrorCode = 'INVALID_ENCODING' | 'INVALID_HEX' | 'INVALID_BASE64' | 'INVALID_INPUT' | 'UNSUPPORTED_ALGORITHM' | 'KEY_MISMATCH' | 'DECRYPT_FAILED' | 'PARSE_FAILED' | 'ANALYSIS_FAILED' | 'NOT_FOUND' | 'BLOCKED';
/** 带分类码的逆向工具错误。 */
export declare class ReverseError extends Error {
    /** 机器可读的分类码。 */
    readonly code: ReverseErrorCode;
    /**
     * @param message - 面向使用者的说明，需包含足以自行修复的细节。
     * @param code - 分类码。
     */
    constructor(message: string, code: ReverseErrorCode);
}
/**
 * 断言条件成立，否则抛出带分类码的 {@link ReverseError}。
 *
 * @param condition - 必须为真的条件。
 * @param message - 失败说明。
 * @param code - 分类码。
 */
export declare function assertReverse(condition: unknown, message: string, code: ReverseErrorCode): asserts condition;
