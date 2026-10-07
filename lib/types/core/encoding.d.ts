/**
 * 字节/文本互转。所有逆向验算的输入输出都从这里过一道，保证编码解释是显式的。
 *
 * 设计原则：**不做魔法推断**。同一个字符串按 hex 和按 utf8 解释会得到完全不同的
 * 结果，静默猜测只会让人拿到错误答案还以为算对了。因此每个字符串参数都必须带
 * `encoding`，默认值也在类型与文档里写明。
 */
/** 支持的文本编码。 */
export type TextEncoding = 'utf8' | 'hex' | 'base64' | 'base64url' | 'latin1';
/** 可被当作字节序列接受的输入。 */
export type ByteInput = string | Uint8Array;
/**
 * 校验编码名合法。
 *
 * @param encoding - 待校验的编码名。
 * @returns 同一个编码名。
 */
export declare function assertEncoding(encoding: string): TextEncoding;
/**
 * 去掉 hex 里的人为分隔符。
 *
 * 真实逆向里密钥常被写成 `12:34:56`、`12-34-56` 或带空格换行的形式，先归一化
 * 再严格校验，可以避免「粘贴过来就报格式错」的摩擦。
 *
 * @param input - 原始 hex 文本。
 * @returns 仅含 hex 字符的文本。
 */
export declare function normalizeHex(input: string): string;
/**
 * 严格解析 hex 文本。非法字符或奇数长度都会抛错，而不是被静默截断。
 *
 * @param input - hex 文本（允许空格/冒号/连字符分隔）。
 * @returns 解析出的字节。
 */
export declare function decodeHex(input: string): Uint8Array;
/**
 * 把字节编码为 hex 文本。
 *
 * @param bytes - 输入字节。
 * @returns 小写 hex 文本。
 */
export declare function encodeHex(bytes: Uint8Array): string;
/**
 * 解析 base64（同时接受 base64url 的 `-`/`_` 与缺失填充）。
 *
 * @param input - base64 文本。
 * @returns 解析出的字节。
 */
export declare function decodeBase64(input: string): Uint8Array;
/**
 * 把字节编码为 base64 文本。
 *
 * @param bytes - 输入字节。
 * @returns 标准 base64（带 `=` 填充）。
 */
export declare function encodeBase64(bytes: Uint8Array): string;
/**
 * 把字节编码为 base64url 文本（无填充）。
 *
 * @param bytes - 输入字节。
 * @returns base64url 文本。
 */
export declare function encodeBase64Url(bytes: Uint8Array): string;
/**
 * 把字节按指定编码转成文本。
 *
 * @param bytes - 输入字节。
 * @param encoding - 目标编码。
 * @returns 编码后的文本。
 */
export declare function fromBytes(bytes: Uint8Array, encoding: TextEncoding): string;
/**
 * 把文本按指定编码解析为字节。
 *
 * @param input - 文本输入。
 * @param encoding - 输入编码。
 * @returns 解析出的字节。
 */
export declare function toBytes(input: string, encoding: TextEncoding): Uint8Array;
/**
 * 把任意 {@link ByteInput} 归一化为字节。
 *
 * @param input - 字符串或字节。
 * @param encoding - 当输入是字符串时使用的编码。
 * @returns 字节序列。
 */
export declare function asBytes(input: ByteInput, encoding: TextEncoding): Uint8Array;
/**
 * 按指定编码输出字节。
 *
 * @param bytes - 字节序列。
 * @param encoding - 目标编码。
 * @returns 编码后的文本。
 */
export declare function outText(bytes: Uint8Array, encoding: TextEncoding): string;
/**
 * 截断过长文本，避免错误信息被巨型密文刷屏。
 *
 * @param text - 原始文本。
 * @param max - 最大保留长度。
 * @returns 可能带省略号的文本。
 */
export declare function truncate(text: string, max?: number): string;
/**
 * 把字节序列转换为纯数组，供 JSON 输出使用。
 *
 * @param bytes - 字节序列。
 * @returns 0-255 的普通数组。
 */
export declare function toPlainArray(bytes: Uint8Array): number[];
/**
 * 校验输入非空。
 *
 * @param bytes - 字节序列。
 * @param what - 字段名，用于错误信息。
 */
export declare function assertNonEmpty(bytes: Uint8Array, what: string): void;
