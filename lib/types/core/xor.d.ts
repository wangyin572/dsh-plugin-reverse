/**
 * 循环异或与单字节爆破。
 *
 * 「自定义循环异或」在前端混淆里极常见，写法五花八门：
 *   - `out[i] = data[i] ^ key[i % key.length]`（字符串/字节密钥）
 *   - 密钥直接是十进制数组，如 `[18, 52, 86]`
 *   - 密钥是 hex 字符串
 * 三种输入都在这里统一支持，并且**始终回显实际参与运算的密钥字节**，
 * 免得使用者对着一段看不出所以然的输出猜自己是不是传错了。
 */
import { type ByteInput, type TextEncoding } from './encoding.js';
/** 循环异或参数。 */
export interface XorParams {
    /** 待处理数据。 */
    data: ByteInput;
    /** `data` 为字符串时的编码，默认 `utf8`。 */
    dataEncoding?: TextEncoding;
    /** 密钥：字符串、字节序列，或十进制字节数组。 */
    key: ByteInput | readonly number[];
    /** 密钥为字符串时的编码，默认 `utf8`。 */
    keyEncoding?: TextEncoding;
    /** 输出编码，默认 `hex`。 */
    outputEncoding?: TextEncoding;
}
/** 循环异或结果。 */
export interface XorResult {
    /** 按请求编码输出的结果。 */
    output: string;
    /** 结果的 hex 形式。 */
    hex: string;
    /** 实际参与运算的密钥字节（十进制）。 */
    keyBytes: number[];
    /** 密钥长度。 */
    keyLength: number;
    /** 输入字节长度。 */
    inputLength: number;
    /** 输出编码。 */
    outputEncoding: TextEncoding;
}
/**
 * 执行循环异或（加解密同一函数，异或自逆）。
 *
 * @param params - 数据与密钥。
 * @returns 结果，含实际使用的密钥字节。
 */
export declare function xorBytes(params: XorParams): XorResult;
/**
 * 已知明文与密文时反推循环异或的密钥。
 *
 * 原理：`key[i] = cipher[i] ^ plain[i]`。若密钥比明文短，结果会呈现周期性——
 * 本函数按最短周期折叠，直接给出候选密钥。
 *
 * @param params - 明文、密文与编码。
 * @returns 反推出的密钥候选。
 */
export declare function xorRecoverKey(params: {
    plaintext: ByteInput;
    plaintextEncoding?: TextEncoding;
    ciphertext: ByteInput;
    ciphertextEncoding?: TextEncoding;
    keyEncoding?: TextEncoding;
}): {
    keyBytes: number[];
    keyHex: string;
    keyUtf8: string;
    period: number;
};
/** 单字节爆破的单个候选。 */
export interface XorCandidate {
    /** 候选密钥字节。 */
    key: number;
    /** 可打印字符形式的密钥。 */
    keyChar: string;
    /** 解密后按 utf8 解码的可读预览。 */
    preview: string;
    /** 可打印字符占比（0-1）。 */
    printableRatio: number;
    /** 综合评分，越高越像自然文本。 */
    score: number;
}
/**
 * 对标量密钥做全 256 值爆破，按可读性排序返回候选。
 *
 * 用于「密钥只有一个字节」或「只知道是单字节异或」的场景，是最快的定位手段。
 *
 * @param params - 密文与筛选参数。
 * @returns 按评分降序的候选列表。
 */
export declare function xorBruteForce(params: {
    data: ByteInput;
    dataEncoding?: TextEncoding;
    /** 返回前 N 个候选，默认 5。 */
    top?: number;
    /** 只保留可打印占比不低于该值的候选，默认 0.85。 */
    minPrintableRatio?: number;
}): XorCandidate[];
