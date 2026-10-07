/**
 * RSA 验算。
 *
 * 覆盖两类真实场景：
 *
 *   A. **标准库路径**——`JSEncrypt`、`crypto.publicEncrypt` 等，密钥是 PEM/DER。
 *      走 Node 的 `publicEncrypt`/`privateDecrypt`/`sign`/`verify`。
 *
 *   B. **手写大数路径**——混淆代码里非常常见：把 RSA 拆成
 *      `m = c^d mod n` 这样的模幂运算，用 BigInt 或大数库自己算，没有 PEM。
 *      这类没有标准 API 可用，所以这里直接提供 {@link rsaManualPow} 与
 *      {@link modPow}，按字节/大整数输入输出。
 *
 * 另外提供 {@link rsaPublicKeyFromComponents}：线上 JS 常把公钥写成
 * `{ n: '0x...', e: '0x10001' }`，需要还原成 PEM 才能交给标准库。
 *
 * 明确不支持（会在结果里说明原因，而不是假装成功）：
 *   - 只给 `(n, e, d)` 而没有 CRT 参数时**无法**构造 PEM 私钥（数学上需要 p、q）。
 *     这种情况请用 {@link rsaManualPow} 直接做模幂。
 */
import { type ByteInput, type TextEncoding } from './encoding.js';
/** 支持的填充方式。 */
export type RsaPadding = 'pkcs1' | 'oaep' | 'none';
/** 支持与 RSA 搭配的摘要算法。 */
export type RsaHash = 'md5' | 'sha1' | 'sha256' | 'sha384' | 'sha512';
/** 密钥编码格式。 */
export type KeyFormat = 'pem' | 'der';
/**
 * 把字节序列转成大整数。
 *
 * @param bytes - 大端字节序。
 * @returns 对应的大整数。
 */
export declare function bytesToBigInt(bytes: Uint8Array): bigint;
/**
 * 把大整数转成大端字节序列。
 *
 * @param value - 非负整数。
 * @param minLength - 补齐到的最小字节数（RSA 需要固定块长）。
 * @returns 大端字节。
 */
export declare function bigIntToBytes(value: bigint, minLength?: number): Uint8Array;
/**
 * 模幂运算 `base^exponent mod modulus`。
 *
 * 用 BigInt 的快速幂实现，是手写 RSA / DH / 自定义签名算法的通用底座。
 *
 * @param base - 底数。
 * @param exponent - 指数。
 * @param modulus - 模数。
 * @returns 模幂结果。
 */
export declare function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint;
/**
 * 模反元素（扩展欧几里得），用于从 (e, φ) 求 d。
 *
 * @param a - 被求逆的数。
 * @param modulus - 模数。
 * @returns `a` 的模逆。
 */
export declare function modInverse(a: bigint, modulus: bigint): bigint;
/** RSA 加解密结果。 */
export interface RsaCipherResult {
    /** 结果（按输出编码）。 */
    data: string;
    /** 结果 hex。 */
    dataHex: string;
    /** 结果字节数。 */
    length: number;
    /** 填充方式。 */
    padding: RsaPadding;
    /** 输出编码。 */
    outputEncoding: TextEncoding;
}
/**
 * 公钥加密。
 *
 * @param params - 数据、公钥与填充。
 * @returns 密文结果。
 */
export declare function rsaEncrypt(params: {
    data: ByteInput;
    dataEncoding?: TextEncoding;
    publicKey: ByteInput;
    keyFormat?: KeyFormat;
    padding?: RsaPadding;
    oaepHash?: RsaHash;
    outputEncoding?: TextEncoding;
}): RsaCipherResult;
/**
 * 私钥解密。
 *
 * @param params - 密文、私钥与填充。
 * @returns 明文结果。
 */
export declare function rsaDecrypt(params: {
    data: ByteInput;
    dataEncoding?: TextEncoding;
    privateKey: ByteInput;
    keyFormat?: KeyFormat;
    padding?: RsaPadding;
    oaepHash?: RsaHash;
    outputEncoding?: TextEncoding;
}): RsaCipherResult;
/**
 * 私钥签名。
 *
 * @param params - 数据、私钥与摘要算法。
 * @returns 签名结果。
 */
export declare function rsaSign(params: {
    data: ByteInput;
    dataEncoding?: TextEncoding;
    privateKey: ByteInput;
    keyFormat?: KeyFormat;
    hash?: RsaHash;
    outputEncoding?: TextEncoding;
}): RsaCipherResult;
/**
 * 公钥验签。
 *
 * @param params - 数据、签名与公钥。
 * @returns 是否验证通过。
 */
export declare function rsaVerify(params: {
    data: ByteInput;
    dataEncoding?: TextEncoding;
    signature: ByteInput;
    signatureEncoding?: TextEncoding;
    publicKey: ByteInput;
    keyFormat?: KeyFormat;
    hash?: RsaHash;
}): {
    valid: boolean;
    algorithm: string;
};
/**
 * 由模数 n 与指数 e 还原公钥 PEM。
 *
 * @param params - n、e 与它们的编码。
 * @returns PEM 文本与密钥信息。
 */
export declare function rsaPublicKeyFromComponents(params: {
    n: string;
    e: string;
    inputEncoding: TextEncoding;
}): {
    pem: string;
    bits: number;
    modulusHex: string;
};
/** 密钥信息。 */
export interface RsaKeyInfo {
    /** 公钥还是私钥。 */
    kind: 'public' | 'private';
    /** 密钥位数。 */
    bits: number;
    /** 模数（hex），仅在可取到时给出。 */
    modulusHex?: string;
    /** 公开指数（hex）。 */
    exponentHex?: string;
}
/**
 * 读取密钥的基本信息（位数、模数、指数）。
 *
 * @param params - 密钥与格式。
 * @returns 密钥信息。
 */
export declare function rsaKeyInfo(params: {
    key: ByteInput;
    keyFormat?: KeyFormat;
    kind?: 'public' | 'private';
}): RsaKeyInfo;
/** 手写大数 RSA 的模幂参数。 */
export interface ManualRsaParams {
    /** 输入值：明文 m（加密）或密文 c（解密）。 */
    value: string;
    /** `value` 的编码。 */
    inputEncoding: TextEncoding;
    /** 指数：公钥用 e，私钥用 d。 */
    exponent: string;
    /** 指数编码。 */
    exponentEncoding: TextEncoding;
    /** 模数 n。 */
    modulus: string;
    /** 模数编码。 */
    modulusEncoding: TextEncoding;
    /** 输出大整数的编码，默认 `hex`。 */
    outputEncoding?: TextEncoding;
    /** 输出补齐到的字节数（RSA 结果常需定长），默认按模数长度。 */
    padTo?: number;
}
/**
 * 手写大数 RSA：直接做 `value^exponent mod modulus`。
 *
 * 这是应对「混淆代码自己实现 RSA」的主力函数：不需要 PEM，不需要标准库，
 * 只要能从代码里读出 n、e（或 d）就能算出结果。
 *
 * @param params - 模幂参数。
 * @returns 结果与中间量。
 */
export declare function rsaManualPow(params: ManualRsaParams): {
    resultHex: string;
    result: string;
    resultDecimal: string;
    bits: number;
    outputEncoding: TextEncoding;
};
/**
 * 把大整数以十进制/hex 文本解析出来，供调试输出使用。
 *
 * @param text - 十进制或 `0x` 前缀 hex 文本。
 * @returns 大整数、字节与 hex 表示。
 */
export declare function parseBigIntLiteral(text: string): {
    value: bigint;
    hex: string;
    bytes: number[];
};
