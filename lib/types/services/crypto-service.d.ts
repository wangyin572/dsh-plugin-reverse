/**
 * 密码学验算服务：把纯计算核心包装成 cordis 服务 `ctx.reverseCrypto`。
 *
 * 分层的理由：
 *   - `src/core/*` 是**纯函数**，不依赖 cordis、不依赖 DSH，可以单独复制出去用；
 *   - 本文件只负责「把模型/工具的扁平参数翻译成对核心的类型化调用」，并在翻译层
 *     做严格的类型校验（模型传进来的东西不可信）。
 *
 * 这样核心的正确性由 `test/core.test.mjs` 保证，服务层只承担参数适配职责。
 */
import { Service } from '@deepseek-ai/cordis';
import type { Context } from '@deepseek-ai/cordis';
/** 支持的操作名。 */
export type CryptoOperation = 'hash' | 'hmac' | 'aes-encrypt' | 'aes-decrypt' | 'openssl-decrypt' | 'openssl-encrypt' | 'xor' | 'xor-brute-force' | 'xor-recover-key' | 'rsa-encrypt' | 'rsa-decrypt' | 'rsa-sign' | 'rsa-verify' | 'rsa-public-from-modulus' | 'rsa-manual-pow' | 'rsa-key-info' | 'mod-pow' | 'mod-inverse' | 'bigint-parse' | 'hex-normalize';
/** 全部操作名，供工具 schema 的枚举使用。 */
export declare const CRYPTO_OPERATIONS: readonly CryptoOperation[];
/** 统一的返回结构。 */
export interface CryptoResponse {
    /** 实际执行的操作。 */
    operation: CryptoOperation;
    /** 一句话结论，便于模型直接引用。 */
    summary: string;
    /** 结果键值对（扁平，值均为 JSON 可表示）。 */
    result: Record<string, string | number | boolean | number[] | string[]>;
    /** 诊断与注意事项。 */
    notes: string[];
}
/** 原始请求：由工具层从模型参数构造，键值均为不可信输入。 */
export type CryptoRequest = Record<string, unknown> & {
    operation: string;
};
/** 密码学验算服务。 */
export declare class ReverseCryptoService extends Service {
    /**
     * @param ctx - 宿主上下文。
     */
    constructor(ctx: Context);
    /**
     * 执行一次验算。
     *
     * @param request - 原始请求（含 `operation`）。
     * @returns 结构化结果。
     */
    calculate(request: CryptoRequest): CryptoResponse;
    /**
     * 哈希。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    private runHash;
    /**
     * HMAC。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    private runHmac;
    /**
     * AES 加解密。
     *
     * @param request - 请求。
     * @param direction - 加密或解密。
     * @returns 结果。
     */
    private runAes;
    /**
     * OpenSSL / CryptoJS 的 `Salted__` 格式。
     *
     * @param request - 请求。
     * @param direction - 方向。
     * @returns 结果。
     */
    private runOpenssl;
    /**
     * 循环异或。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    private runXor;
    /**
     * 单字节爆破。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    private runXorBruteForce;
    /**
     * 由明文与密文反推异或密钥。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    private runXorRecoverKey;
    /**
     * RSA 加解密（标准库路径）。
     *
     * @param request - 请求。
     * @param direction - 方向。
     * @returns 结果。
     */
    private runRsaCipher;
    /**
     * RSA 签名。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    private runRsaSign;
    /**
     * RSA 验签。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    private runRsaVerify;
    /**
     * 由 n/e 还原公钥。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    private runRsaFromModulus;
    /**
     * 手写大数模幂（自定义 RSA）。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    private runRsaManual;
    /**
     * 读取密钥信息。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    private runRsaKeyInfo;
    /**
     * 模幂。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    private runModPow;
    /**
     * 模反元素。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    private runModInverse;
    /**
     * 解析大整数字面量。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    private runBigIntParse;
    /**
     * 归一化 hex（去掉分隔符）并给出字节视图。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    private runHexNormalize;
}
declare module '@deepseek-ai/cordis' {
    interface Context {
        /** 密码学验算服务。 */
        reverseCrypto: ReverseCryptoService;
    }
}
