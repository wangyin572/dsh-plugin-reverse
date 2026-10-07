/**
 * AES 加解密。
 *
 * 为什么这个文件比「调一下 createCipheriv」长得多：前端混淆代码里的 AES 几乎都来自
 * CryptoJS，而 CryptoJS 有几个**不成文的默认行为**，不还原它们就会「算法明明对了却
 * 解不出来」：
 *
 *   1. 传字符串口令（passphrase）时走 OpenSSL 的 EVP_BytesToKey 派生子密钥；
 *   2. 派生用的摘要默认是 **MD5**（不是 SHA）；
 *   3. 密文默认带 `"Salted__" + 8 字节随机 salt` 前缀，再整体 base64。
 *
 * 所以这里除了原始 key/iv 模式，还提供 `passphrase` 模式与 `opensslDecrypt`/`opensslEncrypt`
 * 一对函数，用来直接啃线上抓到的 CryptoJS 密文。
 *
 * 参考实现：OpenSSL `EVP_BytesToKey`，与 CryptoJS `EvpKDF` 的默认参数一致。
 */
import { type ByteInput, type TextEncoding } from './encoding.js';
/** 支持的 AES 分组模式。 */
export type AesMode = 'cbc' | 'ecb' | 'ctr' | 'cfb' | 'ofb' | 'gcm';
/** 填充方式。流式模式（ctr/cfb/ofb/gcm）恒为 `none`。 */
export type AesPadding = 'pkcs7' | 'none';
/**
 * EVP_BytesToKey 可用的摘要算法。
 *
 * 比 RSA 的摘要集合少一个 `sha384`：OpenSSL 的 evp 派生只用到这四种，
 * 单独定义类型可以让「传了不支持的摘要」在编译期就被挡住。
 */
export type KdfHash = 'md5' | 'sha1' | 'sha256' | 'sha512';
/** AES 参数。 */
export interface AesParams {
    /** 待处理数据（明文或密文）。 */
    data: ByteInput;
    /** `data` 为字符串时的编码。加密默认 `utf8`，解密默认 `base64`。 */
    dataEncoding?: TextEncoding;
    /** 原始密钥；与 `passphrase` 二选一。 */
    key?: ByteInput;
    /** 密钥为字符串时的编码，默认 `utf8`。 */
    keyEncoding?: TextEncoding;
    /** 初始化向量；cbc/ctr/cfb/ofb/gcm 必填，ecb 必须不填。 */
    iv?: ByteInput;
    /** IV 为字符串时的编码，默认 `utf8`。 */
    ivEncoding?: TextEncoding;
    /** 口令；给了它就走 EVP_BytesToKey 派生 key/iv。 */
    passphrase?: string;
    /** 派生时使用的 salt；缺省时加密会随机生成，解密则必须提供。 */
    salt?: ByteInput;
    /** salt 为字符串时的编码，默认 `utf8`。 */
    saltEncoding?: TextEncoding;
    /** 派生摘要算法，默认 `md5`（CryptoJS 默认）。 */
    kdfHash?: KdfHash;
    /** 派生出的密钥字节长度，默认 32（AES-256）。 */
    keyLength?: 16 | 24 | 32;
    /** 分组模式，默认 `cbc`。 */
    mode?: AesMode;
    /** 填充方式，默认 `pkcs7`；流式模式会被强制为 `none`。 */
    padding?: AesPadding;
    /** GCM 认证标签（解密必填）。 */
    authTag?: ByteInput;
    /** 认证标签为字符串时的编码，默认 `hex`。 */
    authTagEncoding?: TextEncoding;
    /** 输出编码。加密默认 `base64`，解密默认 `utf8`。 */
    outputEncoding?: TextEncoding;
}
/** 加密结果。 */
export interface AesEncryptResult {
    /** 密文（按输出编码）。 */
    ciphertext: string;
    /** 密文 hex（便于比对）。 */
    ciphertextHex: string;
    /** GCM 认证标签（hex）。 */
    authTag?: string;
    /** OpenSSL 格式下实际使用的 salt（hex）。 */
    salt?: string;
    /** 派生出的密钥（hex），仅在使用了 passphrase 时给出。 */
    derivedKey?: string;
    /** 派生出的 IV（hex），仅在使用了 passphrase 时给出。 */
    derivedIv?: string;
    /** 实际使用的 Node 算法名，如 `aes-256-cbc`。 */
    algorithm: string;
    /** 分组模式。 */
    mode: AesMode;
    /** 密钥位数。 */
    keyLength: number;
    /** 实际生效的填充。 */
    padding: AesPadding;
    /** 输出编码。 */
    outputEncoding: TextEncoding;
    /** 明文字节数。 */
    plaintextLength: number;
}
/** 解密结果。 */
export interface AesDecryptResult {
    /** 明文（按输出编码）。 */
    plaintext: string;
    /** 明文 hex。 */
    plaintextHex: string;
    /** 明文 utf8 预览（非法字节会被替换，仅供肉眼参考）。 */
    preview: string;
    /** 实际使用的 Node 算法名。 */
    algorithm: string;
    /** 分组模式。 */
    mode: AesMode;
    /** 密钥位数。 */
    keyLength: number;
    /** 实际生效的填充。 */
    padding: AesPadding;
    /** 明文字节数。 */
    plaintextLength: number;
    /** 输出编码。 */
    outputEncoding: TextEncoding;
}
/**
 * EVP_BytesToKey 密钥派生（OpenSSL 与 CryptoJS 的默认行为）。
 *
 * 算法：反复做 `D_i = HASH(D_{i-1} || passphrase || salt)`，把各轮摘要首尾相接，
 * 前 `keyLength` 字节作密钥，随后 `ivLength` 字节作 IV。使用 MD5 时，
 * 32 字节密钥正好占满两轮摘要。
 *
 * @param passphrase - 口令字节。
 * @param salt - salt 字节（OpenSSL 为 8 字节；无 salt 时传空）。
 * @param keyLength - 需要的密钥字节数。
 * @param ivLength - 需要的 IV 字节数。
 * @param digest - 摘要算法。
 * @returns 派生的密钥与 IV。
 */
export declare function evpBytesToKey(passphrase: Uint8Array, salt: Uint8Array, keyLength: number, ivLength: number, digest?: KdfHash): {
    key: Uint8Array;
    iv: Uint8Array;
};
/**
 * PKCS#7 填充。
 *
 * @param bytes - 原始字节。
 * @param blockSize - 块大小，默认 16。
 * @returns 填充后的字节。
 */
export declare function pkcs7Pad(bytes: Uint8Array, blockSize?: number): Uint8Array;
/**
 * PKCS#7 去填充。填充非法时抛错——这通常意味着密钥或 IV 是错的，
 * 静默返回垃圾数据会让排查方向彻底跑偏。
 *
 * @param bytes - 含填充的字节。
 * @param blockSize - 块大小，默认 16。
 * @returns 去填充后的字节。
 */
export declare function pkcs7Unpad(bytes: Uint8Array, blockSize?: number): Uint8Array;
/**
 * AES 加密。
 *
 * @param params - 加密参数。
 * @returns 密文与诊断信息。
 */
export declare function aesEncrypt(params: AesParams): AesEncryptResult;
/**
 * AES 解密。
 *
 * @param params - 解密参数。
 * @returns 明文与诊断信息。
 */
export declare function aesDecrypt(params: AesParams): AesDecryptResult;
/**
 * 解密 OpenSSL/CryptoJS 风格的 `Salted__` 密文。
 *
 * 这是抓包/抠码后最常见的一块：`CryptoJS.AES.encrypt(plain, '口令').toString()`
 * 的产物就是 base64 的 `Salted__` 格式。
 *
 * @param params - 密文与口令。
 * @returns 解密结果（沿用 {@link aesDecrypt} 的字段）。
 */
export declare function opensslDecrypt(params: {
    data: ByteInput;
    dataEncoding?: TextEncoding;
    passphrase: string;
    kdfHash?: KdfHash;
    keyLength?: 16 | 24 | 32;
    mode?: Extract<AesMode, 'cbc' | 'ecb' | 'ctr'> | AesMode;
    outputEncoding?: TextEncoding;
}): AesDecryptResult;
/**
 * 生成 OpenSSL/CryptoJS 风格的 `Salted__` 密文。
 *
 * 存在的意义是**闭环验证**：能解开线上密文，也能造出同格式密文来确认自己的实现
 * 与目标一致，而不是只靠「看起来像明文」判断。
 *
 * @param params - 明文与口令。
 * @returns 完整的 base64 密文与派生信息。
 */
export declare function opensslEncrypt(params: {
    data: ByteInput;
    dataEncoding?: TextEncoding;
    passphrase: string;
    kdfHash?: KdfHash;
    keyLength?: 16 | 24 | 32;
    mode?: AesMode;
    salt?: Uint8Array;
    outputEncoding?: TextEncoding;
}): AesEncryptResult & {
    blob: string;
};
