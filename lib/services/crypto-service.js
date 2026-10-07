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
import { ReverseError } from '../core/errors.js';
import { asBytes, encodeHex, normalizeHex, toPlainArray, } from '../core/encoding.js';
import { hash, hmac } from '../core/hash.js';
import { aesDecrypt, aesEncrypt, opensslDecrypt, opensslEncrypt, } from '../core/aes.js';
import { bigIntToBytes, bytesToBigInt, modInverse, modPow, parseBigIntLiteral, rsaDecrypt, rsaEncrypt, rsaKeyInfo, rsaManualPow, rsaPublicKeyFromComponents, rsaSign, rsaVerify, } from '../core/rsa.js';
import { xorBruteForce, xorBytes, xorRecoverKey } from '../core/xor.js';
/** 全部操作名，供工具 schema 的枚举使用。 */
export const CRYPTO_OPERATIONS = [
    'hash',
    'hmac',
    'aes-encrypt',
    'aes-decrypt',
    'openssl-decrypt',
    'openssl-encrypt',
    'xor',
    'xor-brute-force',
    'xor-recover-key',
    'rsa-encrypt',
    'rsa-decrypt',
    'rsa-sign',
    'rsa-verify',
    'rsa-public-from-modulus',
    'rsa-manual-pow',
    'rsa-key-info',
    'mod-pow',
    'mod-inverse',
    'bigint-parse',
    'hex-normalize',
];
/**
 * 读取字符串参数。
 *
 * @param input - 原始请求。
 * @param key - 参数名。
 * @param required - 是否必填。
 * @returns 字符串或 undefined。
 */
function readString(input, key, required = false) {
    const value = input[key];
    if (value === undefined || value === null || value === '') {
        if (required)
            throw new ReverseError(`缺少必填参数 ${key}`, 'INVALID_INPUT');
        return undefined;
    }
    if (typeof value === 'string')
        return value;
    if (typeof value === 'number' || typeof value === 'boolean')
        return String(value);
    throw new ReverseError(`参数 ${key} 应为字符串，实际收到 ${typeof value}`, 'INVALID_INPUT');
}
/**
 * 读取数字参数。
 *
 * @param input - 原始请求。
 * @param key - 参数名。
 * @param required - 是否必填。
 * @returns 数字或 undefined。
 */
function readNumber(input, key, required = false) {
    const value = input[key];
    if (value === undefined || value === null) {
        if (required)
            throw new ReverseError(`缺少必填参数 ${key}`, 'INVALID_INPUT');
        return undefined;
    }
    if (typeof value === 'number' && Number.isFinite(value))
        return value;
    if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) {
        return Number(value);
    }
    throw new ReverseError(`参数 ${key} 应为数字，实际收到 ${JSON.stringify(value)}`, 'INVALID_INPUT');
}
/**
 * 读取布尔参数。
 *
 * @param input - 原始请求。
 * @param key - 参数名。
 * @param fallback - 缺省值。
 * @returns 布尔值。
 */
function readBoolean(input, key, fallback) {
    const value = input[key];
    if (value === undefined || value === null)
        return fallback;
    if (typeof value === 'boolean')
        return value;
    if (value === 'true')
        return true;
    if (value === 'false')
        return false;
    throw new ReverseError(`参数 ${key} 应为布尔值`, 'INVALID_INPUT');
}
/**
 * 读取编码参数并校验。
 *
 * @param input - 原始请求。
 * @param key - 参数名。
 * @param fallback - 缺省编码。
 * @returns 编码名。
 */
function readEncoding(input, key, fallback) {
    const value = readString(input, key);
    return (value ?? fallback);
}
/**
 * 读取密钥：支持字符串，也支持十进制字节数组（混淆代码里常见 `[18,52,86]`）。
 *
 * @param input - 原始请求。
 * @param key - 参数名。
 * @returns 密钥输入。
 */
function readKeyLike(input, key) {
    const value = input[key];
    if (value === undefined || value === null || value === '')
        return undefined;
    if (typeof value === 'string')
        return value;
    if (typeof value === 'number')
        return String(value);
    if (Array.isArray(value)) {
        return value.map((item, index) => {
            const parsed = typeof item === 'number' ? item : Number(item);
            if (!Number.isInteger(parsed) || parsed < 0 || parsed > 255) {
                throw new ReverseError(`参数 ${key} 第 ${index} 项不是合法字节：${String(item)}`, 'INVALID_INPUT');
            }
            return parsed;
        });
    }
    throw new ReverseError(`参数 ${key} 应为字符串或字节数组`, 'INVALID_INPUT');
}
/**
 * 读取分组模式。
 *
 * @param input - 原始请求。
 * @param fallback - 缺省模式。
 * @returns 模式名。
 */
function readMode(input, fallback) {
    return (readString(input, 'mode') ?? fallback);
}
/** 密码学验算服务。 */
export class ReverseCryptoService extends Service {
    /**
     * @param ctx - 宿主上下文。
     */
    constructor(ctx) {
        super(ctx, 'reverseCrypto');
    }
    /**
     * 执行一次验算。
     *
     * @param request - 原始请求（含 `operation`）。
     * @returns 结构化结果。
     */
    calculate(request) {
        const operation = readString(request, 'operation', true);
        switch (operation) {
            case 'hash':
                return this.runHash(request);
            case 'hmac':
                return this.runHmac(request);
            case 'aes-encrypt':
                return this.runAes(request, 'encrypt');
            case 'aes-decrypt':
                return this.runAes(request, 'decrypt');
            case 'openssl-decrypt':
                return this.runOpenssl(request, 'decrypt');
            case 'openssl-encrypt':
                return this.runOpenssl(request, 'encrypt');
            case 'xor':
                return this.runXor(request);
            case 'xor-brute-force':
                return this.runXorBruteForce(request);
            case 'xor-recover-key':
                return this.runXorRecoverKey(request);
            case 'rsa-encrypt':
            case 'rsa-decrypt':
                return this.runRsaCipher(request, operation === 'rsa-encrypt' ? 'encrypt' : 'decrypt');
            case 'rsa-sign':
                return this.runRsaSign(request);
            case 'rsa-verify':
                return this.runRsaVerify(request);
            case 'rsa-public-from-modulus':
                return this.runRsaFromModulus(request);
            case 'rsa-manual-pow':
                return this.runRsaManual(request);
            case 'rsa-key-info':
                return this.runRsaKeyInfo(request);
            case 'mod-pow':
                return this.runModPow(request);
            case 'mod-inverse':
                return this.runModInverse(request);
            case 'bigint-parse':
                return this.runBigIntParse(request);
            case 'hex-normalize':
                return this.runHexNormalize(request);
            default:
                throw new ReverseError(`不支持的操作 "${String(operation)}"。可用操作：${CRYPTO_OPERATIONS.join(' / ')}`, 'UNSUPPORTED_ALGORITHM');
        }
    }
    /**
     * 哈希。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    runHash(request) {
        const algorithm = readString(request, 'algorithm', true) ?? 'sha256';
        const data = readString(request, 'data', true) ?? '';
        const result = hash(algorithm, {
            data,
            dataEncoding: readEncoding(request, 'dataEncoding', 'utf8'),
            outputEncoding: readEncoding(request, 'outputEncoding', 'hex'),
        });
        return {
            operation: 'hash',
            summary: `${result.algorithm} 摘要（${result.length} 字节）已算出`,
            result: { algorithm: result.algorithm, digest: result.digest, hex: result.hex, length: result.length },
            notes: ['hex 字段始终给出，便于与你手头的已知值直接对照'],
        };
    }
    /**
     * HMAC。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    runHmac(request) {
        const algorithm = readString(request, 'algorithm', true) ?? 'sha256';
        const data = readString(request, 'data', true) ?? '';
        const key = readString(request, 'key', true) ?? '';
        const result = hmac(algorithm, {
            data,
            dataEncoding: readEncoding(request, 'dataEncoding', 'utf8'),
            key,
            keyEncoding: readEncoding(request, 'keyEncoding', 'utf8'),
            outputEncoding: readEncoding(request, 'outputEncoding', 'hex'),
        });
        return {
            operation: 'hmac',
            summary: `${result.algorithm} 已算出`,
            result: { algorithm: result.algorithm, digest: result.digest, hex: result.hex, length: result.length },
            notes: [],
        };
    }
    /**
     * AES 加解密。
     *
     * @param request - 请求。
     * @param direction - 加密或解密。
     * @returns 结果。
     */
    runAes(request, direction) {
        const mode = readMode(request, 'cbc');
        const padding = (readString(request, 'padding') ?? 'pkcs7');
        const passphrase = readString(request, 'passphrase');
        const key = readKeyLike(request, 'key');
        const iv = readString(request, 'iv');
        const salt = readString(request, 'salt');
        if (direction === 'encrypt') {
            const result = aesEncrypt({
                data: readString(request, 'data', true) ?? '',
                dataEncoding: readEncoding(request, 'dataEncoding', 'utf8'),
                key: key,
                keyEncoding: readEncoding(request, 'keyEncoding', 'utf8'),
                iv,
                ivEncoding: readEncoding(request, 'ivEncoding', 'utf8'),
                passphrase,
                salt,
                saltEncoding: readEncoding(request, 'saltEncoding', 'hex'),
                kdfHash: readString(request, 'kdfHash'),
                keyLength: readNumber(request, 'keyLength'),
                mode,
                padding,
                outputEncoding: readEncoding(request, 'outputEncoding', 'base64'),
            });
            const notes = [`算法 ${result.algorithm}，填充 ${result.padding}`];
            if (result.derivedKey)
                notes.push('使用了口令派生（EVP_BytesToKey），已回显派生出的 key/iv');
            if (mode === 'gcm')
                notes.push('GCM 模式：解密时必须同时提供返回的 authTag');
            return {
                operation: 'aes-encrypt',
                summary: `AES 加密完成（${result.algorithm}）`,
                result: {
                    ciphertext: result.ciphertext,
                    ciphertextHex: result.ciphertextHex,
                    ...(result.authTag ? { authTag: result.authTag } : {}),
                    ...(result.derivedKey ? { derivedKey: result.derivedKey } : {}),
                    ...(result.derivedIv ? { derivedIv: result.derivedIv } : {}),
                    algorithm: result.algorithm,
                },
                notes,
            };
        }
        const result = aesDecrypt({
            data: readString(request, 'data', true) ?? '',
            dataEncoding: readEncoding(request, 'dataEncoding', 'base64'),
            key: key,
            keyEncoding: readEncoding(request, 'keyEncoding', 'utf8'),
            iv,
            ivEncoding: readEncoding(request, 'ivEncoding', 'utf8'),
            passphrase,
            salt,
            saltEncoding: readEncoding(request, 'saltEncoding', 'hex'),
            kdfHash: readString(request, 'kdfHash'),
            keyLength: readNumber(request, 'keyLength'),
            mode,
            padding,
            authTag: readString(request, 'authTag'),
            authTagEncoding: readEncoding(request, 'authTagEncoding', 'hex'),
            outputEncoding: readEncoding(request, 'outputEncoding', 'utf8'),
        });
        return {
            operation: 'aes-decrypt',
            summary: `AES 解密成功，得到 ${result.plaintextLength} 字节明文`,
            result: {
                plaintext: result.plaintext,
                plaintextHex: result.plaintextHex,
                preview: result.preview,
                algorithm: result.algorithm,
                plaintextLength: result.plaintextLength,
            },
            notes: [`算法 ${result.algorithm}，填充 ${result.padding}`],
        };
    }
    /**
     * OpenSSL / CryptoJS 的 `Salted__` 格式。
     *
     * @param request - 请求。
     * @param direction - 方向。
     * @returns 结果。
     */
    runOpenssl(request, direction) {
        const passphrase = readString(request, 'passphrase', true) ?? '';
        const kdfHash = (readString(request, 'kdfHash') ?? 'md5');
        const keyLength = (readNumber(request, 'keyLength') ?? 32);
        const mode = readMode(request, 'cbc');
        if (direction === 'encrypt') {
            const result = opensslEncrypt({
                data: readString(request, 'data', true) ?? '',
                dataEncoding: readEncoding(request, 'dataEncoding', 'utf8'),
                passphrase,
                kdfHash,
                keyLength,
                mode,
                salt: readString(request, 'salt')
                    ? asBytes(readString(request, 'salt') ?? '', 'hex')
                    : undefined,
                outputEncoding: readEncoding(request, 'outputEncoding', 'base64'),
            });
            return {
                operation: 'openssl-encrypt',
                summary: '生成 OpenSSL/CryptoJS 风格的 Salted__ 密文',
                result: { blob: result.blob, ciphertextHex: result.ciphertextHex, salt: result.salt ?? '' },
                notes: ['这是闭环验证手段：能造出同格式密文，才能确认自己的实现与目标一致'],
            };
        }
        const result = opensslDecrypt({
            data: readString(request, 'data', true) ?? '',
            dataEncoding: readEncoding(request, 'dataEncoding', 'base64'),
            passphrase,
            kdfHash,
            keyLength,
            mode,
            outputEncoding: readEncoding(request, 'outputEncoding', 'utf8'),
        });
        return {
            operation: 'openssl-decrypt',
            summary: `Salted__ 密文解密成功，得到 ${result.plaintextLength} 字节明文`,
            result: {
                plaintext: result.plaintext,
                plaintextHex: result.plaintextHex,
                algorithm: result.algorithm,
                plaintextLength: result.plaintextLength,
            },
            notes: [
                `使用 ${kdfHash.toUpperCase()} 派生、${keyLength * 8} 位密钥、${result.mode.toUpperCase()} 模式`,
                '若解不出正确明文，多半是 kdfHash 或 keyLength 与目标不一致（CryptoJS 默认 md5 / 256 位）',
            ],
        };
    }
    /**
     * 循环异或。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    runXor(request) {
        const key = readKeyLike(request, 'key') ?? (() => {
            throw new ReverseError('异或需要 key（字符串 / hex / 十进制字节数组）', 'INVALID_INPUT');
        })();
        const result = xorBytes({
            data: readString(request, 'data', true) ?? '',
            dataEncoding: readEncoding(request, 'dataEncoding', 'utf8'),
            key,
            keyEncoding: readEncoding(request, 'keyEncoding', 'utf8'),
            outputEncoding: readEncoding(request, 'outputEncoding', 'hex'),
        });
        return {
            operation: 'xor',
            summary: `循环异或完成（密钥 ${result.keyLength} 字节，输入 ${result.inputLength} 字节）`,
            result: {
                output: result.output,
                hex: result.hex,
                keyBytes: result.keyBytes,
                keyLength: result.keyLength,
            },
            notes: ['异或自逆：把 output 当输入、同一密钥再算一次即可还原'],
        };
    }
    /**
     * 单字节爆破。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    runXorBruteForce(request) {
        const candidates = xorBruteForce({
            data: readString(request, 'data', true) ?? '',
            dataEncoding: readEncoding(request, 'dataEncoding', 'hex'),
            top: readNumber(request, 'top') ?? 5,
            minPrintableRatio: readNumber(request, 'minPrintableRatio') ?? 0.85,
        });
        return {
            operation: 'xor-brute-force',
            summary: `找到 ${candidates.length} 个候选单字节密钥，最佳为 0x${(candidates[0]?.key ?? 0).toString(16).padStart(2, '0')}`,
            result: {
                bestKey: candidates[0]?.key ?? 0,
                bestPreview: candidates[0]?.preview ?? '',
                keys: candidates.map((item) => `0x${item.key.toString(16).padStart(2, '0')} (${item.keyChar || '·'})`),
                previews: candidates.map((item) => item.preview),
            },
            notes: ['按可打印字符占比与字符频率排序；预览里 · 代表控制字符'],
        };
    }
    /**
     * 由明文与密文反推异或密钥。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    runXorRecoverKey(request) {
        const result = xorRecoverKey({
            plaintext: readString(request, 'plaintext', true) ?? '',
            plaintextEncoding: readEncoding(request, 'plaintextEncoding', 'utf8'),
            ciphertext: readString(request, 'ciphertext', true) ?? '',
            ciphertextEncoding: readEncoding(request, 'ciphertextEncoding', 'hex'),
        });
        return {
            operation: 'xor-recover-key',
            summary: `反推出密钥（最短周期 ${result.period} 字节）`,
            result: {
                keyBytes: result.keyBytes,
                keyHex: result.keyHex,
                keyUtf8: result.keyUtf8,
                period: result.period,
            },
            notes: ['已按最短周期折叠：若周期远小于明文长度，说明密钥确实很短'],
        };
    }
    /**
     * RSA 加解密（标准库路径）。
     *
     * @param request - 请求。
     * @param direction - 方向。
     * @returns 结果。
     */
    runRsaCipher(request, direction) {
        const padding = (readString(request, 'padding') ?? 'pkcs1');
        const oaepHash = readString(request, 'oaepHash');
        if (direction === 'encrypt') {
            const result = rsaEncrypt({
                data: readString(request, 'data', true) ?? '',
                dataEncoding: readEncoding(request, 'dataEncoding', 'utf8'),
                publicKey: readString(request, 'publicKey', true) ?? '',
                padding,
                oaepHash,
                outputEncoding: readEncoding(request, 'outputEncoding', 'base64'),
            });
            return {
                operation: 'rsa-encrypt',
                summary: `RSA 加密完成（${result.length} 字节）`,
                result: { data: result.data, dataHex: result.dataHex, length: result.length, padding: result.padding },
                notes: ['PKCS#1 v1.5 的明文上限为「密钥字节数 - 11」'],
            };
        }
        const result = rsaDecrypt({
            data: readString(request, 'data', true) ?? '',
            dataEncoding: readEncoding(request, 'dataEncoding', 'base64'),
            privateKey: readString(request, 'privateKey', true) ?? '',
            padding,
            oaepHash,
            outputEncoding: readEncoding(request, 'outputEncoding', 'utf8'),
        });
        return {
            operation: 'rsa-decrypt',
            summary: `RSA 解密成功，得到 ${result.length} 字节明文`,
            result: { data: result.data, dataHex: result.dataHex, length: result.length, padding: result.padding },
            notes: [],
        };
    }
    /**
     * RSA 签名。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    runRsaSign(request) {
        const result = rsaSign({
            data: readString(request, 'data', true) ?? '',
            dataEncoding: readEncoding(request, 'dataEncoding', 'utf8'),
            privateKey: readString(request, 'privateKey', true) ?? '',
            hash: readString(request, 'hash'),
            outputEncoding: readEncoding(request, 'outputEncoding', 'base64'),
        });
        return {
            operation: 'rsa-sign',
            summary: `RSA 签名完成（${result.length} 字节）`,
            result: { signature: result.data, signatureHex: result.dataHex, length: result.length },
            notes: ['默认摘要 sha256；OpenSSL 3 默认禁用了 MD5 签名'],
        };
    }
    /**
     * RSA 验签。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    runRsaVerify(request) {
        const result = rsaVerify({
            data: readString(request, 'data', true) ?? '',
            dataEncoding: readEncoding(request, 'dataEncoding', 'utf8'),
            signature: readString(request, 'signature', true) ?? '',
            signatureEncoding: readEncoding(request, 'signatureEncoding', 'base64'),
            publicKey: readString(request, 'publicKey', true) ?? '',
            hash: readString(request, 'hash'),
        });
        return {
            operation: 'rsa-verify',
            summary: result.valid ? '验签通过' : '验签失败',
            result: { valid: result.valid, algorithm: result.algorithm },
            notes: result.valid ? [] : ['验签失败通常意味着：公钥不对、摘要算法不对、或签名编码解释错误'],
        };
    }
    /**
     * 由 n/e 还原公钥。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    runRsaFromModulus(request) {
        const result = rsaPublicKeyFromComponents({
            n: readString(request, 'n', true) ?? '',
            e: readString(request, 'e', true) ?? '',
            inputEncoding: readEncoding(request, 'inputEncoding', 'hex'),
        });
        return {
            operation: 'rsa-public-from-modulus',
            summary: `已还原公钥（${result.bits} 位）`,
            result: { pem: result.pem, bits: result.bits, modulusHex: result.modulusHex },
            notes: ['n 常带前导 00，这是大整数的符号位保留字节，不影响数值'],
        };
    }
    /**
     * 手写大数模幂（自定义 RSA）。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    runRsaManual(request) {
        const result = rsaManualPow({
            value: readString(request, 'value', true) ?? '',
            inputEncoding: readEncoding(request, 'inputEncoding', 'hex'),
            exponent: readString(request, 'exponent', true) ?? '',
            exponentEncoding: readEncoding(request, 'exponentEncoding', 'hex'),
            modulus: readString(request, 'modulus', true) ?? '',
            modulusEncoding: readEncoding(request, 'modulusEncoding', 'hex'),
            outputEncoding: readEncoding(request, 'outputEncoding', 'hex'),
            padTo: readNumber(request, 'padTo'),
        });
        return {
            operation: 'rsa-manual-pow',
            summary: `模幂完成（模数 ${result.bits} 位）`,
            result: {
                result: result.result,
                resultHex: result.resultHex,
                resultDecimal: result.resultDecimal,
                bits: result.bits,
            },
            notes: ['解密后的大整数字节常含前导 0x00 填充，转字符串前需要去掉'],
        };
    }
    /**
     * 读取密钥信息。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    runRsaKeyInfo(request) {
        const result = rsaKeyInfo({
            key: readString(request, 'key', true) ?? '',
            kind: readString(request, 'kind') === 'private' ? 'private' : 'public',
        });
        return {
            operation: 'rsa-key-info',
            summary: `${result.kind === 'public' ? '公钥' : '私钥'}，${result.bits} 位`,
            result: {
                kind: result.kind,
                bits: result.bits,
                modulusHex: result.modulusHex ?? '',
                exponentHex: result.exponentHex ?? '',
            },
            notes: ['exponentHex = 010001 即最常见的 65537'],
        };
    }
    /**
     * 模幂。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    runModPow(request) {
        const base = parseBigIntLiteral(readString(request, 'base', true) ?? '');
        const exponent = parseBigIntLiteral(readString(request, 'exponent', true) ?? '');
        const modulus = parseBigIntLiteral(readString(request, 'modulus', true) ?? '');
        const value = modPow(base.value, exponent.value, modulus.value);
        return {
            operation: 'mod-pow',
            summary: '模幂完成',
            result: {
                resultDecimal: value.toString(10),
                resultHex: parseBigIntLiteral(value.toString(10)).hex,
                bits: modulus.value.toString(2).length,
            },
            notes: ['输入支持十进制、0x 前缀 hex、或裸 hex'],
        };
    }
    /**
     * 模反元素。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    runModInverse(request) {
        const a = parseBigIntLiteral(readString(request, 'a', true) ?? '');
        const modulus = parseBigIntLiteral(readString(request, 'modulus', true) ?? '');
        const value = modInverse(a.value, modulus.value);
        return {
            operation: 'mod-inverse',
            summary: '模反元素已算出',
            result: { resultDecimal: value.toString(10), resultHex: bigIntToBytes(value).length > 0 ? encodeHex(bigIntToBytes(value)) : '' },
            notes: ['常用于由 e 与 φ(n) 反推 d'],
        };
    }
    /**
     * 解析大整数字面量。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    runBigIntParse(request) {
        const parsed = parseBigIntLiteral(readString(request, 'value', true) ?? '');
        return {
            operation: 'bigint-parse',
            summary: `解析成功，${parsed.bytes.length} 字节`,
            result: {
                decimal: parsed.value.toString(10),
                hex: parsed.hex,
                bytes: parsed.bytes,
                byteLength: parsed.bytes.length,
                bits: parsed.value.toString(2).length,
            },
            notes: [],
        };
    }
    /**
     * 归一化 hex（去掉分隔符）并给出字节视图。
     *
     * @param request - 请求。
     * @returns 结果。
     */
    runHexNormalize(request) {
        const raw = readString(request, 'value', true) ?? '';
        const normalized = normalizeHex(raw);
        const bytes = asBytes(normalized, 'hex');
        return {
            operation: 'hex-normalize',
            summary: `归一化完成，共 ${bytes.length} 字节`,
            result: {
                normalized,
                bytes: toPlainArray(bytes),
                byteLength: bytes.length,
                decimal: bytesToBigInt(bytes).toString(10),
            },
            notes: ['分隔符（空格/冒号/连字符/下划线/逗号）会被去掉；奇数长度或非法字符会直接报错'],
        };
    }
}
