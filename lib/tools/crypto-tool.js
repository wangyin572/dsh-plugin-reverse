/**
 * 工具 `rev_crypto_calc`：密码学快速验算。
 *
 * 用途是「手上有一段密文/一个已知摘要，想立刻确认自己的算法理解对不对」。
 * 所有参数都是扁平的，靠 `operation` 分派——这样模型一次调用就能完成验算，
 * 不必先猜结构再补调用。
 */
import { defineTool } from '@deepseek-ai/dsh-tools';
import { ReverseError } from '../core/errors.js';
import { CRYPTO_OPERATIONS } from '../services/crypto-service.js';
/** 把任意错误转成带分类码的说明文本。 */
function describeError(error) {
    if (error instanceof ReverseError)
        return `[${error.code}] ${error.message}`;
    return error instanceof Error ? error.message : String(error);
}
/** 工具插件。 */
export const name = 'tool-rev-crypto';
/** 依赖：工具注册表 + 密码学服务。 */
export const inject = ['tools', 'reverseCrypto'];
/**
 * 注册 `rev_crypto_calc`。
 *
 * @param ctx - 已满足依赖的上下文。
 */
export function apply(ctx) {
    const service = ctx.reverseCrypto;
    ctx.tools.register(defineTool({
        name: 'rev_crypto_calc',
        description: 'Verify cryptographic primitives against a known ciphertext/key/iv: hash, HMAC, AES ' +
            '(cbc/ecb/ctr/cfb/ofb/gcm, raw key or CryptoJS passphrase), OpenSSL "Salted__" blobs, ' +
            'cyclic XOR and single-byte XOR brute force, RSA (PEM encrypt/decrypt/sign/verify, ' +
            'modulus+exponent to PEM, raw big-integer modpow for hand-rolled RSA), and BigInt utilities. ' +
            'Every encoding is explicit (utf8/hex/base64/base64url/latin1) so a wrong interpretation ' +
            'fails loudly instead of returning plausible garbage. Use it to check intermediate values ' +
            'while restoring an algorithm, not to attack systems you are not authorised to analyse.',
        parameters: {
            operation: {
                type: 'string',
                required: true,
                enum: [...CRYPTO_OPERATIONS],
                description: 'Which primitive to run. aes-* use raw key/iv; openssl-* handle CryptoJS "Salted__" blobs; ' +
                    'rsa-manual-pow covers code that implements RSA itself with BigInt.',
            },
            data: { type: 'string', description: 'Input data: plaintext, ciphertext, or pre-hashed text.' },
            dataEncoding: {
                type: 'string',
                enum: ['utf8', 'hex', 'base64', 'base64url', 'latin1'],
                description: 'How to read `data`. Defaults: utf8 for plaintext, base64 for ciphertext.',
            },
            outputEncoding: {
                type: 'string',
                enum: ['utf8', 'hex', 'base64', 'base64url', 'latin1'],
                description: 'How to render the result. Defaults: base64 when encrypting, utf8 when decrypting.',
            },
            algorithm: { type: 'string', description: 'Hash algorithm: md5, sha1, sha256, sha512, sha3-256…' },
            key: {
                // 混淆代码里的异或密钥经常直接是十进制数组（如 [18,52,86]），
                // 而对称加密的密钥是字符串。DSH 参数 DSL 没有联合类型，
                // 用「恰好匹配一个分支」的 oneOf 表达这个二选一。
                oneOf: [
                    { type: 'string' },
                    { type: 'array', items: { type: 'integer' } },
                ],
                description: 'Raw key. Accepts a string (read with keyEncoding) or a decimal byte array like [18,52,86].',
            },
            keyEncoding: { type: 'string', enum: ['utf8', 'hex', 'base64', 'base64url', 'latin1'], description: 'How to read `key`. Default utf8.' },
            iv: { type: 'string', description: 'Initialisation vector. Required for cbc/ctr/cfb/ofb/gcm.' },
            ivEncoding: { type: 'string', enum: ['utf8', 'hex', 'base64', 'base64url', 'latin1'], description: 'How to read `iv`. Default utf8.' },
            mode: { type: 'string', enum: ['cbc', 'ecb', 'ctr', 'cfb', 'ofb', 'gcm'], description: 'AES mode. Default cbc.' },
            padding: { type: 'string', enum: ['pkcs7', 'none'], description: 'Block-mode padding. Default pkcs7.' },
            authTag: { type: 'string', description: 'GCM authentication tag (required to decrypt GCM).' },
            authTagEncoding: { type: 'string', enum: ['hex', 'base64'], description: 'How to read authTag. Default hex.' },
            passphrase: { type: 'string', description: 'Passphrase for EVP_BytesToKey key derivation (the CryptoJS behaviour).' },
            salt: { type: 'string', description: 'Salt for EVP_BytesToKey, hex. Required to decrypt a passphrase-derived ciphertext.' },
            saltEncoding: { type: 'string', enum: ['hex', 'utf8', 'base64'], description: 'How to read salt. Default hex.' },
            kdfHash: { type: 'string', enum: ['md5', 'sha1', 'sha256', 'sha512'], description: 'Digest used by EVP_BytesToKey. CryptoJS default is md5.' },
            keyLength: { type: 'integer', description: 'Derived key length in bytes: 16, 24 or 32. Default 32.' },
            plaintext: { type: 'string', description: 'Known plaintext (for xor-recover-key).' },
            plaintextEncoding: { type: 'string', enum: ['utf8', 'hex', 'base64'], description: 'How to read plaintext. Default utf8.' },
            ciphertext: { type: 'string', description: 'Known ciphertext (for xor-recover-key).' },
            ciphertextEncoding: { type: 'string', enum: ['utf8', 'hex', 'base64'], description: 'How to read ciphertext. Default hex.' },
            publicKey: { type: 'string', description: 'Public key in PEM.' },
            privateKey: { type: 'string', description: 'Private key in PEM.' },
            n: { type: 'string', description: 'RSA modulus, for rsa-public-from-modulus.' },
            e: { type: 'string', description: 'RSA public exponent, for rsa-public-from-modulus.' },
            inputEncoding: { type: 'string', enum: ['hex', 'base64', 'base64url', 'utf8'], description: 'How to read n/e/value. Default hex.' },
            value: { type: 'string', description: 'Big-integer input (rsa-manual-pow / bigint-parse / hex-normalize).' },
            exponent: { type: 'string', description: 'Big-integer exponent (e or d).' },
            exponentEncoding: { type: 'string', enum: ['hex', 'base64', 'utf8'], description: 'How to read exponent. Default hex.' },
            modulus: { type: 'string', description: 'Big-integer modulus n.' },
            modulusEncoding: { type: 'string', enum: ['hex', 'base64', 'utf8'], description: 'How to read modulus. Default hex.' },
            signature: { type: 'string', description: 'Signature to verify.' },
            signatureEncoding: { type: 'string', enum: ['base64', 'hex'], description: 'How to read signature. Default base64.' },
            hash: { type: 'string', enum: ['md5', 'sha1', 'sha256', 'sha384', 'sha512'], description: 'Digest for RSA sign/verify. Default sha256.' },
            oaepHash: { type: 'string', enum: ['sha1', 'sha256', 'sha384', 'sha512'], description: 'OAEP digest.' },
            top: { type: 'integer', description: 'How many XOR brute-force candidates to return. Default 5.' },
            minPrintableRatio: { type: 'number', description: 'Minimum printable-character ratio for XOR candidates. Default 0.85.' },
            padTo: { type: 'integer', description: 'Pad the big-integer result to this many bytes.' },
            base: { type: 'string', description: 'Base for mod-pow (decimal, 0x-hex, or bare hex).' },
            a: { type: 'string', description: 'Value for mod-inverse.' },
            kind: { type: 'string', enum: ['public', 'private'], description: 'Key kind for rsa-key-info. Default public.' },
        },
        output: {
            // 用 DSH schema 子集里的 `json` 承载结果：结果是本插件自己构造的，
            // 逐字段列举既冗长又脆弱（新增一个操作就要同步改 schema）。
            schema: {
                type: 'object',
                additionalProperties: false,
                properties: {
                    operation: { type: 'string', required: true },
                    summary: { type: 'string', required: true },
                    notes: { type: 'array', required: true, items: { type: 'string' } },
                    result: { type: 'json', required: true },
                },
            },
            render: (_args, value) => {
                // `json` 在类型上是 JsonValue，索引需要显式收窄；这里的结果结构由本插件保证。
                const result = value.result;
                const lines = [value.summary];
                if (result && typeof result === 'object') {
                    for (const [key, item] of Object.entries(result)) {
                        if (item === undefined || item === null || item === '')
                            continue;
                        const text = Array.isArray(item)
                            ? item.length > 24
                                ? `[${item.length} 项] ${item.slice(0, 24).join(', ')}…`
                                : item.join(', ')
                            : String(item);
                        lines.push(`${key}: ${text}`);
                    }
                }
                if (value.notes.length > 0) {
                    lines.push('', ...value.notes.map((note) => `· ${note}`));
                }
                return [{ type: 'text', text: lines.join('\n') }];
            },
        },
        presentCall: (args) => ({
            card: 'generic',
            title: `验算 ${args.operation}`,
            kind: 'other',
        }),
        async execute(args) {
            try {
                const response = service.calculate({ ...args, operation: args.operation });
                return {
                    operation: response.operation,
                    summary: response.summary,
                    notes: response.notes,
                    result: response.result,
                };
            }
            catch (error) {
                throw new Error(describeError(error));
            }
        },
    }));
}
