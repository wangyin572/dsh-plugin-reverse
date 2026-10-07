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
import { constants, createPrivateKey, createPublicKey, createSign, createVerify, privateDecrypt, publicEncrypt, } from 'node:crypto';
import { asBytes, assertNonEmpty, encodeHex, fromBytes, toPlainArray, truncate, } from './encoding.js';
import { ReverseError, assertReverse } from './errors.js';
/**
 * 把字节序列转成大整数。
 *
 * @param bytes - 大端字节序。
 * @returns 对应的大整数。
 */
export function bytesToBigInt(bytes) {
    let value = 0n;
    for (const byte of bytes)
        value = (value << 8n) | BigInt(byte);
    return value;
}
/**
 * 把大整数转成大端字节序列。
 *
 * @param value - 非负整数。
 * @param minLength - 补齐到的最小字节数（RSA 需要固定块长）。
 * @returns 大端字节。
 */
export function bigIntToBytes(value, minLength = 0) {
    assertReverse(value >= 0n, '大整数不能为负', 'INVALID_INPUT');
    let hex = value.toString(16);
    if (hex.length % 2 === 1)
        hex = `0${hex}`;
    let bytes = new Uint8Array(Buffer.from(hex === '' ? '00' : hex, 'hex'));
    if (minLength > bytes.length) {
        const padded = new Uint8Array(minLength);
        padded.set(bytes, minLength - bytes.length);
        bytes = padded;
    }
    return bytes;
}
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
export function modPow(base, exponent, modulus) {
    assertReverse(modulus > 0n, '模数必须为正', 'INVALID_INPUT');
    assertReverse(exponent >= 0n, '指数不能为负', 'INVALID_INPUT');
    let result = 1n;
    let b = ((base % modulus) + modulus) % modulus;
    let e = exponent;
    while (e > 0n) {
        if ((e & 1n) === 1n)
            result = (result * b) % modulus;
        b = (b * b) % modulus;
        e >>= 1n;
    }
    return result;
}
/**
 * 模反元素（扩展欧几里得），用于从 (e, φ) 求 d。
 *
 * @param a - 被求逆的数。
 * @param modulus - 模数。
 * @returns `a` 的模逆。
 */
export function modInverse(a, modulus) {
    let [oldR, r] = [((a % modulus) + modulus) % modulus, modulus];
    let [oldS, s] = [1n, 0n];
    while (r !== 0n) {
        const q = oldR / r;
        [oldR, r] = [r, oldR - q * r];
        [oldS, s] = [s, oldS - q * s];
    }
    assertReverse(oldR === 1n, `${a} 与 ${modulus} 不互质，不存在模逆`, 'INVALID_INPUT');
    return ((oldS % modulus) + modulus) % modulus;
}
/**
 * 把密钥输入解析为 Node 的 KeyObject。
 *
 * @param key - PEM 文本或 DER 字节。
 * @param format - `pem`（默认，字符串输入）或 `der`。
 * @param kind - 期望的公钥还是私钥。
 * @returns KeyObject。
 */
function keyObject(key, format, kind) {
    const isPem = (format ?? (typeof key === 'string' ? 'pem' : 'der')) === 'pem';
    const material = typeof key === 'string' ? key : Buffer.from(key);
    try {
        return kind === 'public'
            ? createPublicKey({ key: material, format: isPem ? 'pem' : 'der', type: isPem ? undefined : 'spki' })
            : createPrivateKey({ key: material, format: isPem ? 'pem' : 'der', type: isPem ? undefined : 'pkcs8' });
    }
    catch (error) {
        throw new ReverseError(`无法解析${kind === 'public' ? '公' : '私'}钥：${error instanceof Error ? error.message : String(error)}。` +
            '请确认是 PEM（-----BEGIN ...-----）还是 DER 字节，并检查是否被截断。', 'PARSE_FAILED');
    }
}
/**
 * 把填充名转成 Node 常量。
 *
 * @param padding - 填充名。
 * @returns Node 常量与 OAEP 摘要默认值。
 */
function paddingConstant(padding) {
    switch (padding) {
        case 'pkcs1':
            return constants.RSA_PKCS1_PADDING;
        case 'oaep':
            return constants.RSA_PKCS1_OAEP_PADDING;
        case 'none':
            return constants.RSA_NO_PADDING;
    }
}
/**
 * 公钥加密。
 *
 * @param params - 数据、公钥与填充。
 * @returns 密文结果。
 */
export function rsaEncrypt(params) {
    const padding = params.padding ?? 'pkcs1';
    const bytes = asBytes(params.data, params.dataEncoding ?? 'utf8');
    assertNonEmpty(bytes, '明文');
    const key = keyObject(params.publicKey, params.keyFormat, 'public');
    try {
        const out = publicEncrypt({
            key,
            padding: paddingConstant(padding),
            ...(padding === 'oaep' ? { oaepHash: params.oaepHash ?? 'sha256' } : {}),
        }, Buffer.from(bytes));
        const result = new Uint8Array(out);
        const outputEncoding = params.outputEncoding ?? 'base64';
        return {
            data: fromBytes(result, outputEncoding),
            dataHex: encodeHex(result),
            length: result.length,
            padding,
            outputEncoding,
        };
    }
    catch (error) {
        throw new ReverseError(`RSA 加密失败：${error instanceof Error ? error.message : String(error)}。` +
            'PKCS#1 v1.5 对明文长度有限制（密钥字节数 - 11）；过长请改用混合加密或 OAEP。', 'DECRYPT_FAILED');
    }
}
/**
 * 私钥解密。
 *
 * @param params - 密文、私钥与填充。
 * @returns 明文结果。
 */
export function rsaDecrypt(params) {
    const padding = params.padding ?? 'pkcs1';
    const bytes = asBytes(params.data, params.dataEncoding ?? 'base64');
    assertNonEmpty(bytes, '密文');
    const key = keyObject(params.privateKey, params.keyFormat, 'private');
    try {
        const out = privateDecrypt({
            key,
            padding: paddingConstant(padding),
            ...(padding === 'oaep' ? { oaepHash: params.oaepHash ?? 'sha256' } : {}),
        }, Buffer.from(bytes));
        const result = new Uint8Array(out);
        const outputEncoding = params.outputEncoding ?? 'utf8';
        return {
            data: fromBytes(result, outputEncoding),
            dataHex: encodeHex(result),
            length: result.length,
            padding,
            outputEncoding,
        };
    }
    catch (error) {
        throw new ReverseError(`RSA 解密失败：${error instanceof Error ? error.message : String(error)}。` +
            '常见原因：密文不是该私钥的、填充方式不符、密文编码不是 base64。', 'DECRYPT_FAILED');
    }
}
/**
 * 私钥签名。
 *
 * @param params - 数据、私钥与摘要算法。
 * @returns 签名结果。
 */
export function rsaSign(params) {
    const hashName = params.hash ?? 'sha256';
    const key = keyObject(params.privateKey, params.keyFormat, 'private');
    const bytes = asBytes(params.data, params.dataEncoding ?? 'utf8');
    assertNonEmpty(bytes, '待签名数据');
    try {
        const signature = createSign(hashName).update(Buffer.from(bytes)).end().sign(key);
        const result = new Uint8Array(signature);
        const outputEncoding = params.outputEncoding ?? 'base64';
        return {
            data: fromBytes(result, outputEncoding),
            dataHex: encodeHex(result),
            length: result.length,
            padding: 'pkcs1',
            outputEncoding,
        };
    }
    catch (error) {
        throw new ReverseError(`RSA 签名失败：${error instanceof Error ? error.message : String(error)}。` +
            `摘要 "${hashName}" 在当前 OpenSSL 上可能不可用（MD5 常因安全策略被禁用）。`, 'UNSUPPORTED_ALGORITHM');
    }
}
/**
 * 公钥验签。
 *
 * @param params - 数据、签名与公钥。
 * @returns 是否验证通过。
 */
export function rsaVerify(params) {
    const hashName = params.hash ?? 'sha256';
    const key = keyObject(params.publicKey, params.keyFormat, 'public');
    const bytes = asBytes(params.data, params.dataEncoding ?? 'utf8');
    const signature = asBytes(params.signature, params.signatureEncoding ?? 'base64');
    try {
        const valid = createVerify(hashName).update(Buffer.from(bytes)).end().verify(key, Buffer.from(signature));
        return { valid, algorithm: `RSA-${hashName.toUpperCase()}` };
    }
    catch (error) {
        throw new ReverseError(`RSA 验签过程出错：${error instanceof Error ? error.message : String(error)}`, 'DECRYPT_FAILED');
    }
}
/**
 * 由模数 n 与指数 e 还原公钥 PEM。
 *
 * @param params - n、e 与它们的编码。
 * @returns PEM 文本与密钥信息。
 */
export function rsaPublicKeyFromComponents(params) {
    const nBytes = asBytes(params.n, params.inputEncoding);
    const eBytes = asBytes(params.e, params.inputEncoding);
    assertNonEmpty(nBytes, '模数 n');
    assertNonEmpty(eBytes, '指数 e');
    const jwk = {
        kty: 'RSA',
        n: encodeHex(nBytes).length > 0 ? Buffer.from(nBytes).toString('base64url') : '',
        e: Buffer.from(eBytes).toString('base64url'),
    };
    try {
        const key = createPublicKey({ key: jwk, format: 'jwk' });
        return {
            pem: key.export({ type: 'spki', format: 'pem' }).toString(),
            bits: key.asymmetricKeyDetails?.modulusLength ?? nBytes.length * 8,
            modulusHex: encodeHex(nBytes),
        };
    }
    catch (error) {
        throw new ReverseError(`无法由 n/e 构造公钥：${error instanceof Error ? error.message : String(error)}。` +
            '请确认 n 的编码（hex 常带前导 00，base64 常用于 JWK）。', 'PARSE_FAILED');
    }
}
/**
 * 读取密钥的基本信息（位数、模数、指数）。
 *
 * @param params - 密钥与格式。
 * @returns 密钥信息。
 */
export function rsaKeyInfo(params) {
    const kind = params.kind ?? 'public';
    const key = keyObject(params.key, params.keyFormat, kind);
    const details = key.asymmetricKeyDetails;
    const info = {
        kind,
        bits: details?.modulusLength ?? 0,
    };
    try {
        const jwk = key.export({ format: 'jwk' });
        if (jwk.n)
            info.modulusHex = Buffer.from(jwk.n, 'base64url').toString('hex');
        if (jwk.e)
            info.exponentHex = Buffer.from(jwk.e, 'base64url').toString('hex');
    }
    catch {
        // 某些私钥导出 JWK 需要更多参数，取不到就只回位数。
    }
    return info;
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
export function rsaManualPow(params) {
    const value = bytesToBigInt(asBytes(params.value, params.inputEncoding));
    const exponent = bytesToBigInt(asBytes(params.exponent, params.exponentEncoding));
    const modulus = bytesToBigInt(asBytes(params.modulus, params.modulusEncoding));
    assertReverse(modulus > 1n, '模数 n 必须大于 1', 'INVALID_INPUT');
    const bits = modulus.toString(2).length;
    const padded = params.padTo ?? Math.ceil(bits / 8);
    const raw = modPow(value, exponent, modulus);
    const resultBytes = bigIntToBytes(raw, padded);
    const outputEncoding = params.outputEncoding ?? 'hex';
    return {
        resultHex: encodeHex(resultBytes),
        result: fromBytes(resultBytes, outputEncoding),
        resultDecimal: raw.toString(10),
        bits,
        outputEncoding,
    };
}
/**
 * 把大整数以十进制/hex 文本解析出来，供调试输出使用。
 *
 * @param text - 十进制或 `0x` 前缀 hex 文本。
 * @returns 大整数、字节与 hex 表示。
 */
export function parseBigIntLiteral(text) {
    const trimmed = text.trim();
    let value;
    try {
        if (/^0x[0-9a-f]+$/iu.test(trimmed))
            value = BigInt(trimmed);
        else if (/^[0-9]+$/u.test(trimmed))
            value = BigInt(trimmed);
        else if (/^[0-9a-f]+$/iu.test(trimmed))
            value = BigInt(`0x${trimmed}`);
        else
            throw new Error('格式无法识别');
    }
    catch (error) {
        throw new ReverseError(`无法解析大整数字面量 ${JSON.stringify(truncate(text, 40))}：${error instanceof Error ? error.message : String(error)}`, 'INVALID_INPUT');
    }
    const bytes = bigIntToBytes(value);
    return { value, hex: encodeHex(bytes), bytes: toPlainArray(bytes) };
}
