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
import { asBytes, encodeHex, fromBytes, toPlainArray, truncate, } from './encoding.js';
import { ReverseError, assertReverse } from './errors.js';
/**
 * 把各种形态的密钥归一化为字节。
 *
 * @param key - 字符串 / 字节 / 十进制数组。
 * @param encoding - 字符串密钥的编码。
 * @returns 密钥字节。
 */
function normalizeKey(key, encoding) {
    if (Array.isArray(key) || (typeof key === 'object' && !(key instanceof Uint8Array))) {
        const values = Array.from(key);
        assertReverse(values.length > 0, '密钥数组为空', 'INVALID_INPUT');
        return Uint8Array.from(values.map((value, index) => {
            assertReverse(Number.isInteger(value) && value >= 0 && value <= 255, `密钥数组第 ${index} 项不是合法字节：${String(value)}`, 'INVALID_INPUT');
            return value;
        }));
    }
    const bytes = asBytes(key, encoding);
    assertReverse(bytes.length > 0, '密钥为空', 'INVALID_INPUT');
    return bytes;
}
/**
 * 执行循环异或（加解密同一函数，异或自逆）。
 *
 * @param params - 数据与密钥。
 * @returns 结果，含实际使用的密钥字节。
 */
export function xorBytes(params) {
    const data = asBytes(params.data, params.dataEncoding ?? 'utf8');
    const key = normalizeKey(params.key, params.keyEncoding ?? 'utf8');
    const output = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += 1) {
        output[i] = (data[i] ?? 0) ^ (key[i % key.length] ?? 0);
    }
    const outputEncoding = params.outputEncoding ?? 'hex';
    return {
        output: fromBytes(output, outputEncoding),
        hex: encodeHex(output),
        keyBytes: toPlainArray(key),
        keyLength: key.length,
        inputLength: data.length,
        outputEncoding,
    };
}
/**
 * 已知明文与密文时反推循环异或的密钥。
 *
 * 原理：`key[i] = cipher[i] ^ plain[i]`。若密钥比明文短，结果会呈现周期性——
 * 本函数按最短周期折叠，直接给出候选密钥。
 *
 * @param params - 明文、密文与编码。
 * @returns 反推出的密钥候选。
 */
export function xorRecoverKey(params) {
    const plain = asBytes(params.plaintext, params.plaintextEncoding ?? 'utf8');
    const cipher = asBytes(params.ciphertext, params.ciphertextEncoding ?? 'utf8');
    assertReverse(plain.length === cipher.length, `明文(${plain.length} 字节)与密文(${cipher.length} 字节)长度不一致，无法逐字节反推`, 'INVALID_INPUT');
    const raw = new Uint8Array(plain.length);
    for (let i = 0; i < plain.length; i += 1) {
        raw[i] = (plain[i] ?? 0) ^ (cipher[i] ?? 0);
    }
    // 折叠出最短周期：找到最小的 p 使序列以 p 为周期重复。
    let period = raw.length;
    for (let p = 1; p <= raw.length; p += 1) {
        let ok = true;
        for (let i = p; i < raw.length; i += 1) {
            if (raw[i] !== raw[i % p]) {
                ok = false;
                break;
            }
        }
        if (ok) {
            period = p;
            break;
        }
    }
    const key = raw.subarray(0, period);
    return {
        keyBytes: toPlainArray(key),
        keyHex: encodeHex(key),
        keyUtf8: fromBytes(key, 'utf8'),
        period,
    };
}
/** 英文与常见代码文本的字符频率先验，用于给爆破结果排序。 */
const FREQUENCY = {
    ' ': 13.0,
    e: 10.5,
    t: 7.1,
    a: 6.5,
    o: 6.4,
    i: 5.5,
    n: 5.4,
    s: 5.1,
    r: 4.9,
    h: 4.8,
    l: 3.3,
    d: 3.3,
    c: 2.3,
    u: 2.2,
    m: 2.0,
    f: 1.8,
    p: 1.6,
    g: 1.6,
    w: 1.4,
    y: 1.4,
    b: 1.2,
    v: 0.8,
    k: 0.6,
    x: 0.15,
    j: 0.1,
    q: 0.1,
    z: 0.07,
    '0': 1.0,
    '1': 1.0,
    '2': 1.0,
    '3': 1.0,
    '4': 1.0,
    '5': 1.0,
    '6': 1.0,
    '7': 1.0,
    '8': 1.0,
    '9': 1.0,
    '{': 0.8,
    '}': 0.8,
    '"': 0.8,
    ':': 0.6,
    ',': 0.6,
    '/': 0.3,
    '-': 0.3,
    _: 0.3,
};
/**
 * 给一段字节打「像不像自然文本/JSON」的分。
 *
 * @param bytes - 解密结果。
 * @returns 0-1 之间的评分。
 */
function scoreText(bytes) {
    if (bytes.length === 0)
        return { score: 0, printableRatio: 0 };
    let printable = 0;
    let weight = 0;
    for (const byte of bytes) {
        if (byte === 9 || byte === 10 || byte === 13) {
            printable += 1;
            weight += 0.5;
            continue;
        }
        if (byte < 32 || byte > 126)
            continue;
        printable += 1;
        const char = String.fromCharCode(byte).toLowerCase();
        weight += FREQUENCY[char] ?? 0.05;
    }
    const printableRatio = printable / bytes.length;
    const score = (weight / bytes.length) * printableRatio;
    return { score, printableRatio };
}
/**
 * 对标量密钥做全 256 值爆破，按可读性排序返回候选。
 *
 * 用于「密钥只有一个字节」或「只知道是单字节异或」的场景，是最快的定位手段。
 *
 * @param params - 密文与筛选参数。
 * @returns 按评分降序的候选列表。
 */
export function xorBruteForce(params) {
    const data = asBytes(params.data, params.dataEncoding ?? 'hex');
    const top = params.top ?? 5;
    const minRatio = params.minPrintableRatio ?? 0.85;
    assertReverse(top > 0, 'top 必须为正整数', 'INVALID_INPUT');
    const candidates = [];
    for (let key = 0; key < 256; key += 1) {
        const output = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i += 1)
            output[i] = (data[i] ?? 0) ^ key;
        const { score, printableRatio } = scoreText(output);
        if (printableRatio < minRatio)
            continue;
        candidates.push({
            key,
            keyChar: key >= 32 && key <= 126 ? String.fromCharCode(key) : '',
            preview: truncate(fromBytes(output, 'utf8').replace(/[\u0000-\u001f]/gu, '·'), 120),
            printableRatio,
            score,
        });
    }
    candidates.sort((a, b) => b.score - a.score);
    const result = candidates.slice(0, top);
    if (result.length === 0) {
        throw new ReverseError('没有任何单字节密钥能产出足够可读的结果；密钥可能不是单字节，或数据并非简单异或', 'DECRYPT_FAILED');
    }
    return result;
}
