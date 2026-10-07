/**
 * 纯计算核心的测试套件。
 *
 * 全部使用 Node 内置 `node:test`，无第三方测试框架——因为本项目的核心承诺之一就是
 * 「脱离浏览器与 DSH 运行时也能跑」，测试本身也不该引入额外依赖。
 *
 * 权威性说明：AES/Hash 的关键向量来自**系统 OpenSSL 3.6.2** 现场生成，而不是
 * 由本项目自己产生再自己验证（那只能证明自洽，不能证明兼容）：
 *
 *   printf 'hello reverse engineering' | openssl enc -aes-256-cbc -md md5 \
 *     -base64 -A -S 0001020304050607 -pass pass:secret
 *
 * 运行：npm run build && npm test
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, createHash } from 'node:crypto'

import {
  ReverseError,
  aesDecrypt,
  aesEncrypt,
  bigIntToBytes,
  bytesToBigInt,
  constantTimeEqual,
  decodeBase64,
  decodeHex,
  encodeBase64,
  encodeHex,
  evpBytesToKey,
  hash,
  hmac,
  modInverse,
  modPow,
  opensslDecrypt,
  opensslEncrypt,
  parseBigIntLiteral,
  pkcs7Pad,
  pkcs7Unpad,
  rsaDecrypt,
  rsaEncrypt,
  rsaKeyInfo,
  rsaManualPow,
  rsaPublicKeyFromComponents,
  rsaSign,
  rsaVerify,
  xorBruteForce,
  xorBytes,
  xorRecoverKey,
} from '../lib/core/index.js'

/** 断言某次调用抛出带指定 code 的 ReverseError。 */
function expectCode(fn, code, label) {
  try {
    fn()
  } catch (error) {
    assert.ok(error instanceof ReverseError, `${label}: 应抛 ReverseError，实际 ${String(error)}`)
    assert.equal(error.code, code, `${label}: code 应为 ${code}，实际 ${error.code}`)
    return
  }
  assert.fail(`${label}: 预期抛出错误但没有`)
}

// ---------------------------------------------------------------- 编码

test('编码：hex / base64 往返，且严格拒绝非法输入', () => {
  const bytes = new Uint8Array([0x00, 0x0f, 0xff, 0x10])
  assert.equal(encodeHex(bytes), '000fff10')
  assert.deepEqual([...decodeHex('000fff10')], [...bytes])
  // 分隔符会被归一化：真实逆向里密钥常写成 00:0f:ff:10
  assert.deepEqual([...decodeHex('00:0f-ff 10')], [...bytes])
  assert.equal(encodeBase64(bytes), 'AA//EA==')
  assert.deepEqual([...decodeBase64('AA//EA==')], [...bytes])

  expectCode(() => decodeHex('abc'), 'INVALID_HEX', 'hex 奇数长度')
  expectCode(() => decodeHex('zz'), 'INVALID_HEX', 'hex 非法字符')
  expectCode(() => decodeBase64('!!!!'), 'INVALID_BASE64', 'base64 非法字符')
})

// ---------------------------------------------------------------- 哈希

test('哈希：标准向量与 HMAC(RFC 4231)', () => {
  assert.equal(hash('md5', { data: 'abc' }).hex, '900150983cd24fb0d6963f7d28e17f72')
  assert.equal(
    hash('sha1', { data: 'abc' }).hex,
    'a9993e364706816aba3e25717850c26c9cd0d89d',
  )
  assert.equal(
    hash('sha256', { data: 'abc' }).hex,
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  )
  assert.equal(
    hash('sha512', { data: 'abc' }).hex,
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
      '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
  )

  // RFC 4231 Test Case 2
  const mac = hmac('sha256', {
    key: 'Jefe',
    data: 'what do ya want for nothing?',
  })
  assert.equal(
    mac.hex,
    '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
  )

  // 输出编码可选，且 hex 始终同时给出
  const b64 = hash('sha256', { data: 'abc', outputEncoding: 'base64' })
  assert.equal(b64.digest, 'ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=')
  assert.equal(b64.hex, hash('sha256', { data: 'abc' }).hex)

  expectCode(() => hash('md4-nope', { data: 'x' }), 'UNSUPPORTED_ALGORITHM', '未知算法')
})

test('定长比较：相等/不等/长度不同', () => {
  assert.equal(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])), true)
  assert.equal(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])), false)
  assert.equal(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])), false)
})

// ---------------------------------------------------------------- AES

test('AES：原始 key/iv 对齐系统 OpenSSL 向量', () => {
  // printf 'block cipher check' | openssl enc -aes-128-cbc \
  //   -K 000102030405060708090a0b0c0d0e0f -iv 101112131415161718191a1b1c1d1e1f -base64 -A
  const ciphertext = 'XT1DEq0GS5B3iK8iSUsBy022/3nJAad8uAwhzqmV43c='
  const result = aesDecrypt({
    data: ciphertext,
    dataEncoding: 'base64',
    key: '000102030405060708090a0b0c0d0e0f',
    keyEncoding: 'hex',
    iv: '101112131415161718191a1b1c1d1e1f',
    ivEncoding: 'hex',
    mode: 'cbc',
  })
  assert.equal(result.plaintext, 'block cipher check')
  assert.equal(result.algorithm, 'aes-128-cbc')

  // 反向：加密结果必须逐字节等于 OpenSSL 输出
  const back = aesEncrypt({
    data: 'block cipher check',
    key: '000102030405060708090a0b0c0d0e0f',
    keyEncoding: 'hex',
    iv: '101112131415161718191a1b1c1d1e1f',
    ivEncoding: 'hex',
    mode: 'cbc',
    outputEncoding: 'base64',
  })
  assert.equal(back.ciphertext, ciphertext)
})

test('AES：口令派生（EVP_BytesToKey + MD5）对齐系统 OpenSSL 向量', () => {
  // openssl enc -aes-256-cbc -md md5 -S 0001020304050607 -pass pass:secret
  const result = aesDecrypt({
    data: '80p1kg4kNCTY3kx4aCiJfEUpFaY6Fs6u8yjWDQO5FJE=',
    dataEncoding: 'base64',
    passphrase: 'secret',
    salt: '0001020304050607',
    saltEncoding: 'hex',
    kdfHash: 'md5',
    keyLength: 32,
    mode: 'cbc',
  })
  assert.equal(result.plaintext, 'hello reverse engineering')
  assert.equal(result.algorithm, 'aes-256-cbc')

  // 同一向量用 SHA-256 派生，OpenSSL 给出不同密文——证明 kdfHash 真的生效
  const sha = aesDecrypt({
    data: '1braJVqts/Re58f80rkAW3dQ4cPjnFCucmgz1+nBLQU=',
    dataEncoding: 'base64',
    passphrase: 'secret',
    salt: '0001020304050607',
    saltEncoding: 'hex',
    kdfHash: 'sha256',
    keyLength: 32,
    mode: 'cbc',
  })
  assert.equal(sha.plaintext, 'hello reverse engineering')

  // 用错的 KDF 必须解不出原文（而不是悄悄给出垃圾）
  expectCode(
    () =>
      aesDecrypt({
        data: '80p1kg4kNCTY3kx4aCiJfEUpFaY6Fs6u8yjWDQO5FJE=',
        dataEncoding: 'base64',
        passphrase: 'secret',
        salt: '0001020304050607',
        saltEncoding: 'hex',
        kdfHash: 'sha256',
        keyLength: 32,
        mode: 'cbc',
      }),
    'DECRYPT_FAILED',
    'KDF 不匹配',
  )
})

test('AES：evpBytesToKey 按定义逐块校验（D_i = MD5(D_{i-1} || pass || salt)）', () => {
  const pass = new TextEncoder().encode('secret')
  const salt = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7])
  const { key, iv } = evpBytesToKey(pass, salt, 32, 16, 'md5')

  // 直接用 node:crypto 独立复算一遍定义，避免用被测代码验证被测代码
  const md5 = (...parts) => {
    const h = createHash('md5')
    for (const part of parts) h.update(Buffer.from(part))
    return new Uint8Array(h.digest())
  }
  const d1 = md5(pass, salt)
  const d2 = md5(d1, pass, salt)
  const d3 = md5(d2, pass, salt)
  const material = Buffer.concat([d1, d2, d3])

  assert.equal(key.length, 32)
  assert.equal(iv.length, 16)
  assert.deepEqual([...key], [...material.subarray(0, 32)])
  assert.deepEqual([...iv], [...material.subarray(32, 48)])
})

test('AES：OpenSSL/CryptoJS Salted__ 格式闭环（自造密文可自解，且前缀正确）', () => {
  const encrypted = opensslEncrypt({
    data: '{"sign":"abc","ts":1730000000}',
    passphrase: 'p@ssw0rd',
    salt: new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]),
    outputEncoding: 'base64',
  })
  const blob = decodeBase64(encrypted.blob)
  assert.equal(Buffer.from(blob.subarray(0, 8)).toString('latin1'), 'Salted__')

  const decrypted = opensslDecrypt({ data: encrypted.blob, passphrase: 'p@ssw0rd' })
  assert.equal(decrypted.plaintext, '{"sign":"abc","ts":1730000000}')

  expectCode(
    () => opensslDecrypt({ data: encrypted.blob, passphrase: 'wrong' }),
    'DECRYPT_FAILED',
    '口令错误',
  )
  expectCode(
    () =>
      opensslDecrypt({
        data: encodeBase64(new Uint8Array(40)),
        passphrase: 'p@ssw0rd',
      }),
    'INVALID_INPUT',
    '缺少 Salted__ 前缀',
  )
})

test('AES：各模式往返（cbc/ecb/ctr/cfb/ofb/gcm）', () => {
  const key = '0123456789abcdef0123456789abcdef' // 32 字节 utf8 → AES-256
  const iv16 = 'fedcba9876543210' // 16 字节 utf8
  const plain = '中文+emoji🚀 payload 0123456789'

  for (const [mode, iv] of [
    ['cbc', iv16],
    ['ecb', undefined],
    ['ctr', iv16],
    ['cfb', iv16],
    ['ofb', iv16],
    ['gcm', '001122334455'], // 12 字节 utf8（GCM 的标准 IV 长度）
  ]) {
    const enc = aesEncrypt({
      data: plain,
      key,
      keyEncoding: 'utf8',
      iv,
      ivEncoding: 'utf8',
      mode,
      outputEncoding: 'base64',
    })
    const dec = aesDecrypt({
      data: enc.ciphertext,
      dataEncoding: 'base64',
      key,
      keyEncoding: 'utf8',
      iv,
      ivEncoding: 'utf8',
      mode,
      authTag: enc.authTag,
      outputEncoding: 'utf8',
    })
    assert.equal(dec.plaintext, plain, `模式 ${mode} 往返失败`)
    assert.equal(dec.padding, mode === 'cbc' || mode === 'ecb' ? 'pkcs7' : 'none')
    if (mode === 'gcm') assert.ok(enc.authTag, 'GCM 必须返回 authTag')
  }
})

test('AES：错误用法给出可诊断的失败，而不是静默垃圾', () => {
  expectCode(
    () =>
      aesDecrypt({
        data: 'AAAA',
        dataEncoding: 'base64',
        key: '00112233445566778899aabbccddeeff',
        keyEncoding: 'hex',
        iv: '00112233445566778899aabbccddeeff',
        ivEncoding: 'hex',
      }),
    'DECRYPT_FAILED',
    '错误密钥',
  )
  expectCode(
    () => aesEncrypt({ data: 'x', key: 'short', iv: 'a'.repeat(16), mode: 'cbc' }),
    'KEY_MISMATCH',
    '密钥长度非 16/24/32',
  )
  expectCode(
    () => aesEncrypt({ data: 'x', key: 'a'.repeat(16), mode: 'cbc' }),
    'INVALID_INPUT',
    'CBC 缺 IV',
  )
  expectCode(
    () => aesEncrypt({ data: 'x', key: 'a'.repeat(16), iv: 'b'.repeat(16), mode: 'ecb' }),
    'INVALID_INPUT',
    'ECB 不应给 IV',
  )
  expectCode(
    () => aesDecrypt({ data: 'AAAA', dataEncoding: 'base64', key: 'a'.repeat(16), iv: 'b'.repeat(16), mode: 'gcm' }),
    'INVALID_INPUT',
    'GCM 缺 authTag',
  )
})

test('PKCS#7 填充：往返与非法填充检测', () => {
  const data = new TextEncoder().encode('abc')
  const padded = pkcs7Pad(data)
  assert.equal(padded.length, 16)
  assert.equal(padded[15], 13)
  assert.deepEqual([...pkcs7Unpad(padded)], [...data])

  // 整块时补满一整块
  const full = new Uint8Array(16).fill(0x41)
  assert.equal(pkcs7Pad(full).length, 32)

  expectCode(() => pkcs7Unpad(new Uint8Array([1, 2, 3, 9])), 'DECRYPT_FAILED', '填充越界')
})

// ---------------------------------------------------------------- XOR

test('XOR：字符串密钥、十进制数组密钥、hex 密钥三种写法等价', () => {
  const plain = 'sign=abc123'
  const byString = xorBytes({ data: plain, dataEncoding: 'utf8', key: 'k1', keyEncoding: 'utf8' })
  const byArray = xorBytes({ data: plain, dataEncoding: 'utf8', key: [0x6b, 0x31] })
  const byHex = xorBytes({ data: plain, dataEncoding: 'utf8', key: '6b31', keyEncoding: 'hex' })
  assert.equal(byString.hex, byArray.hex)
  assert.equal(byString.hex, byHex.hex)
  assert.deepEqual(byString.keyBytes, [0x6b, 0x31])

  // 异或自逆
  const back = xorBytes({
    data: byString.hex,
    dataEncoding: 'hex',
    key: '6b31',
    keyEncoding: 'hex',
    outputEncoding: 'utf8',
  })
  assert.equal(back.output, plain)
})

test('XOR：由明文与密文反推密钥，并折叠出最短周期', () => {
  const recovered = xorRecoverKey({
    plaintext: 'aaaaaaaa',
    ciphertext: encodeHex(
      new Uint8Array([...'aaaaaaaa'].map((char, index) => char.charCodeAt(0) ^ [7, 9][index % 2])),
    ),
    ciphertextEncoding: 'hex',
  })
  assert.deepEqual(recovered.keyBytes, [7, 9])
  assert.equal(recovered.period, 2)
})

test('XOR：单字节爆破能定位正确答案', () => {
  const plain = 'the quick brown fox jumps over the lazy dog'
  const key = 0x5a
  const cipher = new Uint8Array([...plain].map((char) => char.charCodeAt(0) ^ key))
  const candidates = xorBruteForce({ data: cipher, dataEncoding: 'latin1', top: 3 })
  assert.equal(candidates[0].key, key)
  assert.equal(candidates[0].preview, plain)
  assert.ok(candidates[0].printableRatio > 0.99)
})

// ---------------------------------------------------------------- RSA / 大数

test('RSA：标准库加解密与签名验签（2048 位现场生成）', () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const pemPublic = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const pemPrivate = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()

  const encrypted = rsaEncrypt({ data: 'secret payload', publicKey: pemPublic })
  const decrypted = rsaDecrypt({
    data: encrypted.data,
    dataEncoding: 'base64',
    privateKey: pemPrivate,
  })
  assert.equal(decrypted.data, 'secret payload')

  const signature = rsaSign({ data: 'msg', privateKey: pemPrivate, hash: 'sha256' })
  assert.equal(
    rsaVerify({ data: 'msg', signature: signature.data, publicKey: pemPublic, hash: 'sha256' }).valid,
    true,
  )
  assert.equal(
    rsaVerify({ data: 'msg!', signature: signature.data, publicKey: pemPublic, hash: 'sha256' }).valid,
    false,
  )

  const info = rsaKeyInfo({ key: pemPublic })
  assert.equal(info.bits, 2048)
  assert.equal(info.exponentHex, '010001')
})

test('RSA：由 n/e 还原公钥，且与原始公钥的模数一致', () => {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const jwk = publicKey.export({ format: 'jwk' })
  const nHex = Buffer.from(jwk.n, 'base64url').toString('hex')
  const eHex = Buffer.from(jwk.e, 'base64url').toString('hex')

  const rebuilt = rsaPublicKeyFromComponents({ n: nHex, e: eHex, inputEncoding: 'hex' })
  assert.equal(rebuilt.modulusHex, nHex)
  assert.equal(rebuilt.bits, 2048)

  const info = rsaKeyInfo({ key: rebuilt.pem })
  assert.equal(info.modulusHex, nHex)
  assert.equal(info.exponentHex, eHex)
})

test('大数：modPow / modInverse / 字节与大整数互转', () => {
  assert.equal(modPow(2n, 10n, 1000n), 24n)
  assert.equal(modPow(4n, 13n, 497n), 445n) // 教科书示例
  assert.equal(modInverse(3n, 11n), 4n)
  assert.equal((3n * modInverse(3n, 11n)) % 11n, 1n)

  const bytes = new Uint8Array([0x01, 0x00, 0xff])
  assert.equal(bytesToBigInt(bytes), 0x0100ffn)
  assert.deepEqual([...bigIntToBytes(0x0100ffn, 3)], [...bytes])
  assert.deepEqual([...bigIntToBytes(0x01n, 4)], [0, 0, 0, 1]) // 定长补齐

  assert.equal(parseBigIntLiteral('0x10').value, 16n)
  assert.equal(parseBigIntLiteral('16').value, 16n)
  expectCode(() => parseBigIntLiteral('不是数字'), 'INVALID_INPUT', '非法大数字面量')
})

test('RSA：手写大数路径与标准库结果一致（混淆代码常见写法）', () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 })
  const jwkPub = publicKey.export({ format: 'jwk' })
  const jwkPriv = privateKey.export({ format: 'jwk' })
  const nHex = Buffer.from(jwkPub.n, 'base64url').toString('hex')
  const eHex = Buffer.from(jwkPub.e, 'base64url').toString('hex')
  const dHex = Buffer.from(jwkPriv.d, 'base64url').toString('hex')

  const message = 'hi'
  const mHex = Buffer.from(message, 'utf8').toString('hex')

  // c = m^e mod n
  const encrypted = rsaManualPow({
    value: mHex,
    inputEncoding: 'hex',
    exponent: eHex,
    exponentEncoding: 'hex',
    modulus: nHex,
    modulusEncoding: 'hex',
  })

  // m = c^d mod n
  const decrypted = rsaManualPow({
    value: encrypted.resultHex,
    inputEncoding: 'hex',
    exponent: dHex,
    exponentEncoding: 'hex',
    modulus: nHex,
    modulusEncoding: 'hex',
  })
  // 定长输出会带前导零字节，去掉后再比对原文
  assert.equal(
    Buffer.from(decrypted.resultHex, 'hex').toString('utf8').replace(/^\u0000+/u, ''),
    message,
  )
  assert.equal(encrypted.bits, 1024)
})
