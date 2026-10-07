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

import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import {
  type ByteInput,
  type TextEncoding,
  asBytes,
  assertNonEmpty,
  encodeHex,
  fromBytes,
} from './encoding.js'
import { ReverseError, assertReverse } from './errors.js'

/** 支持的 AES 分组模式。 */
export type AesMode = 'cbc' | 'ecb' | 'ctr' | 'cfb' | 'ofb' | 'gcm'

/** 填充方式。流式模式（ctr/cfb/ofb/gcm）恒为 `none`。 */
export type AesPadding = 'pkcs7' | 'none'

/**
 * EVP_BytesToKey 可用的摘要算法。
 *
 * 比 RSA 的摘要集合少一个 `sha384`：OpenSSL 的 evp 派生只用到这四种，
 * 单独定义类型可以让「传了不支持的摘要」在编译期就被挡住。
 */
export type KdfHash = 'md5' | 'sha1' | 'sha256' | 'sha512'

/** 块模式（需要 PKCS7 填充的那几种）。 */
const BLOCK_MODES: readonly AesMode[] = ['cbc', 'ecb']

/** 流式模式（无填充）。 */
const STREAM_MODES: readonly AesMode[] = ['ctr', 'cfb', 'ofb', 'gcm']

/** 全部模式。 */
const ALL_MODES: readonly AesMode[] = [...BLOCK_MODES, ...STREAM_MODES]

/** OpenSSL/CryptoJS 的魔法前缀。 */
const SALTED_PREFIX = Buffer.from('Salted__', 'latin1')

/** AES 参数。 */
export interface AesParams {
  /** 待处理数据（明文或密文）。 */
  data: ByteInput
  /** `data` 为字符串时的编码。加密默认 `utf8`，解密默认 `base64`。 */
  dataEncoding?: TextEncoding
  /** 原始密钥；与 `passphrase` 二选一。 */
  key?: ByteInput
  /** 密钥为字符串时的编码，默认 `utf8`。 */
  keyEncoding?: TextEncoding
  /** 初始化向量；cbc/ctr/cfb/ofb/gcm 必填，ecb 必须不填。 */
  iv?: ByteInput
  /** IV 为字符串时的编码，默认 `utf8`。 */
  ivEncoding?: TextEncoding
  /** 口令；给了它就走 EVP_BytesToKey 派生 key/iv。 */
  passphrase?: string
  /** 派生时使用的 salt；缺省时加密会随机生成，解密则必须提供。 */
  salt?: ByteInput
  /** salt 为字符串时的编码，默认 `utf8`。 */
  saltEncoding?: TextEncoding
  /** 派生摘要算法，默认 `md5`（CryptoJS 默认）。 */
  kdfHash?: KdfHash
  /** 派生出的密钥字节长度，默认 32（AES-256）。 */
  keyLength?: 16 | 24 | 32
  /** 分组模式，默认 `cbc`。 */
  mode?: AesMode
  /** 填充方式，默认 `pkcs7`；流式模式会被强制为 `none`。 */
  padding?: AesPadding
  /** GCM 认证标签（解密必填）。 */
  authTag?: ByteInput
  /** 认证标签为字符串时的编码，默认 `hex`。 */
  authTagEncoding?: TextEncoding
  /** 输出编码。加密默认 `base64`，解密默认 `utf8`。 */
  outputEncoding?: TextEncoding
}

/** 加密结果。 */
export interface AesEncryptResult {
  /** 密文（按输出编码）。 */
  ciphertext: string
  /** 密文 hex（便于比对）。 */
  ciphertextHex: string
  /** GCM 认证标签（hex）。 */
  authTag?: string
  /** OpenSSL 格式下实际使用的 salt（hex）。 */
  salt?: string
  /** 派生出的密钥（hex），仅在使用了 passphrase 时给出。 */
  derivedKey?: string
  /** 派生出的 IV（hex），仅在使用了 passphrase 时给出。 */
  derivedIv?: string
  /** 实际使用的 Node 算法名，如 `aes-256-cbc`。 */
  algorithm: string
  /** 分组模式。 */
  mode: AesMode
  /** 密钥位数。 */
  keyLength: number
  /** 实际生效的填充。 */
  padding: AesPadding
  /** 输出编码。 */
  outputEncoding: TextEncoding
  /** 明文字节数。 */
  plaintextLength: number
}

/** 解密结果。 */
export interface AesDecryptResult {
  /** 明文（按输出编码）。 */
  plaintext: string
  /** 明文 hex。 */
  plaintextHex: string
  /** 明文 utf8 预览（非法字节会被替换，仅供肉眼参考）。 */
  preview: string
  /** 实际使用的 Node 算法名。 */
  algorithm: string
  /** 分组模式。 */
  mode: AesMode
  /** 密钥位数。 */
  keyLength: number
  /** 实际生效的填充。 */
  padding: AesPadding
  /** 明文字节数。 */
  plaintextLength: number
  /** 输出编码。 */
  outputEncoding: TextEncoding
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
export function evpBytesToKey(
  passphrase: Uint8Array,
  salt: Uint8Array,
  keyLength: number,
  ivLength: number,
  digest: KdfHash = 'md5',
): { key: Uint8Array; iv: Uint8Array } {
  const need = keyLength + ivLength
  const chunks: Buffer[] = []
  let previous = Buffer.alloc(0)
  let produced = 0
  while (produced < need) {
    const hasher = createHash(digest)
    hasher.update(previous)
    hasher.update(Buffer.from(passphrase))
    hasher.update(Buffer.from(salt))
    const block = hasher.digest()
    chunks.push(block)
    previous = block
    produced += block.length
  }
  const material = Buffer.concat(chunks)
  return {
    key: new Uint8Array(material.subarray(0, keyLength)),
    iv: new Uint8Array(material.subarray(keyLength, keyLength + ivLength)),
  }
}

/**
 * 由密钥长度推出 Node 的算法名。
 *
 * @param keyLength - 密钥字节数。
 * @param mode - 分组模式。
 * @returns 形如 `aes-256-cbc` 的算法名。
 */
function algorithmName(keyLength: number, mode: AesMode): string {
  const bits = keyLength * 8
  assertReverse(
    bits === 128 || bits === 192 || bits === 256,
    `AES 密钥长度必须是 16/24/32 字节，当前 ${keyLength} 字节（${bits} 位）`,
    'KEY_MISMATCH',
  )
  return `aes-${bits}-${mode}`
}

/**
 * 解析模式名。
 *
 * @param mode - 待校验的模式。
 * @returns 合法模式。
 */
function assertMode(mode: string): AesMode {
  assertReverse(
    (ALL_MODES as readonly string[]).includes(mode),
    `不支持的 AES 模式 "${mode}"，可用：${ALL_MODES.join(' / ')}`,
    'UNSUPPORTED_ALGORITHM',
  )
  return mode as AesMode
}

/**
 * 把参数里的 key/iv 解析出来（必要时走口令派生）。
 *
 * @param params - AES 参数。
 * @param allowedIvLengths - 该模式接受的手工 IV 长度集合（空集表示 ECB）。
 * @returns 解析结果，含诊断字段。
 */
function resolveKeyMaterial(
  params: AesParams,
  allowedIvLengths: readonly number[],
): { key: Uint8Array; iv: Uint8Array | null; salt?: Uint8Array; derived: boolean } {
  const mode = assertMode(params.mode ?? 'cbc')
  if (params.passphrase !== undefined) {
    const keyLength = params.keyLength ?? 32
    const salt = params.salt
      ? asBytes(params.salt, params.saltEncoding ?? 'utf8')
      : new Uint8Array(0)
    const { key, iv } = evpBytesToKey(
      new Uint8Array(Buffer.from(params.passphrase, 'utf8')),
      salt,
      keyLength,
      mode === 'ecb' ? 0 : DERIVED_IV_LENGTH,
      params.kdfHash ?? 'md5',
    )
    return { key, iv: mode === 'ecb' ? null : iv, salt, derived: true }
  }
  assertReverse(
    params.key !== undefined,
    '缺少密钥：请提供 key（原始密钥）或 passphrase（口令）',
    'INVALID_INPUT',
  )
  const key = asBytes(params.key, params.keyEncoding ?? 'utf8')
  assertNonEmpty(key, '密钥')
  const iv =
    params.iv === undefined ? null : asBytes(params.iv, params.ivEncoding ?? 'utf8')
  if (mode === 'ecb') {
    assertReverse(
      iv === null,
      'ECB 模式不需要 IV：请去掉 iv 参数（CryptoJS 在 ECB 下也会忽略 IV）',
      'INVALID_INPUT',
    )
  } else {
    assertReverse(
      iv !== null,
      `${mode.toUpperCase()} 模式需要 IV；若原始代码用口令，请改用 passphrase 参数`,
      'INVALID_INPUT',
    )
    assertReverse(
      allowedIvLengths.includes(iv.length),
      `${mode.toUpperCase()} 模式的 IV 长度应为 ${allowedIvLengths.join(' 或 ')} 字节，当前 ${iv.length} 字节`,
      'KEY_MISMATCH',
    )
  }
  return { key, iv, derived: false }
}

/** 每种模式接受的手工 IV 长度；ECB 不接受 IV。GCM 常见 12 字节，也见 16 字节。 */
const IV_LENGTH: Readonly<Record<AesMode, readonly number[]>> = {
  cbc: [16],
  ecb: [],
  ctr: [16],
  cfb: [16],
  ofb: [16],
  gcm: [12, 16],
}

/**
 * EVP_BytesToKey 派生 IV 的长度。
 *
 * 注意与手工 IV 的区别：OpenSSL 的 KDF 恒按 AES 分组大小（16 字节）派生 IV，
 * 与最终使用哪种模式无关。GCM 下就是「派生 16 字节 IV」。
 */
const DERIVED_IV_LENGTH = 16

/**
 * PKCS#7 填充。
 *
 * @param bytes - 原始字节。
 * @param blockSize - 块大小，默认 16。
 * @returns 填充后的字节。
 */
export function pkcs7Pad(bytes: Uint8Array, blockSize = 16): Uint8Array {
  const pad = blockSize - (bytes.length % blockSize)
  const out = new Uint8Array(bytes.length + pad)
  out.set(bytes, 0)
  out.fill(pad, bytes.length)
  return out
}

/**
 * PKCS#7 去填充。填充非法时抛错——这通常意味着密钥或 IV 是错的，
 * 静默返回垃圾数据会让排查方向彻底跑偏。
 *
 * @param bytes - 含填充的字节。
 * @param blockSize - 块大小，默认 16。
 * @returns 去填充后的字节。
 */
export function pkcs7Unpad(bytes: Uint8Array, blockSize = 16): Uint8Array {
  assertNonEmpty(bytes, '去填充输入')
  const pad = bytes[bytes.length - 1] ?? 0
  assertReverse(
    pad >= 1 && pad <= blockSize && pad <= bytes.length,
    `PKCS7 填充非法（末字节 ${pad}）：密钥/IV/模式很可能不对`,
    'DECRYPT_FAILED',
  )
  for (let i = bytes.length - pad; i < bytes.length; i += 1) {
    assertReverse(
      bytes[i] === pad,
      'PKCS7 填充字节不一致：密钥/IV/模式很可能不对',
      'DECRYPT_FAILED',
    )
  }
  return bytes.subarray(0, bytes.length - pad)
}

/**
 * AES 加密。
 *
 * @param params - 加密参数。
 * @returns 密文与诊断信息。
 */
export function aesEncrypt(params: AesParams): AesEncryptResult {
  const mode = assertMode(params.mode ?? 'cbc')
  const isBlock = BLOCK_MODES.includes(mode)
  const padding: AesPadding = isBlock ? (params.padding ?? 'pkcs7') : 'none'
  const { key, iv, salt, derived } = resolveKeyMaterial(params, IV_LENGTH[mode])
  const algorithm = algorithmName(key.length, mode)

  const plain = asBytes(params.data, params.dataEncoding ?? 'utf8')
  assertNonEmpty(plain, '明文')

  const cipher = createCipheriv(algorithm, key, mode === 'ecb' ? null : iv)
  if (isBlock) cipher.setAutoPadding(padding === 'pkcs7')
  const body = Buffer.concat([cipher.update(Buffer.from(plain)), cipher.final()])
  const authTag = mode === 'gcm' ? (cipher as unknown as { getAuthTag(): Buffer }).getAuthTag() : undefined
  const outputEncoding = params.outputEncoding ?? 'base64'

  const result: AesEncryptResult = {
    ciphertext: fromBytes(new Uint8Array(body), outputEncoding),
    ciphertextHex: encodeHex(new Uint8Array(body)),
    algorithm,
    mode,
    keyLength: key.length,
    padding,
    outputEncoding,
    plaintextLength: plain.length,
  }
  if (authTag) result.authTag = authTag.toString('hex')
  if (salt && salt.length > 0) result.salt = encodeHex(salt)
  if (derived) {
    result.derivedKey = encodeHex(key)
    result.derivedIv = iv ? encodeHex(iv) : undefined
  }
  return result
}

/**
 * AES 解密。
 *
 * @param params - 解密参数。
 * @returns 明文与诊断信息。
 */
export function aesDecrypt(params: AesParams): AesDecryptResult {
  const mode = assertMode(params.mode ?? 'cbc')
  const isBlock = BLOCK_MODES.includes(mode)
  const padding: AesPadding = isBlock ? (params.padding ?? 'pkcs7') : 'none'
  const { key, iv } = resolveKeyMaterial(params, IV_LENGTH[mode])
  const algorithm = algorithmName(key.length, mode)

  const cipherBytes = asBytes(params.data, params.dataEncoding ?? 'base64')
  assertNonEmpty(cipherBytes, '密文')

  const decipher = createDecipheriv(algorithm, key, mode === 'ecb' ? null : iv)
  if (isBlock) decipher.setAutoPadding(padding === 'pkcs7')
  if (mode === 'gcm') {
    assertReverse(
      params.authTag !== undefined,
      'GCM 解密需要 authTag（加密时返回的认证标签）',
      'INVALID_INPUT',
    )
    const tag = asBytes(params.authTag, params.authTagEncoding ?? 'hex')
    ;(decipher as unknown as { setAuthTag(tag: Buffer): void }).setAuthTag(Buffer.from(tag))
  }

  let plain: Buffer
  try {
    plain = Buffer.concat([decipher.update(Buffer.from(cipherBytes)), decipher.final()])
  } catch (error) {
    throw new ReverseError(
      `AES 解密失败：${error instanceof Error ? error.message : String(error)}。` +
        '常见原因：key/iv 编码解释错误（hex 当成了 utf8）、模式或填充不匹配、密文本身被截断。',
      'DECRYPT_FAILED',
    )
  }

  const outputEncoding = params.outputEncoding ?? 'utf8'
  const plainBytes = new Uint8Array(plain)
  return {
    plaintext: fromBytes(plainBytes, outputEncoding),
    plaintextHex: encodeHex(plainBytes),
    preview: plain.toString('utf8').replace(/[\u0000-\u001f]/gu, '·'),
    algorithm,
    mode,
    keyLength: key.length,
    padding,
    plaintextLength: plainBytes.length,
    outputEncoding,
  }
}

/**
 * 解析（或构造）OpenSSL `Salted__` 格式：`"Salted__" || salt(8) || ciphertext`。
 *
 * @param blob - 完整字节。
 * @returns 拆出的 salt 与密文。
 */
function splitSalted(blob: Uint8Array): { salt: Uint8Array; body: Uint8Array } {
  assertReverse(
    blob.length > 16,
    `密文太短（${blob.length} 字节），不可能是 OpenSSL/CryptoJS 的 Salted 格式`,
    'INVALID_INPUT',
  )
  const header = Buffer.from(blob.subarray(0, 8)).toString('latin1')
  assertReverse(
    header === 'Salted__',
    `密文没有 "Salted__" 前缀（实际前 8 字节为 ${JSON.stringify(header)}）。` +
      '若你的密文是纯 CBC 结果，请改用 aes_decrypt 并显式给出 key 与 iv。',
    'INVALID_INPUT',
  )
  return { salt: blob.subarray(8, 16), body: blob.subarray(16) }
}

/**
 * 解密 OpenSSL/CryptoJS 风格的 `Salted__` 密文。
 *
 * 这是抓包/抠码后最常见的一块：`CryptoJS.AES.encrypt(plain, '口令').toString()`
 * 的产物就是 base64 的 `Salted__` 格式。
 *
 * @param params - 密文与口令。
 * @returns 解密结果（沿用 {@link aesDecrypt} 的字段）。
 */
export function opensslDecrypt(params: {
  data: ByteInput
  dataEncoding?: TextEncoding
  passphrase: string
  kdfHash?: KdfHash
  keyLength?: 16 | 24 | 32
  mode?: Extract<AesMode, 'cbc' | 'ecb' | 'ctr'> | AesMode
  outputEncoding?: TextEncoding
}): AesDecryptResult {
  const blob = asBytes(params.data, params.dataEncoding ?? 'base64')
  const { salt, body } = splitSalted(blob)
  return aesDecrypt({
    data: body,
    dataEncoding: 'hex',
    passphrase: params.passphrase,
    salt,
    saltEncoding: 'hex',
    kdfHash: params.kdfHash ?? 'md5',
    keyLength: params.keyLength ?? 32,
    mode: params.mode ?? 'cbc',
    outputEncoding: params.outputEncoding ?? 'utf8',
  })
}

/**
 * 生成 OpenSSL/CryptoJS 风格的 `Salted__` 密文。
 *
 * 存在的意义是**闭环验证**：能解开线上密文，也能造出同格式密文来确认自己的实现
 * 与目标一致，而不是只靠「看起来像明文」判断。
 *
 * @param params - 明文与口令。
 * @returns 完整的 base64 密文与派生信息。
 */
export function opensslEncrypt(params: {
  data: ByteInput
  dataEncoding?: TextEncoding
  passphrase: string
  kdfHash?: KdfHash
  keyLength?: 16 | 24 | 32
  mode?: AesMode
  salt?: Uint8Array
  outputEncoding?: TextEncoding
}): AesEncryptResult & { blob: string } {
  const salt = params.salt ?? new Uint8Array(randomBytes(8))
  const enc = aesEncrypt({
    data: params.data,
    dataEncoding: params.dataEncoding ?? 'utf8',
    passphrase: params.passphrase,
    salt,
    saltEncoding: 'hex',
    kdfHash: params.kdfHash ?? 'md5',
    keyLength: params.keyLength ?? 32,
    mode: params.mode ?? 'cbc',
    outputEncoding: 'hex',
  })
  const body = Buffer.from(enc.ciphertextHex, 'hex')
  const blob = Buffer.concat([SALTED_PREFIX, Buffer.from(salt), body])
  const outputEncoding = params.outputEncoding ?? 'base64'
  return { ...enc, blob: fromBytes(new Uint8Array(blob), outputEncoding), outputEncoding }
}
