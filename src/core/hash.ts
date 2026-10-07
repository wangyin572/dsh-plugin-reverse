/**
 * 哈希与 HMAC 验算。
 *
 * 全部走 Node 内置 `node:crypto`，算法名在运行时对着 `getHashes()` 校验——不写死
 * 一份可能过期的清单，避免「声称支持但实际编译进 OpenSSL 里没有」这种假承诺。
 */

import { createHash, createHmac, getHashes, timingSafeEqual } from 'node:crypto'
import { ReverseError } from './errors.js'
import {
  type ByteInput,
  type TextEncoding,
  asBytes,
  assertNonEmpty,
  encodeHex,
  fromBytes,
} from './encoding.js'

/** 单次哈希/HMAC 的结果，同时给出请求编码与 hex，方便对照日志里的已知值。 */
export interface DigestResult {
  /** 实际使用的算法名。 */
  algorithm: string
  /** 按请求编码输出的摘要。 */
  digest: string
  /** 摘要的 hex 形式（始终提供，便于肉眼比对）。 */
  hex: string
  /** 摘要字节长度。 */
  length: number
  /** 实际使用的输出编码。 */
  encoding: TextEncoding
}

/** 摘要参数。 */
export interface DigestParams {
  /** 待摘要数据。 */
  data: ByteInput
  /** `data` 为字符串时的编码，默认 `utf8`。 */
  dataEncoding?: TextEncoding
  /** 输出编码，默认 `hex`。 */
  outputEncoding?: TextEncoding
}

/** HMAC 参数。 */
export interface HmacParams extends DigestParams {
  /** 密钥。 */
  key: ByteInput
  /** 密钥为字符串时的编码，默认 `utf8`。 */
  keyEncoding?: TextEncoding
}

/** 运行时可用的哈希算法集合。 */
const AVAILABLE = new Set(getHashes())

/**
 * 校验算法在当前 Node/OpenSSL 上真的可用。
 *
 * @param algorithm - 算法名，如 `md5`、`sha256`。
 * @returns 同一个算法名。
 */
function assertHashAlgorithm(algorithm: string): string {
  const name = algorithm.toLowerCase()
  if (!AVAILABLE.has(name)) {
    throw new ReverseError(
      `当前运行时没有哈希算法 "${algorithm}"。可用的常见值：${[
        'md5',
        'sha1',
        'sha256',
        'sha512',
      ]
        .filter((candidate) => AVAILABLE.has(candidate))
        .join(' / ')}`,
      'UNSUPPORTED_ALGORITHM',
    )
  }
  return name
}

/**
 * 计算摘要。
 *
 * @param algorithm - 算法名。
 * @param params - 数据与编码。
 * @returns 摘要结果。
 */
export function hash(algorithm: string, params: DigestParams): DigestResult {
  const name = assertHashAlgorithm(algorithm)
  const bytes = asBytes(params.data, params.dataEncoding ?? 'utf8')
  const digest = new Uint8Array(createHash(name).update(bytes).digest())
  const encoding = params.outputEncoding ?? 'hex'
  return {
    algorithm: name,
    digest: fromBytes(digest, encoding),
    hex: encodeHex(digest),
    length: digest.length,
    encoding,
  }
}

/**
 * 计算 HMAC。
 *
 * @param algorithm - 底层哈希算法名。
 * @param params - 数据、密钥与编码。
 * @returns 与 {@link hash} 同构的结果。
 */
export function hmac(algorithm: string, params: HmacParams): DigestResult {
  const name = assertHashAlgorithm(algorithm)
  const key = asBytes(params.key, params.keyEncoding ?? 'utf8')
  const bytes = asBytes(params.data, params.dataEncoding ?? 'utf8')
  const digest = new Uint8Array(createHmac(name, key).update(bytes).digest())
  const encoding = params.outputEncoding ?? 'hex'
  return {
    algorithm: `hmac-${name}`,
    digest: fromBytes(digest, encoding),
    hex: encodeHex(digest),
    length: digest.length,
    encoding,
  }
}

/**
 * 定长比较两个字节序列（用于校验签名/摘要是否相等，避免短路比较泄漏长度信息）。
 *
 * @param a - 左操作数。
 * @param b - 右操作数。
 * @returns 是否完全相等。
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  assertNonEmpty(a, '比较左值')
  if (a.length !== b.length) return false
  return timingSafeEqual(Buffer.from(a), Buffer.from(b))
}
