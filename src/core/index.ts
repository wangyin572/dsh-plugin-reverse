/**
 * 纯计算核心的统一出口。
 *
 * 这一层的硬约束（也是本插件「静态还原」输出物必须满足的标准）：
 *   - 不引用任何 DOM / BOM 宿主 API（window、document、navigator、canvas…）
 *   - 不做 I/O、不读环境变量、不依赖 DSH 运行时
 *   - 只依赖 Node 内置模块与纯算法
 * 因此它可以被单独复制到任何 Node 环境里直接用：
 *
 * ```js
 * import { aesDecrypt, opensslDecrypt } from './lib/core/index.js'
 * ```
 */

export * from './errors.js'
export * from './encoding.js'
export * from './hash.js'
export * from './aes.js'
export * from './rsa.js'
export * from './xor.js'
