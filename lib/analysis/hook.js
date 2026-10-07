/**
 * Hook 脚本生成（辅助定位路线）。
 *
 * ## 定位
 *
 * 明确一点：Hook 脚本**只用于调试与取证**——在你自己有权分析的页面里观察
 * 「哪个函数被调用、入参是什么、返回值是什么」，从而定位加密入口。它不产出可交付的
 * 纯算代码；那条路由 {@link ../analysis/extract} 负责。
 *
 * ## 为什么生成的不是一段「裸 wrap」
 *
 * 真实网站上直接 wrap 一个方法，经常会遇到两件事：
 *   1. 目标把 `window` 上的方法引用提前缓存了（`var _e = window.encrypt`），
 *      只替换 `window.encrypt` 抓不到调用；
 *   2. 目标用 `Function.prototype.toString` 校验「函数有没有被改过」。
 *
 * 所以生成物包含：**多路径覆盖**（同时挂到缓存别名与原型上）、**调用栈记录**
 * （用来反推是谁调用了加密函数，这才是定位入口的关键信息）、以及可选的
 * `toString` 伪装。这些都是浏览器调试器里公开可见、日常排查手段的一部分。
 *
 * 生成物是一个自包含 IIFE，不依赖任何库，可直接粘进 DevTools 控制台。
 */
/** 默认预设。 */
const DEFAULT_PRESETS = ['webcrypto', 'cryptojs', 'jsencrypt', 'encoding'];
/**
 * 生成浏览器可用的 Hook 脚本。
 *
 * 生成物内部刻意只用字符串拼接、不使用模板字符串，这样外层 TypeScript 模板里
 * 不必出现转义地狱，生成的代码也更容易人工审阅。
 *
 * @param options - 生成选项。
 * @returns 脚本与说明。
 */
export function generateHookScript(options = {}) {
    const autoDiscover = options.autoDiscover ?? true;
    const includeNetwork = options.includeNetwork ?? true;
    const stealth = options.stealth ?? true;
    const maxValueLength = options.maxValueLength ?? 500;
    const logLimit = options.logLimit ?? 2000;
    const presets = options.presets ?? DEFAULT_PRESETS;
    const explicit = [...(options.targets ?? [])];
    const config = {
        autoDiscover,
        includeNetwork,
        stealth,
        maxValueLength,
        logLimit,
        presets: [...presets],
        targets: explicit,
    };
    const plannedTargets = [
        ...(presets.includes('webcrypto') ? ['crypto.subtle.*'] : []),
        ...(presets.includes('cryptojs') ? ['CryptoJS.*'] : []),
        ...(presets.includes('jsencrypt') ? ['JSEncrypt.prototype.*'] : []),
        ...(presets.includes('encoding') ? ['btoa / atob'] : []),
        ...(includeNetwork ? ['XMLHttpRequest.prototype.*', 'fetch', 'WebSocket.prototype.send'] : []),
        ...(autoDiscover ? ['<自动发现：window 上名字含 sign/encrypt/token/hmac… 的函数>'] : []),
        ...explicit.map((target) => `${target.object}.${target.method}`),
    ];
    const script = `/* ============================================================================
 * DSH 逆向工具包 —— 函数 Hook 脚本（仅用于调试取证）
 *
 * 用途：在你有权分析的页面里，观察指定函数的入参、返回值与调用栈，
 *       用来定位加密/签名入口，以及确认「哪一个函数真正在做运算」。
 *
 * 使用方式（任选其一）：
 *   A. DevTools 控制台直接粘贴执行
 *   B. DevTools → Sources → Snippets → 新建 → 粘贴 → 右键 Run
 *      （Snippets 便于反复执行与版本管理）
 *   C. 需要在页面 JS 执行之前就生效时，用 CDP：
 *      Page.addScriptToEvaluateOnNewDocument({ source: <本脚本> })
 *
 * 执行后：
 *   __revHook.dump()   在控制台查看已捕获记录
 *   __revHook.save()   下载为 JSON 文件
 *   __revHook.clear()  清空记录
 *   __revHook.unhook() 还原所有被替换的方法
 * ========================================================================== */
(function () {
  'use strict'

  var CONFIG = ${JSON.stringify(config, null, 2)}

  if (window.__revHook && window.__revHook.__installed) {
    console.warn('[revHook] 已经安装过一次，先执行 __revHook.unhook() 再重跑以避免重复包装')
    return
  }

  /** 已捕获的记录。 */
  var records = []
  /** 被替换过的方法，用于还原。 */
  var patches = []

  /** 把任意值序列化成可读、可 JSON 化的形式。 */
  function serialize(value, depth) {
    depth = depth || 0
    try {
      if (value === null) return null
      if (value === undefined) return 'undefined'
      var type = typeof value
      if (type === 'string') {
        return value.length > CONFIG.maxValueLength
          ? value.slice(0, CONFIG.maxValueLength) + '…(+' + (value.length - CONFIG.maxValueLength) + ')'
          : value
      }
      if (type === 'number' || type === 'boolean') return value
      if (type === 'function') return '[function ' + (value.name || 'anonymous') + ']'
      if (type === 'symbol') return String(value)
      if (type === 'bigint') return value.toString() + 'n'
      if (depth > 3) return '[depth-limit]'

      // 二进制：转 hex —— 加解密链路上最需要看清的就是这些字节
      if (value instanceof ArrayBuffer) {
        var whole = new Uint8Array(value)
        return { __type: 'ArrayBuffer', byteLength: whole.length, hex: toHex(whole) }
      }
      if (ArrayBuffer.isView(value)) {
        return {
          __type: value.constructor ? value.constructor.name : 'TypedArray',
          byteLength: value.byteLength,
          hex: toHex(new Uint8Array(value.buffer, value.byteOffset, value.byteLength)),
        }
      }
      if (Array.isArray(value)) {
        return value.slice(0, 64).map(function (item) { return serialize(item, depth + 1) })
      }
      if (value instanceof Date) return value.toISOString()
      if (value instanceof Error) return { name: value.name, message: value.message }

      // 对象：只取自有可枚举属性，避免把原型链拉爆
      var out = {}
      var keys = Object.keys(value).slice(0, 64)
      for (var i = 0; i < keys.length; i++) {
        out[keys[i]] = serialize(value[keys[i]], depth + 1)
      }
      if (keys.length === 0) {
        var tag = Object.prototype.toString.call(value)
        return '[object ' + tag.slice(8, -1) + ']'
      }
      return out
    } catch (error) {
      return '[serialize-error: ' + (error && error.message) + ']'
    }
  }

  /** 字节数组转 hex。 */
  function toHex(bytes) {
    var hex = ''
    for (var i = 0; i < bytes.length && i < 4096; i++) {
      hex += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16)
    }
    if (bytes.length > 4096) hex += '…(+' + (bytes.length - 4096) + ' bytes)'
    return hex
  }

  /** 取调用栈中属于页面自己的那几帧 —— 定位入口靠的就是它。 */
  function captureStack() {
    var stack = new Error().stack
    if (!stack) return []
    return stack
      .split('\\n')
      .slice(2, 12)
      .map(function (line) { return line.trim() })
      .filter(function (line) { return line.indexOf('revHook') === -1 })
  }

  /** 写入一条记录。 */
  function record(entry) {
    entry.time = Date.now()
    entry.stack = captureStack()
    records.push(entry)
    if (records.length > CONFIG.logLimit) records.shift()
    try {
      console.groupCollapsed('%c[revHook] ' + entry.label, 'color:#0a0;font-weight:bold')
      console.log('阶段:', entry.phase)
      if (entry.args) console.log('入参:', entry.args)
      if (entry.result !== undefined) console.log('返回:', entry.result)
      if (entry.error) console.error('抛出:', entry.error)
      console.log('调用栈:', entry.stack.join('\\n'))
      console.groupEnd()
    } catch (ignored) { /* 控制台不可用时静默 */ }
  }

  /** 解析 'a.b.c' 形式的路径。 */
  function resolvePath(path) {
    var parts = String(path).split('.')
    var current = window
    for (var i = 0; i < parts.length; i++) {
      if (current == null) return null
      current = current[parts[i]]
    }
    return current
  }

  /**
   * 包装一个方法。
   * 关键点：保留 this 与返回/抛出的原样语义，包装只是「顺便记录」。
   */
  function wrapMethod(owner, key, label, opts) {
    opts = opts || {}
    if (!owner) return false
    var original
    try { original = owner[key] } catch (error) { return false }
    if (typeof original !== 'function') return false
    if (original.__revHookWrapped) return false

    var wrapped = function () {
      var args = Array.prototype.slice.call(arguments).map(function (arg) { return serialize(arg, 0) })
      var callId = records.length
      record({ label: label, phase: '调用', args: args })
      var result
      try {
        result = original.apply(this, arguments)
      } catch (error) {
        record({
          label: label,
          phase: '抛出',
          args: args,
          error: { name: error && error.name, message: error && error.message },
        })
        throw error
      }
      // Promise 也要看结果
      if (result && typeof result.then === 'function') {
        return result.then(function (resolved) {
          record({ label: label, phase: '返回(Promise)', args: args, result: serialize(resolved, 0) })
          return resolved
        }, function (rejected) {
          record({
            label: label,
            phase: '拒绝(Promise)',
            args: args,
            error: { name: rejected && rejected.name, message: rejected && rejected.message },
          })
          return Promise.reject(rejected)
        })
      }
      record({ label: label, phase: '返回', args: args, result: serialize(result, 0) })
      return result
    }

    wrapped.__revHookWrapped = true
    wrapped.__revHookOriginal = original
    // toString 伪装：让「函数有没有被改过」这类校验看到原来的源码
    if (CONFIG.stealth) {
      try {
        Object.defineProperty(wrapped, 'toString', {
          value: function () { return original.toString() },
          configurable: true,
        })
      } catch (ignored) { /* 某些环境不允许改写，忽略 */ }
    }

    try {
      owner[key] = wrapped
      patches.push({ owner: owner, key: key, original: original })
      return true
    } catch (error) {
      return false
    }
  }

  /** 找到某方法所在的对象（用于挂到原型上而不是实例上）。 */
  function prototypeOf(path, ctorName) {
    var ctor = resolvePath(path)
    return ctor && ctor.prototype ? ctor.prototype : null
  }

  // ---------------------------------------------------------------- 预设

  var installed = []

  /** WebCrypto：浏览器原生加密 API，签名链路的第一站。 */
  if (CONFIG.presets.indexOf('webcrypto') !== -1) {
    var subtle = resolvePath('crypto.subtle')
    if (subtle) {
      var subtleMethods = ['encrypt', 'decrypt', 'digest', 'sign', 'verify', 'importKey', 'exportKey', 'deriveKey', 'deriveBits', 'generateKey', 'wrapKey', 'unwrapKey']
      for (var i = 0; i < subtleMethods.length; i++) {
        if (wrapMethod(subtle, subtleMethods[i], 'crypto.subtle.' + subtleMethods[i])) {
          installed.push('crypto.subtle.' + subtleMethods[i])
        }
      }
    } else {
      console.warn('[revHook] 未找到 crypto.subtle（需要 HTTPS 或 localhost 上下文）')
    }
  }

  /** CryptoJS：前端最常用的第三方加密库。 */
  if (CONFIG.presets.indexOf('cryptojs') !== -1) {
    var CryptoJS = resolvePath('CryptoJS')
    if (CryptoJS) {
      var cjsTargets = [
        ['AES', ['encrypt', 'decrypt']],
        ['DES', ['encrypt', 'decrypt']],
        ['TripleDES', ['encrypt', 'decrypt']],
        ['RC4', ['encrypt', 'decrypt']],
        ['Rabbit', ['encrypt', 'decrypt']],
        ['MD5', null],
        ['SHA1', null],
        ['SHA224', null],
        ['SHA256', null],
        ['SHA384', null],
        ['SHA512', null],
        ['SHA3', null],
        ['RIPEMD160', null],
        ['HmacMD5', null],
        ['HmacSHA1', null],
        ['HmacSHA256', null],
        ['HmacSHA512', null],
        ['PBKDF2', null],
        ['EvpKDF', null],
      ]
      for (var j = 0; j < cjsTargets.length; j++) {
        var groupName = cjsTargets[j][0]
        var group = CryptoJS[groupName]
        if (!group) continue
        if (cjsTargets[j][1]) {
          for (var k = 0; k < cjsTargets[j][1].length; k++) {
            var method = cjsTargets[j][1][k]
            if (wrapMethod(group, method, 'CryptoJS.' + groupName + '.' + method)) {
              installed.push('CryptoJS.' + groupName + '.' + method)
            }
          }
        } else if (typeof group === 'function' && wrapMethod(CryptoJS, groupName, 'CryptoJS.' + groupName)) {
          installed.push('CryptoJS.' + groupName)
        }
      }
      // 编码层：Base64/Hex 的进出往往就是密文边界
      var enc = CryptoJS.enc
      if (enc) {
        var codecs = ['Base64', 'Hex', 'Utf8', 'Latin1']
        for (var m = 0; m < codecs.length; m++) {
          var codec = enc[codecs[m]]
          if (!codec) continue
          var codecMethods = ['stringify', 'parse']
          for (var n = 0; n < codecMethods.length; n++) {
            if (wrapMethod(codec, codecMethods[n], 'CryptoJS.enc.' + codecs[m] + '.' + codecMethods[n])) {
              installed.push('CryptoJS.enc.' + codecs[m] + '.' + codecMethods[n])
            }
          }
        }
      }
    }
  }

  /** JSEncrypt：RSA 场景最常见。 */
  if (CONFIG.presets.indexOf('jsencrypt') !== -1) {
    var JSEncrypt = resolvePath('JSEncrypt')
    var jsencryptProto = prototypeOf('JSEncrypt')
    if (jsencryptProto) {
      var rsaMethods = ['encrypt', 'decrypt', 'sign', 'verify', 'setPublicKey', 'setPrivateKey', 'setKey', 'getKey']
      for (var p = 0; p < rsaMethods.length; p++) {
        if (wrapMethod(jsencryptProto, rsaMethods[p], 'JSEncrypt.prototype.' + rsaMethods[p])) {
          installed.push('JSEncrypt.prototype.' + rsaMethods[p])
        }
      }
    }
  }

  /** 编解码：确认密文边界最直接的手段。 */
  if (CONFIG.presets.indexOf('encoding') !== -1) {
    if (wrapMethod(window, 'btoa', 'btoa')) installed.push('btoa')
    if (wrapMethod(window, 'atob', 'atob')) installed.push('atob')
  }

  // ---------------------------------------------------------------- 网络层

  if (CONFIG.includeNetwork) {
    var xhrProto = resolvePath('XMLHttpRequest.prototype')
    if (xhrProto) {
      if (wrapMethod(xhrProto, 'open', 'XHR.open')) installed.push('XMLHttpRequest.prototype.open')
      if (wrapMethod(xhrProto, 'send', 'XHR.send')) installed.push('XMLHttpRequest.prototype.send')
      if (wrapMethod(xhrProto, 'setRequestHeader', 'XHR.setRequestHeader')) installed.push('XMLHttpRequest.prototype.setRequestHeader')
    }
    if (wrapMethod(window, 'fetch', 'fetch')) installed.push('fetch')
    var wsProto = resolvePath('WebSocket.prototype')
    if (wsProto && wrapMethod(wsProto, 'send', 'WebSocket.send')) installed.push('WebSocket.prototype.send')
    if (wrapMethod(window.navigator, 'sendBeacon', 'navigator.sendBeacon')) installed.push('navigator.sendBeacon')
  }

  // ---------------------------------------------------------------- 自动发现

  if (CONFIG.autoDiscover) {
    var HINT = /(sign|encrypt|decrypt|token|hmac|digest|hash|secret|aes|rsa|md5|sha1|sha256|cipher|nonce|makekey|genkey)/i
    var discovered = 0
    var ownKeys = []
    try { ownKeys = Object.keys(window) } catch (ignored) { ownKeys = [] }
    for (var q = 0; q < ownKeys.length; q++) {
      var key = ownKeys[q]
      if (!HINT.test(key)) continue
      var value
      try { value = window[key] } catch (ignored) { continue }
      if (typeof value !== 'function') continue
      // 只认页面自己定义的：原生函数的 toString 含 [native code]
      try {
        if (/\\[native code\\]/.test(Function.prototype.toString.call(value))) continue
      } catch (ignored) { /* 取不到就当自定义处理 */ }
      if (wrapMethod(window, key, 'window.' + key)) {
        installed.push('window.' + key)
        discovered++
      }
    }
    if (discovered > 0) console.info('[revHook] 自动发现并挂钩 ' + discovered + ' 个可疑函数')
  }

  // ---------------------------------------------------------------- 显式目标

  for (var t = 0; t < CONFIG.targets.length; t++) {
    var target = CONFIG.targets[t]
    var owner = resolvePath(target.object)
    var label = target.label || (target.object + '.' + target.method)
    if (wrapMethod(owner, target.method, label)) installed.push(label)
    else console.warn('[revHook] 挂接失败（对象或方法不存在）: ' + label)
  }

  // ---------------------------------------------------------------- 对外接口

  window.__revHook = {
    __installed: true,
    config: CONFIG,
    installed: installed,
    dump: function () {
      console.table(records.map(function (item) {
        return { label: item.label, phase: item.phase, time: new Date(item.time).toISOString() }
      }))
      return records
    },
    save: function (filename) {
      var blob = new Blob([JSON.stringify(records, null, 2)], { type: 'application/json' })
      var url = URL.createObjectURL(blob)
      var anchor = document.createElement('a')
      anchor.href = url
      anchor.download = filename || 'revhook-' + Date.now() + '.json'
      anchor.click()
      setTimeout(function () { URL.revokeObjectURL(url) }, 1000)
      return records.length
    },
    clear: function () { records.length = 0 },
    /** 还原所有被替换的方法，便于对比「有 Hook / 无 Hook」的行为差异。 */
    unhook: function () {
      for (var i = patches.length - 1; i >= 0; i--) {
        try { patches[i].owner[patches[i].key] = patches[i].original } catch (ignored) { /* 忽略 */ }
      }
      patches.length = 0
      window.__revHook.__installed = false
      console.info('[revHook] 已还原 ' + installed.length + ' 个方法')
      return installed.length
    },
  }

  console.info('%c[revHook] 安装完成，共挂钩 ' + installed.length + ' 个目标', 'color:#0a0;font-weight:bold')
  console.info('[revHook] 用法：__revHook.dump() / __revHook.save() / __revHook.clear() / __revHook.unhook()')
  console.info('[revHook] 已挂钩：', installed)
})()
`;
    const usage = [
        'A. DevTools 控制台直接粘贴执行',
        'B. DevTools → Sources → Snippets → 新建 → 粘贴 → 右键 Run（推荐，便于反复执行）',
        'C. 需要在页面脚本执行之前生效时用 CDP：Page.addScriptToEvaluateOnNewDocument({ source: 脚本 })',
        '执行后可用：__revHook.dump() 查看、__revHook.save() 导出 JSON、__revHook.clear() 清空、__revHook.unhook() 还原',
    ];
    const notes = [
        '仅在你自己有权分析的页面使用；Hook 会读取函数的入参与返回值，可能包含凭证类数据。',
        '日志里的「调用栈」是定位加密入口最有效的信息：它能告诉你谁在调用加密函数。',
        '若目标把方法引用提前缓存（如 var e = window.encrypt），需要对该缓存点单独补 Hook，或改用原型层挂接。',
        'stealth 选项会伪装 Function.prototype.toString，用于绕开「检测函数是否被改写」的校验；关闭它则更容易被目标发现。',
        '异步函数（返回 Promise）的结果会在 resolve 之后再记录一条，注意区分「调用」与「返回(Promise)」两条记录。',
        '本脚本不产出可交付的纯算代码；把入口定位出来之后，请用 rev_extract_pure 做静态还原。',
    ];
    return { script, usage, plannedTargets, notes };
}
