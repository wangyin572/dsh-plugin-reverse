/**
 * 分析层测试：解混淆、宿主识别、闭包抽取、Hook 生成、评估。
 *
 * 这里最关键的一条是 **语义等价测试**：把原始混淆代码放进 `node:vm` 的模拟浏览器里跑，
 * 再把静态还原出来的纯算模块在纯 Node 里跑，断言两者输出**逐字节相同**。
 *
 * 只断言「还原后的代码不报错」是不够的——一段算错了的代码同样不会报错。
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import vm from 'node:vm'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { dirname, join } from 'node:path'

import { parseSource } from '../lib/analysis/ast.js'
import { analyzeHostUsage, generateStubs } from '../lib/analysis/host.js'
import { deobfuscate } from '../lib/analysis/deobfuscate.js'
import { extractPure } from '../lib/analysis/extract.js'
import { generateHookScript } from '../lib/analysis/hook.js'
import { assess, renderAssessment } from '../lib/analysis/assess.js'
import { ReverseError } from '../lib/core/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const SAMPLE = readFileSync(join(here, 'fixtures/obfuscated-sample.js'), 'utf8')

/** 从生成结果里取出某个文件的源码。 */
function moduleFrom(files, name) {
  const file = files.find((item) => item.path === name)
  assert.ok(file, `未生成 ${name}`)
  return file.content
}

/**
 * 把生成的文件真的写到磁盘上，返回可按 ESM 引用的入口 URL。
 *
 * 不能用 `data:` URL：生成物之间用相对路径互相 import（pure.mjs → ./env.mjs），
 * 而 data: URL 没有层级结构，相对导入会解析失败。落盘也正好等价于真实用法
 * ——「独立文件 + node 直接运行」本来就是这个形态。
 */
function materialize(files, name) {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-rev-'))
  for (const file of files) writeFileSync(join(dir, file.path), file.content)
  return { dir, entryUrl: pathToFileURL(join(dir, name)).href }
}

// ---------------------------------------------------------------- 解混淆

test('解混淆：转义还原 / 常量折叠 / 成员访问规范化都是语义等价的', () => {
  const source = `
    var a = "\\x68\\x69";
    var b = '\\u4f60\\u597d';
    var c = !0;
    var d = !1;
    var e = void 0;
    var f = 'ab' + 'cd';
    var g = !![];
    obj['name'] = 1;
    obj['not-valid'] = 2;
  `
  const result = deobfuscate(source)
  assert.match(result.code, /var a = "hi"/)
  assert.match(result.code, /var b = "你好"/)
  assert.match(result.code, /var c = true/)
  assert.match(result.code, /var d = false/)
  assert.match(result.code, /var e = undefined/)
  assert.match(result.code, /var f = "abcd"/)
  assert.match(result.code, /var g = true/)
  // 合法标识符才转点号，带连字符的必须保持方括号
  assert.match(result.code, /obj\.name = 1/)
  assert.match(result.code, /obj\["not-valid"\] = 2/)
  // 回归保护：绝不能出现 obj[name]（字符串键被改成变量引用，语义会变）
  assert.ok(!/obj\[name\]/u.test(result.code), 'obj[\'name\'] 必须变成 obj.name，而不是 obj[name]')
  // 可选链语义必须保留
  const optionalResult = deobfuscate("var v = a?.['b'];")
  assert.match(optionalResult.code, /a\?\.b/)

  // 重写后仍是合法 JS，且行为不变
  const context = { obj: {}, result: undefined }
  vm.createContext(context)
  vm.runInContext(`${result.code}\nresult = [a, b, c, d, e, f, g, obj];`, context)
  assert.deepEqual(
    JSON.parse(JSON.stringify(context.result)),
    ['hi', '你好', true, false, null, 'abcd', true, { name: 1, 'not-valid': 2 }],
  )
})

test('解混淆：识别字符串数组、控制流平坦化、eval 与 debugger', () => {
  const flagged = `
    var _0xabc = ['a','b','c','d','e','f','g','h','i'];
    var i = 0;
    while (!![]) {
      switch (_0xabc[i++]) {
        case '0': continue;
        case '1': continue;
        case '2': continue;
        case '3': continue;
        case '4': continue;
        case '5': continue;
      }
      break;
    }
    debugger;
    eval('1+1');
    new Function('return 1');
  `
  const result = deobfuscate(flagged)
  const kinds = result.findings.map((finding) => finding.kind)
  assert.ok(kinds.includes('string-array'), '应识别字符串数组')
  assert.ok(kinds.includes('control-flow-flattening'), '应识别控制流平坦化')
  assert.ok(kinds.includes('debugger'), '应识别 debugger')
  assert.ok(kinds.includes('eval'), '应识别 eval')
  assert.ok(kinds.includes('function-constructor'), '应识别 new Function')
  assert.equal(result.stats.stringArrayCandidates, 1)
  assert.equal(result.stats.controlFlowFlattening, 1)
  assert.equal(result.stats.dynamicExecution, 2)
  // eval/new Function 属于硬卡点
  assert.ok(result.blockers.some((blocker) => blocker.kind === 'eval'))
  assert.ok(result.obfuscationScore > 0)
})

test('解混淆：rewrite=false 时只分析不改代码', () => {
  const source = 'var a = "\\x41";'
  const result = deobfuscate(source, { rewrite: false })
  assert.equal(result.code, source)
  assert.equal(result.changes.length, 0)
})

// ---------------------------------------------------------------- 宿主识别

test('宿主识别：函数归属正确（嵌套函数不串味）', () => {
  const source = `
    function outer() {
      var a = navigator.userAgent;
      function inner() {
        return document.cookie + location.href;
      }
      window.x = 1;
      return a + inner();
    }
  `
  const { ast, source: text } = parseSource(source)
  const report = analyzeHostUsage(ast, text)
  const byName = new Map(report.references.map((item) => [item.name, item]))

  const navigatorRef = byName.get('navigator')
  assert.ok(navigatorRef)
  assert.equal(navigatorRef.locations[0].enclosing, 'outer')
  assert.ok(navigatorRef.memberPaths.includes('navigator.userAgent'))

  const documentRef = byName.get('document')
  assert.ok(documentRef)
  assert.equal(documentRef.locations[0].enclosing, 'inner', 'document 应归属到 inner 而不是 outer')

  assert.ok(report.mustCapture.includes('navigator'))
  assert.ok(report.mustCapture.includes('document'))
  assert.ok(report.functionScores.some((item) => item.name === 'outer'))
})

test('宿主识别：已声明的同名局部变量不算宿主引用', () => {
  const source = `
    function f(navigator) {
      return navigator.userAgent;
    }
    function g() {
      var document = { cookie: '' };
      return document.cookie;
    }
    function h() {
      return navigator.userAgent;
    }
  `
  const { ast, source: text } = parseSource(source)
  const report = analyzeHostUsage(ast, text)
  // navigator 在 f 里是参数（函数内被遮蔽），但 h 里的 navigator 仍是宿主引用 —— 必须检出
  const nav = report.references.find((item) => item.name === 'navigator')
  assert.ok(nav, 'h() 里的 navigator 应被识别为宿主引用（不能因为 f 的参数而漏检）')
  assert.deepEqual(nav.locations.map((item) => item.enclosing), ['h'])
  // document 只在 g 内部被局部声明遮蔽，同样不应漏检别处；本例确实没有别处引用它
  assert.equal(report.references.some((item) => item.name === 'document'), false)
})

test('宿主桩：生成物语法合法、可 import、行为符合预期', async () => {
  const source = `
    function f() {
      return navigator.userAgent + screen.width + document.cookie + atob('aGk=') + btoa('x');
    }
    function g() { return window.innerWidth + performance.now(); }
  `
  const { ast, source: text } = parseSource(source)
  const report = analyzeHostUsage(ast, text)
  const stubs = generateStubs(report)

  // 生成的是源码字符串，先确认语法合法
  parseSource(stubs.source)

  // 真的执行一次，确认不抛异常且值可用
  const stubOut = materialize([{ path: 'env.mjs', content: stubs.source }], 'env.mjs')
  const mod = await import(stubOut.entryUrl)
  const env = mod.createEnv()
  assert.equal(typeof env.navigator.userAgent, 'string')
  assert.equal(env.document.cookie, '')
  assert.equal(env.atob('aGk='), 'hi', 'atob 应是真实实现而不是桩')
  assert.equal(env.btoa('x'), 'eA==')
  assert.equal(env.window, env, 'window 应自指到 env')
  assert.ok(env.performance.now() >= 0)

  // 覆盖注入生效（这是让签名可复现的唯一正确做法）
  const injected = mod.createEnv({ navigator: { userAgent: 'Injected/1.0' } })
  assert.equal(injected.navigator.userAgent, 'Injected/1.0')
  assert.deepEqual(
    stubs.mustCapture.some((item) => item.startsWith('navigator')),
    true,
  )
  rmSync(stubOut.dir, { recursive: true, force: true })
})

test('宿主桩：window.btoa / self.atob 这类根对象属性访问也要生成实现（回归）', async () => {
  // 回归背景：只统计裸标识符时，`window.btoa(...)` 里的 btoa 不算「引用了 btoa」，
  // env.mjs 于是不生成 btoa。而生成物会把 window 别名到 env 自身，
  // 结果还原产物一跑就是 TypeError: window.btoa is not a function。
  // 打包产物里 window.btoa 是极常见写法，所以这条必须锁住。
  const source = `
    function sign(input) {
      return window.btoa(input) + '|' + self.atob('aGk=') + '|' + window.makeUpName;
    }
  `
  const { ast, source: text } = parseSource(source)
  const report = analyzeHostUsage(ast, text)
  const names = report.references.map((item) => item.name)
  assert.ok(names.includes('btoa'), 'window.btoa 应被记为引用了 btoa')
  assert.ok(names.includes('atob'), 'self.atob 应被记为引用了 atob')
  assert.ok(!names.includes('makeUpName'), '不存在的属性名不应被当成宿主全局')

  const stubs = generateStubs(report)
  parseSource(stubs.source)

  const materialized = materialize([{ path: 'env.mjs', content: stubs.source }], 'env.mjs')
  const mod = await import(materialized.entryUrl)
  const env = mod.createEnv()

  // 关键判据：通过根对象取到的实现必须真的可用
  assert.equal(env.window.btoa('x'), 'eA==')
  assert.equal(env.self.atob('aGk='), 'hi')
  assert.equal(env.btoa('x'), 'eA==', '根对象属性与顶层全局应指向同一实现')

  // 端到端：还原产物必须能真的跑通，而不是只在 env 层面看起来对
  const extracted = extractPure(`
    function sign(input) { return window.btoa(input).replace(/=+$/, ''); }
    window.sign = sign;
  `, { entry: ['sign'], includeDemo: false })
  const out = materialize(extracted.files, 'pure.mjs')
  const pure = await import(out.entryUrl)
  const runtime = pure.createRuntime(mod.createEnv())
  assert.equal(runtime.sign('x'), 'eA', '还原产物应在纯 Node 下算出结果')

  // 局部变量遮蔽了 window 时不能按宿主处理
  const shadowed = analyzeHostUsage(
    ...(() => {
      const parsed = parseSource('function f(window) { return window.btoa("x"); }')
      return [parsed.ast, parsed.source]
    })(),
  )
  assert.ok(
    !shadowed.references.map((item) => item.name).includes('btoa'),
    '被形参遮蔽的 window 不应产生宿主引用',
  )

  rmSync(materialized.dir, { recursive: true, force: true })
  rmSync(out.dir, { recursive: true, force: true })
})

// ---------------------------------------------------------------- 闭包抽取

test('闭包抽取：只带入口真正用到的依赖，且不引用宿主全局', () => {
  const result = extractPure(SAMPLE)
  assert.deepEqual(result.entries, ['makeSign'])
  const names = result.symbols.map((symbol) => symbol.name).sort()
  assert.deepEqual(names, ['_0x1a2b', '_0x3c4d', 'makeSign'])
  // 未被 makeSign 引用的字符串数组不应被带出来
  assert.ok(!names.includes('_0x4f2a'))
  assert.deepEqual(result.unresolved, [])
  assert.deepEqual(result.blockers, [])

  const pure = moduleFrom(result.files, 'pure.mjs')
  // 关键：产出模块里不得出现对宿主全局的直接引用（它们只能来自 env 解构）
  assert.match(pure, /const \{ [^}]*navigator[^}]*\} = env/)
  assert.ok(!/document\.createElement|window\.location/u.test(pure))
})

test('闭包抽取：无法解析的外层作用域变量会被报成卡点', () => {
  const source = `
    (function (outerLocal) {
      function entry(x) { return x + outerLocal; }
    })('seed');
  `
  const result = extractPure(source, { entry: ['entry'] })
  assert.deepEqual(result.unresolved, ['outerLocal'])
  assert.ok(result.blockers.some((blocker) => blocker.kind === 'unresolved-reference'))
})

test('闭包抽取：找不到入口时给出候选而不是瞎猜', () => {
  const source = 'function plain(a) { return a * 2 }'
  assert.throws(
    () => extractPure(source, { entry: ['nope'] }),
    (error) => error instanceof ReverseError && error.code === 'NOT_FOUND',
  )
})

// ---------------------------------------------------------------- 语义等价（核心）

test('语义等价：静态还原结果与原始代码在相同环境值下输出逐字节相同', async () => {
  const result = extractPure(SAMPLE)

  // 1) 原始混淆代码在模拟浏览器里跑
  const observed = {
    navigator: { userAgent: 'Mozilla/5.0 (Test) Chrome/124' },
    screen: { width: 1512 },
    document: { cookie: 'sid=abc123' },
  }
  const sandbox = {
    ...observed,
    btoa: (value) => Buffer.from(String(value), 'latin1').toString('base64'),
    window: {},
  }
  vm.createContext(sandbox)
  vm.runInContext(SAMPLE, sandbox)
  const expected = sandbox.window.__sign('payload-1')

  // 2) 还原版落到真实目录，在纯 Node 里跑，注入同一组观测值
  const output = materialize(result.files, 'pure.mjs')
  const pure = await import(output.entryUrl)
  const envPath = join(output.dir, 'env.mjs')
  const envMod = await import(pathToFileURL(envPath).href)
  const runtime = pure.createRuntime(envMod.createEnv(observed))

  const actual = runtime.makeSign('payload-1')
  assert.equal(actual, expected, '静态还原结果必须与原始代码一致')

  // 3) 环境值确实参与计算：换一个 userAgent 签名必须变
  const other = pure.createRuntime(
    envMod.createEnv({ ...observed, navigator: { userAgent: 'Other/9.9' } }),
  )
  assert.notEqual(other.makeSign('payload-1'), expected)

  // 4) 收尾：生成物落盘后也能被 demo.mjs 独立运行
  const demoRun = await import(pathToFileURL(join(output.dir, 'demo.mjs')).href)
  assert.ok(demoRun, 'demo.mjs 必须可以被独立 import 运行')
  rmSync(output.dir, { recursive: true, force: true })
})

// ---------------------------------------------------------------- Hook

test('Hook：脚本语法合法、可执行、返回值不变、可还原', () => {
  const hook = generateHookScript({ targets: [{ object: 'window', method: 'mySign' }] })
  // 生成的是 JS 字符串，先确认语法合法
  parseSource(hook.script)

  const logs = []
  const sandbox = {
    console: {
      groupCollapsed() {}, groupEnd() {}, log() {}, table() {}, warn() {}, error() {},
      info: (...args) => logs.push(args.join(' ')),
    },
    window: { mySign: (value) => `signed:${value}` },
    navigator: {},
    Blob: class {},
    URL: { createObjectURL: () => '', revokeObjectURL: () => {} },
    document: { createElement: () => ({ click() {} }) },
    Error, Promise, Object, Array, String, Number, Date, JSON, Math, Symbol, BigInt,
    RegExp, Function, Uint8Array, ArrayBuffer, setTimeout,
  }
  vm.createContext(sandbox)
  vm.runInContext(hook.script, sandbox)

  assert.ok(sandbox.window.__revHook.installed.includes('window.mySign'))
  const output = sandbox.window.mySign('abc')
  assert.equal(output, 'signed:abc', 'Hook 不能改变原函数行为')

  const records = sandbox.window.__revHook.dump()
  assert.equal(records.length, 2, '应记录「调用」与「返回」两条')
  assert.equal(records[0].label, 'window.mySign')
  assert.ok(Array.isArray(records[0].stack), '必须捕获调用栈（定位入口的关键）')

  sandbox.window.__revHook.unhook()
  assert.equal(sandbox.window.mySign('x'), 'signed:x')
  assert.equal(sandbox.window.__revHook.__installed, false)
})

test('Hook：可指定预设与显式目标，且不引入库依赖', () => {
  const hook = generateHookScript({
    presets: ['cryptojs'],
    includeNetwork: false,
    autoDiscover: false,
    targets: [{ object: 'CryptoJS.AES', method: 'encrypt', label: 'AES.encrypt' }],
  })
  assert.ok(hook.plannedTargets.includes('CryptoJS.AES.encrypt'))
  assert.ok(!hook.plannedTargets.some((item) => item.includes('XMLHttpRequest')))
  assert.ok(!hook.plannedTargets.some((item) => item.includes('自动发现')))
  assert.ok(!/\bimport\s|\brequire\(/u.test(hook.script), 'Hook 脚本必须自包含，不能依赖模块加载')
})

// ---------------------------------------------------------------- 评估

test('评估：纯计算代码与动态执行代码给出不同结论', () => {
  const pureCode = 'function calc(a, b) { return a * 31 + b }'
  const pureReport = assess(pureCode)
  assert.equal(pureReport.static.feasible, true)
  assert.equal(pureReport.static.confidence, 'high')
  assert.equal(pureReport.hook.feasible, false, '没有宿主交互时不需要 Hook')
  assert.equal(pureReport.verdict, 'static-first')

  const dynamicCode = `
    function run(seed) {
      var body = atob(seed);
      return eval(body);
    }
  `
  const dynamicReport = assess(dynamicCode)
  assert.equal(dynamicReport.static.feasible, false, 'eval 应判定静态还原受阻')
  assert.equal(dynamicReport.verdict, 'hook-first')
  assert.ok(dynamicReport.blockers.length > 0)

  const markdown = renderAssessment(dynamicReport)
  assert.match(markdown, /需求评估报告/)
  assert.match(markdown, /执行计划/)
})

test('评估：控制流平坦化只降低置信度，不否决可还原性', () => {
  const flattened = `
    var order = ['0','1','2','3','4','5'];
    var i = 0;
    function entry(x) {
      while (!![]) {
        switch (order[i++]) {
          case '0': x += 1; continue;
          case '1': x *= 2; continue;
          case '2': x ^= 3; continue;
          case '3': x -= 4; continue;
          case '4': x += 5; continue;
          case '5': return x;
        }
        break;
      }
      return x;
    }
  `
  const report = assess(flattened)
  assert.equal(report.static.feasible, true, '控制流平坦化不应直接判死')
  assert.equal(report.static.confidence, 'low')
  assert.ok(report.obfuscation.features.some((item) => item.includes('控制流平坦化')))
})

// ---------------------------------------------------------------- 边界

test('边界：空输入与不可解析输入都给出明确错误', () => {
  assert.throws(
    () => deobfuscate('   '),
    (error) => error instanceof ReverseError && error.code === 'INVALID_INPUT',
  )
  assert.throws(
    () => extractPure('function ( { broken'),
    (error) => error instanceof ReverseError && error.code === 'PARSE_FAILED',
  )
})
