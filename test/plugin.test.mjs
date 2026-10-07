/**
 * 插件级测试：把本插件真的挂载到 cordis 上，验证服务注册、工具注册与端到端执行。
 *
 * 与 `analysis.test.mjs` 的分工：
 *   - analysis 测试验证「算法与静态分析是否正确」
 *   - 本文件验证「插件契约是否正确」——服务名、工具名、schema 合法性、参数翻译、
 *     以及 `defineTool` 的入参校验链路
 *
 * 这里用 `ctx.tools.get(name).execute(args, exec)` 直接调用工具定义：`defineTool`
 * 返回的 `execute` 已经包含入参校验，因此这条路径覆盖了「模型传参 → 校验 → 服务 → 核心」
 * 的完整链路，只是绕开了 agent 循环本身。
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { Context } from '@deepseek-ai/cordis'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'

const here = dirname(fileURLToPath(import.meta.url))
const SAMPLE = readFileSync(join(here, 'fixtures/obfuscated-sample.js'), 'utf8')

/** FiberState.ACTIVE */
const ACTIVE = 2

/** 期望注册的工具名。 */
const EXPECTED_TOOLS = [
  'rev_assess',
  'rev_crypto_calc',
  'rev_deobfuscate',
  'rev_extract_pure',
  'rev_hook_generate',
]

/**
 * 搭起最小宿主并挂载本插件。
 *
 * @returns 上下文与插件 fiber。
 */
async function mountPlugin() {
  const ctx = new Context()
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  const plugin = await import('../lib/index.js')
  const fiber = await ctx.plugin(plugin, {
    maxSourceBytes: 2_000_000,
    hookLogLimit: 100,
    hookAutoDiscover: true,
  })
  return { ctx, fiber, plugin }
}

/** 调用一个已注册工具。 */
async function callTool(ctx, name, args) {
  const definition = ctx.tools.get(name)
  assert.ok(definition, `工具 ${name} 未注册`)
  return definition.execute(args, { signal: new AbortController().signal })
}

test('插件契约：导出四项、服务注册、工具全部挂载且 fiber 为 ACTIVE', async () => {
  const { ctx, fiber, plugin } = await mountPlugin()

  assert.equal(typeof plugin.name, 'string')
  assert.deepEqual([...plugin.inject], ['tools'])
  assert.equal(typeof plugin.apply, 'function')
  const validated = plugin.Config['~standard'].validate({})
  assert.equal(validated.issues, undefined)
  assert.deepEqual(validated.value, {
    maxSourceBytes: 2_000_000,
    hookLogLimit: 2000,
    hookAutoDiscover: true,
  })

  assert.equal(fiber.state, ACTIVE, '根插件应进入 ACTIVE')

  // 两个服务必须已注册并可访问
  assert.equal(typeof ctx.reverseCrypto.calculate, 'function')
  assert.equal(typeof ctx.reverseAnalysis.runAssess, 'function')
  assert.equal(typeof ctx.reverseAnalysis.runExtract, 'function')

  // 五个工具全部进入注册表
  const registered = ctx.tools.schemas().map((schema) => schema.name)
  for (const tool of EXPECTED_TOOLS) {
    assert.ok(registered.includes(tool), `缺少工具 ${tool}`)
  }

  await ctx.fiber.dispose()
})

test('工具链路：rev_crypto_calc 走完「模型参数 → schema 校验 → 服务 → 核心」', async () => {
  const { ctx } = await mountPlugin()

  const digest = await callTool(ctx, 'rev_crypto_calc', {
    operation: 'hash',
    algorithm: 'md5',
    data: 'abc',
  })
  assert.equal(digest.result.hex, '900150983cd24fb0d6963f7d28e17f72')

  // 用系统 OpenSSL 生成的向量验证服务层的编码翻译是对的
  const decrypted = await callTool(ctx, 'rev_crypto_calc', {
    operation: 'aes-decrypt',
    data: '80p1kg4kNCTY3kx4aCiJfEUpFaY6Fs6u8yjWDQO5FJE=',
    dataEncoding: 'base64',
    passphrase: 'secret',
    salt: '0001020304050607',
    kdfHash: 'md5',
    keyLength: 32,
    mode: 'cbc',
  })
  assert.equal(decrypted.result.plaintext, 'hello reverse engineering')

  // 异或：数组形式的密钥也要能翻译
  const xor = await callTool(ctx, 'rev_crypto_calc', {
    operation: 'xor',
    data: 'sign=abc',
    key: [18, 52, 86],
  })
  assert.deepEqual(xor.result.keyBytes, [18, 52, 86])

  // 非法参数必须被挡下，且错误信息可读（不能让模型拿到一份"看起来算完了"的结果）
  await assert.rejects(
    () => callTool(ctx, 'rev_crypto_calc', { operation: 'aes-decrypt', data: 'AAAA', key: 'aabb' }),
    /缺少|IV|密钥/u,
  )

  await ctx.fiber.dispose()
})

test('工具链路：rev_assess / rev_deobfuscate / rev_extract_pure / rev_hook_generate', async () => {
  const { ctx } = await mountPlugin()

  const assessment = await callTool(ctx, 'rev_assess', { code: SAMPLE })
  assert.equal(typeof assessment.report, 'string')
  assert.match(assessment.report, /需求评估报告/)
  assert.ok(['static-first', 'hook-first', 'hook-then-static', 'blocked'].includes(assessment.verdict))
  assert.ok(Array.isArray(assessment.plan) && assessment.plan.length > 0)

  const deobfuscated = await callTool(ctx, 'rev_deobfuscate', {
    code: "var a = '\\x41'; var b = !0; obj['k'] = 1;",
  })
  assert.match(deobfuscated.code, /"A"/)
  assert.match(deobfuscated.code, /true/)
  assert.match(deobfuscated.code, /obj\.k = 1/)
  // 4 处：'\x41'→"A"（转义还原）、'k'→"k"（引号归一化）、!0→true（常量折叠）、
  // obj["k"]→obj.k（成员访问规范化，发生在第二轮）
  assert.equal(deobfuscated.changeCount, 4)

  const extracted = await callTool(ctx, 'rev_extract_pure', { code: SAMPLE })
  assert.deepEqual(extracted.entries, ['makeSign'])
  const paths = extracted.files.map((file) => file.path).sort()
  assert.deepEqual(paths, ['demo.mjs', 'env.mjs', 'pure.mjs'])
  assert.ok(extracted.files.every((file) => typeof file.content === 'string' && file.content.length > 0))
  assert.ok(extracted.mustCapture.some((item) => item.startsWith('navigator')))

  const hook = await callTool(ctx, 'rev_hook_generate', {
    targets: [{ object: 'window', method: 'makeSign' }],
    logLimit: 50,
  })
  assert.ok(hook.script.includes('__revHook'))
  assert.ok(hook.plannedTargets.includes('window.makeSign'))
  assert.ok(hook.usage.length > 0)

  await ctx.fiber.dispose()
})

test('工具链路：源码超出上限时被服务层挡住，并给出可执行的建议', async () => {
  const ctx = new Context()
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  const plugin = await import('../lib/index.js')
  await ctx.plugin(plugin, { maxSourceBytes: 64, hookLogLimit: 10, hookAutoDiscover: false })

  await assert.rejects(
    () => callTool(ctx, 'rev_assess', { code: 'var a = 1;\n'.repeat(50) }),
    /超过上限/u,
  )

  await ctx.fiber.dispose()
})
