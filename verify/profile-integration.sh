#!/bin/sh
# 真实启动器集成验证：证明本插件作为 bundle 能被 DSH 组合并加载。
#
# 全部动作发生在**工作区内的临时 DSH_HOME**（.dsh-scratch/），不触碰真实的 ~/.dsh。
#
#   sh verify/profile-integration.sh
#
# 覆盖三件事：
#   1. 用随产品附带的 web 模板创建隔离 profile
#   2. 用真实 `dsh plugin add` 安装本包
#   3. 断言 --dump-config 出现本包贡献的行，且 --dump-config-schema 能 import 本包模块
set -eu

APP_DEFAULT="/Applications/DeepSeek Harness.app/Contents/MacOS/DeepSeek Harness"
CLI_DEFAULT="/Applications/DeepSeek Harness.app/Contents/Resources/app.asar/dsh/node_modules/@deepseek-ai/dsh-desktop-host/lib/cli.js"

APP="${DSH_APP:-$APP_DEFAULT}"
CLI="${DSH_CLI:-$CLI_DEFAULT}"
PROFILE="${DSH_PROFILE_NAME:-revlab}"

HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
SCRATCH="$HERE/.dsh-scratch"

# 护栏：临时 home 必须落在本仓库内，避免误写用户的真实配置。
case "$SCRATCH" in
  "$HERE"/*) : ;;
  *) echo "✗ 临时 DSH_HOME 落在仓库之外，拒绝运行：$SCRATCH" >&2; exit 1 ;;
esac

if [ ! -x "$APP" ]; then
  echo "✗ 找不到 DSH 可执行文件：$APP" >&2
  echo "  用 DSH_APP=<路径> 覆盖。" >&2
  exit 1
fi

# CLI 入口位于 app.asar 归档内，普通 shell 无法 stat 它，只能真正跑一次来探测。
if ! "$APP" --expose-internals "$CLI" --version >/dev/null 2>&1; then
  echo "✗ 无法通过 DSH CLI 启动：$CLI" >&2
  echo "  用 DSH_CLI=<路径> 覆盖。" >&2
  exit 1
fi

export DSH_HOME="$SCRATCH"
export ELECTRON_RUN_AS_NODE=1

dsh() { "$APP" --expose-internals "$CLI" "$@"; }

echo "▸ 临时 DSH_HOME：$DSH_HOME"
echo "▸ 用随附模板创建隔离 profile：$PROFILE"
rm -rf "$SCRATCH/profiles/$PROFILE"
dsh --profile "$PROFILE" --from-default-profile web --dump-config >/dev/null

echo "▸ 安装本包（真实 dsh plugin add）"
dsh plugin --profile "$PROFILE" add "$HERE" >/dev/null

echo "▸ 断言 1/2：--dump-config 含本包贡献的行"
dump=$(dsh --profile "$PROFILE" --dump-config)
printf '%s\n' "$dump" | grep -q "id: reverse-toolkit" || {
  echo "✗ --dump-config 未包含 id: reverse-toolkit" >&2; exit 1; }
printf '%s\n' "$dump" | grep -q "name: dsh-plugin-reverse" || {
  echo "✗ --dump-config 未包含 name: dsh-plugin-reverse" >&2; exit 1; }

echo "▸ 断言 2/2：--dump-config-schema 能真实 import 本包模块"
dsh --profile "$PROFILE" --dump-config-schema 2>/dev/null \
  | grep -q '"const": "dsh-plugin-reverse"' || {
  echo "✗ schema 未包含本包模块标识" >&2; exit 1; }

echo
echo "✅ 集成验证通过：bundle 层被组合，插件模块被真实加载"
echo "   产物留在 ${SCRATCH}，可检查："
echo "     cat ${SCRATCH}/profiles/${PROFILE}/package.json"
