#!/bin/sh
# Airlock 安装脚本（curl -fsSL <url>/install.sh | sh）
# 体验承诺（PRD §2.3 T+40s）：结尾打印下一步命令，不要求读文档；
# 非 Linux / 内核过旧：明说"你将运行在 L1 advisory"，不报错退出。
#
# 环境变量：
#   AIRLOCK_INSTALL_DIR   二进制符号链接的落点目录（默认 $HOME/.local/bin；
#                         cargo 安装根自动取其父目录）
#
# 卸载：
#   rm -f "$AIRLOCK_INSTALL_DIR/airlock"          # 或默认 $HOME/.local/bin/airlock
#   rm -rf "$(dirname "${AIRLOCK_INSTALL_DIR:-$HOME/.local/bin}")/share/doc/airlock" 2>/dev/null
#   cargo uninstall --root "$(dirname "${AIRLOCK_INSTALL_DIR:-$HOME/.local/bin}")" airlock 2>/dev/null
#   （daemon 数据在各仓库 <git-common-dir>/airlock/ 下，按需删除）
set -eu

REPO="https://github.com/a742987/airlock"
# 安装锁定在发布 tag 上，保证 Cargo.lock 可复现构建；每次发版后随 README 一起更新。
TAG="v2.0.0"
INSTALL_DIR="${AIRLOCK_INSTALL_DIR:-$HOME/.local/bin}"
CARGO_ROOT="$(dirname "$INSTALL_DIR")"

say() { printf '%s\n' "$*"; }

need_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        say "✗ 缺少 $1 —— 请先安装后重试（$2）"
        exit 1
    fi
}

# rustc ≥ 1.80（workspace rust-version）。cargo 存在但 rustc 缺失/过旧都视为不满足。
rust_version_ok() {
    command -v rustc >/dev/null 2>&1 || return 1
    _v="$(rustc --version | awk '{print $2}')"   # 形如 1.80.0 / 1.80
    _major="$(printf '%s' "$_v" | cut -d. -f1)"
    _minor="$(printf '%s' "$_v" | cut -d. -f2)"
    [ "$_major" = "1" ] && [ "$_minor" -ge 80 ] 2>/dev/null
}

need_tool cargo "https://rustup.rs"
if ! rust_version_ok; then
    say "✗ Rust ≥ 1.80（当前：$(command -v rustc >/dev/null 2>&1 && rustc --version || echo '未安装 rustc')）"
    say "  请升级后再试：curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
    say "  或在已有 rustup 的机器上：rustup update stable"
    exit 1
fi
need_tool cc "rusqlite（bundled SQLite）编译需要 C 编译器，通常由 gcc/clang 提供"
need_tool git "Airlock 依赖 git 解析冲突域"

say "→ 构建并安装 airlock / airlockd 到 $INSTALL_DIR（锁定 $TAG，首次约 1–3 分钟）"
# --locked：按仓库内 Cargo.lock 构建，依赖版本与发布时完全一致。
# --tag：每次发版后更新此处的 TAG 变量（见上方注释）。
cargo install --git "$REPO" --tag "$TAG" --locked --root "$CARGO_ROOT" airlock-cli || {
    say "✗ cargo install 失败——可改为克隆仓库手动构建："
    say "  git clone $REPO && cd airlock && cargo build --release"
    exit 1
}

mkdir -p "$INSTALL_DIR"
# 默认情况下 INSTALL_DIR 即 cargo root 的 bin 目录（同一文件，ln 拒绝自链接属预期）；
# 自定义 AIRLOCK_INSTALL_DIR 时，此链接把二进制接到你指定的目录。
ln -sf "$CARGO_ROOT/bin/airlock" "$INSTALL_DIR/airlock" 2>/dev/null || true

# 安装后确认二进制在 PATH 上；不在则给出可直接复制的 export 行。
if ! command -v airlock >/dev/null 2>&1; then
    say ""
    say "⚠ airlock 不在当前 PATH 中——请将其加入后再使用："
    say "  export PATH=\"$INSTALL_DIR:\$PATH\""
    say "  （可把上行写入 ~/.profile 或 ~/.zshrc 以永久生效）"
fi

# Landlock（L2）要求 Linux 内核 ≥ 5.13；过旧则明说会运行在 L1 advisory。
KERNEL_LAYER_NOTE=""
case "$(uname -s)" in
    Linux)
        _k="$(uname -r | cut -d. -f1-2)"   # 形如 6.8 / 5.15
        _kmaj="$(printf '%s' "$_k" | cut -d. -f1)"
        _kmin="$(printf '%s' "$_k" | cut -d. -f2)"
        if [ "$_kmaj" -gt 5 ] || { [ "$_kmaj" = "5" ] && [ "$_kmin" -ge 13 ]; } 2>/dev/null; then
            KERNEL_LAYER_NOTE="内核 $_k 支持 Landlock：可用时自动进入 L2（真实拒绝）"
        else
            KERNEL_LAYER_NOTE="内核过旧：你将运行在 L1 advisory"
        fi
        ;;
    Darwin)
        KERNEL_LAYER_NOTE="macOS 上你将运行在 L1 advisory（内核强制不可用，属预期而非错误）"
        ;;
    *)
        KERNEL_LAYER_NOTE="当前平台仅 L1 advisory"
        ;;
esac

say ""
say "✓ 安装完成。下一步（60 秒上手）："
say ""
say "  cd your-repo"
say "  airlock daemon start     # 启动守护进程"
say "  airlock doctor           # 看你处在哪一层（$KERNEL_LAYER_NOTE）"
say "  airlock init claude-code # 接入你的 agent（支持 codex/gemini/cursor/opencode）"
say ""
say "然后正常开你的 agent——第一次 Edit 前会自动 claim。"
