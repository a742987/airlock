# Homebrew formula：brew tap a742987/tap && brew install airlock
#
# v2.0.0：包含 F5 符号级冲突预测、F6 成本归因、F7 隔离回滚、
#         F12 政策即代码（airlock.policy.toml）、F13 凭据作用域代理。
# 打 tag 后填入 sha256 行（tarball 校验和）：
#   curl -sL https://github.com/a742987/airlock/archive/refs/tags/v2.0.0.tar.gz | shasum -a 256
# TODO: release 后填入真实 sha256（v2.0.0 tarball）
class Airlock < Formula
  desc "Kernel-enforced file leases for parallel AI coding agents"
  homepage "https://github.com/a742987/airlock"
  url "https://github.com/a742987/airlock/archive/refs/tags/v2.0.0.tar.gz"
  # sha256 "TODO_FILL_AFTER_TAGGING"
  head "https://github.com/a742987/airlock.git", branch: "main"
  license any_of: ["MIT", "Apache-2.0"]

  depends_on "rust" => :build
  depends_on "git"

  def install
    # 工作区根为虚拟 manifest（cargo ≥1.71 支持 --path . 安装全部成员二进制）：
    # airlock 与 airlockd 一起装进 buildpath/local/bin
    system "cargo", "install", "--locked", "--root", buildpath/"local", "--path", "."
    bin.install Dir[buildpath/"local/bin/*"]
  end

  def caveats
    <<~EOS
      macOS 上 Airlock 运行于 L1 advisory（内核强制不可用属预期，非错误）。
      Linux ≥5.13（含 WSL2）上 `airlock run` 提供 L2 Landlock 真实拒绝。
      L3 BPF-LSM 为规划中：当前仅探测内核能力，不拦截。

      v2.0.0 新特性：
        - F12: 政策即代码（airlock.policy.toml 在 claim 时驱动内核拒绝；
          配方见 docs/policy-cookbook.md）
        - F13: 凭据作用域代理（claim --cred <资源> 随租约发放，释放 ≤60s 吊销）

      快速开始：
        airlock daemon start
        airlock doctor
        airlock init claude-code
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/airlock --version")
  end
end
