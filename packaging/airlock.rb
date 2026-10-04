# Homebrew formula：brew tap airlock-dev/tap && brew install airlock
#
# 当前状态：首个 release tag 未发布，stable URL 尚无 sha256——
# 现阶段可用 `brew install --HEAD airlock`（从 main 分支构建）；
# tag 发布后填入 sha256 行，stable 安装即生效。
class Airlock < Formula
  desc "Kernel-enforced file leases for parallel AI coding agents"
  homepage "https://github.com/airlock-dev/airlock"
  url "https://github.com/airlock-dev/airlock/archive/refs/tags/v0.1.0.tar.gz"
  # TODO: 首个 release tag 后填入 sha256（tarball 校验和）：
  #   shasum -a 256 v0.1.0.tar.gz
  # sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  head "https://github.com/airlock-dev/airlock.git", branch: "main"
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
