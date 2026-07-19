class McpSeatbelt < Formula
  desc "Runtime guardrails for AI agent MCP tools — blocks dangerous tool calls at the protocol layer"
  homepage "https://github.com/KryptosAI/mcp-seatbelt"
  url "https://registry.npmjs.org/@kryptosai/mcp-seatbelt/-/mcp-seatbelt-0.4.0.tgz"
  sha256 "auto"
  license "MIT"

  depends_on "node@22"

  def install
    system "npm", "install", *std_npm_args
    bin.install_symlink Dir["#{libexec}/bin/*"]
  end

  test do
    system "#{bin}/mcp-seatbelt", "--version"
  end
end
