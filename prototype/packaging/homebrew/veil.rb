class Veil < Formula
  include Language::Python::Virtualenv

  desc "Privacy proxy for AI coding agents: models see pseudonyms, you keep real values"
  homepage "https://github.com/lemonadesaltbagel/veil"
  url "https://files.pythonhosted.org/packages/67/61/be7b303b49c0319b0bc3af41498d75ee69f826c1f4e3ff8c9305edfbaf36/veil_proxy-0.1.2.tar.gz"
  sha256 "41c113b13ba6b408837fb563701c89e872096a95d88ee7b82e9ca574ae2b65d6"

  depends_on "cryptography"
  depends_on "python@3.14"

  resource "anyio" do
    url "https://files.pythonhosted.org/packages/a9/d2/f4d173e22df740bc37b1db102b386ba719b66e95b0f0d751f556b387e6d2/anyio-4.15.1.tar.gz"
    sha256 "9f28306018cbd6d329e64a36d58256edff76dd996fe423bc957326e578b82a94"
  end

  resource "certifi" do
    url "https://files.pythonhosted.org/packages/7e/eb/a2aa1ac3ea30dd3f30ca57f40232138b6b0040719316ecb85daf61167771/certifi-2026.10.18.tar.gz"
    sha256 "b9995d97b64d0431a5af837d8ca8cd6238104d1f319f04bd93ea43124d6c861e"
  end

  resource "h11" do
    url "https://files.pythonhosted.org/packages/01/ee/02a2c011bdab74c6fb3c75474d40b3052059d95df7e73351460c8588d963/h11-0.16.0.tar.gz"
    sha256 "4e35b956cf45792e4caa5885e69fba00bdbc6ffafbfa020300e549b208ee5ff1"
  end

  resource "httpcore" do
    url "https://files.pythonhosted.org/packages/06/94/82699a10bca87a5556c9c59b5963f2d039dbd239f25bc2a63907a05a14cb/httpcore-1.0.9.tar.gz"
    sha256 "6e34463af53fd2ab5d807f399a9b45ea31c3dfa2276f15a2c3f00afff6e176e8"
  end

  resource "httpx" do
    url "https://files.pythonhosted.org/packages/b1/df/48c586a5fe32a0f01324ee087459e112ebb7224f646c0b5023f5e79e9956/httpx-0.28.1.tar.gz"
    sha256 "75e98c5f16b0f35b567856f597f06ff2270a374470a5c2392242528e3e3e42fc"
  end

  resource "idna" do
    url "https://files.pythonhosted.org/packages/f5/08/8eea9d4b8302028f3abb2c0813953f7aec26d33b7a8960ed760e65ff29fa/idna-3.20.tar.gz"
    sha256 "a7db850025b95ded1eae8a46181a1a6c56c92c96f0e2b005d9ff8dc0210cab44"
  end

  resource "pyahocorasick" do
    url "https://files.pythonhosted.org/packages/b0/3c/dc9e31a0f004eabe2ef5d31456766555a02e2af29e159daa31266934af79/pyahocorasick-2.3.1.tar.gz"
    sha256 "9d0f6bb522237ed7f111ed59c9e8baea7d1e75813587b6773babd43bda35db9f"
  end

  resource "typing-extensions" do
    url "https://files.pythonhosted.org/packages/f6/cc/6253133b5bb138fc3306cebfbda2c520f545d36b5be2c7255cc528bb45d6/typing_extensions-4.16.0.tar.gz"
    sha256 "dc983d19a509c94dba722ee6abd33940f7c05a89e243c47e907eb4db6f1a43e5"
  end

  def install
    virtualenv_install_with_resources
  end

  service do
    run [opt_bin/"veil", "proxy", "--port", "8787"]
    keep_alive true
    environment_variables NO_PROXY: "127.0.0.1,localhost"
    log_path var/"log/veil.log"
    error_log_path var/"log/veil.log"
  end

  test do
    ENV["VEIL_HOME"] = testpath/".veil"
    ENV["VEIL_VAULT_KEY"] = "dGVzdC12YXVsdC1rZXktMzItYnl0ZXMtbG9uZyEhISE=" # test-only keys: no keychain
    ENV["VEIL_TOKEN_SECRET"] = "dGVzdC10b2tlbi1zZWNyZXQtMzItYnl0ZXMtbG9uZyE="
    assert_match "usage: veil", shell_output("#{bin}/veil --help")
    assert_match "user_", pipe_output("#{bin}/veil redact", "mail jane.roe@mailbox.org\n")
  end
end
