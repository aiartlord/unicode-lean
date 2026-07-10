/-
  Unicode.Generated.KnownAttackTargetsData

  Materialized attack-target catalog (curated), pinned as a `List String`
  literal so membership tests reduce in the kernel. The parser and
  `include_str` source live in `Unicode.Generated.KnownAttackTargets`,
  which imports this module and carries the build-time drift gate.
-/

namespace Unicode.Generated.KnownAttackTargets

set_option maxRecDepth 1000000

/-- Materialized attack-target names in source order. -/
def targetsList : List String := [
  "Nethereum",
  "ethereum",
  "ethers",
  "web3",
  "bitcoin",
  "uniswap",
  "metamask",
  "binance",
  "coinbase",
  "solana",
  "react",
  "react-dom",
  "next",
  "vue",
  "angular",
  "lodash",
  "express",
  "electron",
  "typescript",
  "webpack",
  "node-fetch",
  "discord.js",
  "crypto-js",
  "django",
  "requests",
  "flask",
  "numpy",
  "pandas",
  "tensorflow",
  "pytorch",
  "matplotlib",
  "scipy",
  "beautifulsoup4",
  "pyyaml",
  "cryptography",
  "serde",
  "tokio",
  "clap",
  "reqwest",
  "rand",
  "anyhow",
  "rails",
  "rspec",
  "devise",
  "nokogiri",
  "google",
  "amazon",
  "microsoft",
  "apple",
  "github",
  "gitlab",
  "bitbucket",
  "cloudflare",
  "stripe",
  "twilio",
  "paypal",
  "openai",
  "anthropic",
  "claude",
  "chatgpt",
  "tesla",
  "twitter",
  "facebook",
  "instagram",
  "tiktok",
  "telegram",
  "discord"
]

end Unicode.Generated.KnownAttackTargets
