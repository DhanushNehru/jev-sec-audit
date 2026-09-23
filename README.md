<div align="center">
  <h1>🛡️ jev-sec-audit ⚡</h1>
  <p><b>Lightning-fast AI supply chain security auditor using Jev (System 1 models)</b></p>

  <a href="https://github.com/DhanushNehru/jev-sec-audit/stargazers">
    <img src="https://img.shields.io/github/stars/DhanushNehru/jev-sec-audit" alt="Stars Badge"/>
  </a>
  <a href="https://github.com/DhanushNehru/jev-sec-audit/network/members">
    <img src="https://img.shields.io/github/forks/DhanushNehru/jev-sec-audit" alt="Forks Badge"/>
  </a>
  <a href="https://github.com/DhanushNehru/jev-sec-audit/pulls">
    <img src="https://img.shields.io/github/issues-pr/DhanushNehru/jev-sec-audit" alt="Pull Requests Badge"/>
  </a>
  <a href="https://github.com/DhanushNehru/jev-sec-audit/issues">
    <img src="https://img.shields.io/github/issues/DhanushNehru/jev-sec-audit" alt="Issues Badge"/>
  </a>
  <a href="https://github.com/DhanushNehru/jev-sec-audit/graphs/contributors">
    <img alt="GitHub contributors" src="https://img.shields.io/github/contributors/DhanushNehru/jev-sec-audit?color=2b9348">
  </a>
  <a href="https://github.com/DhanushNehru/jev-sec-audit/blob/master/LICENSE">
    <img src="https://img.shields.io/github/license/DhanushNehru/jev-sec-audit?color=2b9348" alt="License Badge"/>
  </a>
</div>

<br>

Catch supply-chain attacks, typosquatting, and malicious post-install scripts in milliseconds using **System 1 AI**. 

Traditional LLMs are too slow and expensive to run on every commit in a CI/CD pipeline, and static regex rules are easily bypassed by attackers. `jev-sec-audit` solves this by utilizing **[TypeSafe AI's Jev model](https://typesafe.ai/blog/introducing-system-one-models-and-jev)**—a non-autoregressive decision engine that returns structured schemas at 200x the speed of standard LLMs.

---

## 🌟 Why Jev?

Jev is the first public "System 1" model. Instead of generating prose (chatting), it is designed purely for **fast, structured decision-making**. 

By passing our supply chain audit schema to Jev, we instantly receive a deterministically typed object with maliciousness probabilities:

```json
{
  "is_malicious": true, 
  "confidence": 0.98, 
  "threat_type": "obfuscated_code",
  "explanation": "Detected a highly obfuscated payload hidden in a Buffer.from() block."
}
```

This makes `jev-sec-audit` capable of analyzing dependencies, pull requests, and lockfiles natively in your pipeline, acting as a real-time AI security gate.

## 🚀 Installation

```bash
npm install -g jev-sec-audit
```

## 🛠️ Usage

### CLI 

You will need a TypeSafe API key to access the Jev model. You can set it as an environment variable or pass it directly.

```bash
export JEV_API_KEY="your_api_key_here"

# Audit a package-lock.json
jev-sec-audit ./package-lock.json

# Audit a specific suspect script
jev-sec-audit ./scripts/postinstall.js
```

### GitHub Actions (CI/CD)

Drop this into your `.github/workflows/audit.yml` to automatically analyze PRs for anomalous code or supply chain tampering:

```yaml
name: Jev Security Audit

on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Jev Sec Audit
        uses: DhanushNehru/jev-sec-audit@v1
        with:
          api-key: ${{ secrets.JEV_API_KEY }}
          target: './package-lock.json'
```

## 🧠 Threat Categories Detected

- **Typosquatting:** Detecting lookalike package names that masquerade as popular dependencies.
- **Obfuscated Code:** Finding hidden hex, base64, or eval blocks typically used to hide reverse shells.
- **Post-install Anomalies:** Flagging suspicious `npm run` or lifecycle scripts that execute external binaries or exfiltrate data.
- **Hardcoded Secrets:** Identifying exposed credentials in source code.

## 🤝 Contributing

Contributions are always welcome! Since JEV and System 1 models are brand new, we are looking for help expanding the detection schemas and supporting more package managers (Cargo, Pip, Go modules).

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.

## 🔗 Credits
- Created by [@DhanushNehru](https://github.com/DhanushNehru)
- Powered by [TypeSafe AI Jev](https://typesafe.ai/blog/introducing-system-one-models-and-jev)
