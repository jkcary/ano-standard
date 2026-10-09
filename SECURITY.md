# Security policy

## Scope and supported versions

The latest development revision is the current remediation target. Version 0.5.0-alpha.4 is experimental; 0.4.0 is a reference baseline, not a separately maintained production security branch. There is no production support or patch-time guarantee.

Do not use reference keys, identity emulators or test infrastructure in production. Local test success does not establish production isolation, distributed consensus, cloud KMS/HSM assurance or regulatory compliance. Read the limitations in README.zh-CN.md and V050_IMPLEMENTATION_STATUS.md.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting option at the repository's **Security → Advisories → Report a vulnerability**, if available. Do not place exploit details, secrets or private user data in public issues.

If private reporting is unavailable, open a minimal issue titled **Request for private security contact**, with no vulnerability details. Wait for the maintainer to provide a private channel before sharing sensitive material. Do not assume an email address or reporting SLA.

Include the affected revision, environment, minimal reproduction, impact and suggested mitigation through the private channel. Coordinate disclosure with maintainers; do not test systems you do not control.

## 中文摘要

请优先使用 GitHub 私密漏洞报告；如该入口未启用，仅公开请求私密联系方式，不公开漏洞细节或凭据。当前参考实现不提供生产安全认证或修复时限承诺。
