# QCCheck releases

Signed packages of **QCCheck** (file-based QC before delivery to ARD, ZDF, ORF, SRF) and its install page.

- **Install:** https://marcvannuffel.github.io/qccheck-releases/ (GitHub Pages of this repository, `main`, root)
  - Windows: `irm https://marcvannuffel.github.io/qccheck-releases/install.ps1 | iex`
  - macOS: `curl -fsSL https://marcvannuffel.github.io/qccheck-releases/install.sh | bash`
- **Releases:** each GitHub release has `qccheck-<version>-<win64|macos>.tar.gz`, its `.sig` (Ed25519), `latest.json`
  and `SHA256SUMS`. Installers and the app's update check read `releases/latest` (beta: newest pre-release) and only
  unpack a package whose signature matches the key built into them. Only the current release is kept.

The source lives in the private repository `marcvannuffel/QCCheck`; `install.ps1`, `install.sh` and `beta/` here are
copies of `tools/installer/` there (copy after every installer change). The access code on the page only keeps casual
visitors out – it does not protect the packages.
