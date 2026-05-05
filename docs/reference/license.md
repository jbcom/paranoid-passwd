---
title: License
---

# License

`paranoid-passwd` is licensed under the GNU General Public License v3.0 only
(`GPL-3.0-only`).

This is an intentional product decision:

- the password manager remains open source under a reciprocal license
- downstream redistributors receive the same source-available security posture as users
- Slint can be used under Slint's GPLv3 open-source licensing path
- the licensing model does not require reintroducing a browser, webview, JavaScript, or Node
  runtime into the trusted product surface

The canonical license text is included in the repository `LICENSE` file.

For Slint work, use the GPLv3 option unless a future release decision explicitly chooses
Slint's separate royalty-free or commercial licensing path. Slint WASM and mobile targets
are allowed only as explicit Rust/Slint surfaces with separate threat models and release gates.
