"""Sphinx configuration for paranoid-passwd."""

from __future__ import annotations

import os
import subprocess
from datetime import datetime
from pathlib import Path

project = "paranoid-passwd"
author = "Jon Bogaty"
copyright = f"{datetime.now().year}, {author}"
html_title = project
html_baseurl = "https://paranoid-passwd.com/"
repo_root = Path(__file__).resolve().parent.parent
docs_root = Path(__file__).resolve().parent


def _release() -> str:
    if env := os.environ.get("DOCS_VERSION"):
        return env
    try:
        result = subprocess.run(
            ["git", "describe", "--tags", "--always", "--dirty"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return "dev"
    return result.stdout.strip() or "dev"


release = version = _release()

extensions = [
    "myst_parser",
    "sphinx.ext.githubpages",
    "sphinxcontrib_rust",
]

source_suffix = {
    ".md": "markdown",
}

exclude_patterns = [
    "_build",
    "Thumbs.db",
    ".DS_Store",
]

html_theme = "shibuya"
html_static_path = ["_static"]
html_css_files = ["custom.css"]
html_extra_path = ["public"]

html_theme_options = {
    "accent_color": "green",
    "announcement": "Rust-native generator now ships as a TUI-first local app; the website is docs + downloads only.",
    "nav_links": [
        {"name": "Get Started", "url": "https://paranoid-passwd.com/getting-started/"},
        {"name": "TUI Guide", "url": "https://paranoid-passwd.com/guides/tui/"},
        {"name": "Reference", "url": "https://paranoid-passwd.com/reference/index/"},
        {"name": "API", "url": "https://paranoid-passwd.com/api/"},
        {"name": "Releases", "url": "https://github.com/jbcom/paranoid-passwd/releases"},
    ],
}

myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "html_image",
    "linkify",
]

myst_heading_anchors = 3

rust_crates = {
    "paranoid_core": str(repo_root / "crates" / "paranoid-core"),
    "paranoid_cli": str(repo_root / "crates" / "paranoid-cli"),
    "paranoid_gui": str(repo_root / "crates" / "paranoid-gui"),
    "paranoid_vault": str(repo_root / "crates" / "paranoid-vault"),
}
rust_doc_dir = str(docs_root / "api" / "crates")
rust_rustdoc_fmt = "md"
rust_generate_mode = "always"

suppress_warnings = [
    "myst.header",
    "myst.xref_missing",
]
