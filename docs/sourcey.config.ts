import { defineConfig, markdown } from "sourcey";

const markdownGroups = [
  {
    group: "Getting Started",
    pages: ["index", "getting-started/index", "getting-started/install-and-verify", "getting-started/downloads"],
  },
  {
    group: "Guides",
    pages: ["guides/tui", "guides/recovery-operations"],
  },
  {
    group: "Reference",
    pages: [
      "reference/index",
      "reference/architecture",
      "reference/testing",
      "reference/security-assurance",
      "reference/supply-chain",
      "reference/release-verification",
      "reference/release-checklist",
      "reference/platform-installers",
      "reference/federal-readiness",
      "reference/vault-format",
      "reference/compliance-frameworks",
      "reference/control-mapping",
      "reference/assurance-claims",
      "reference/ai-review",
      "reference/ci-design",
      "reference/messaging",
      "reference/license",
      "reference/remaining-work-prd",
    ],
  },
  {
    group: "Design System",
    pages: ["design/index", "design/brand", "design/system", "design/ia", "design/journeys", "design/evidence"],
  },
  {
    group: "Contributing",
    pages: ["contributing"],
  },
  {
    group: "API Reference",
    pages: ["api/index"],
  },
];

export default defineConfig({
  name: "paranoid-passwd",
  prettyUrls: "slash",
  theme: {
    preset: "default",
    colors: {
      primary: "#34d399",
      light: "#6ee7b7",
      dark: "#047857",
    },
    fonts: {
      sans: "Inter, ui-sans-serif, system-ui, sans-serif",
      mono: "IBM Plex Mono, SFMono-Regular, JetBrains Mono, ui-monospace, monospace",
    },
    layout: {
      sidebar: "18rem",
      toc: "18rem",
      content: "48rem",
    },
    css: ["./_static/custom.css"],
  },
  repo: "https://github.com/jbcom/paranoid-passwd",
  editBranch: "main",
  navbar: {
    links: [
      { type: "github", href: "https://github.com/jbcom/paranoid-passwd" },
      { label: "Releases", href: "https://github.com/jbcom/paranoid-passwd/releases" },
    ],
  },
  footer: {
    links: [
      { label: "Security", href: "https://github.com/jbcom/paranoid-passwd/security/policy" },
      { label: "GPL-3.0-only", href: "https://github.com/jbcom/paranoid-passwd/blob/main/LICENSE" },
    ],
  },
  navigation: {
    tabs: [
      {
        tab: "Documentation",
        slug: "",
        source: markdown({ groups: markdownGroups }),
      },
    ],
  },
});
