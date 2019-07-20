// .vuepress/config.js
module.exports = {
  title: "Pomerium",
  description: "An open source identity-aware access proxy.",
  plugins: {
    sitemap: {
      hostname: "https://www.pomerium.io"
    },
    "@vuepress/google-analytics": {
      ga: "UA-129872447-2"
    }
  },
  extend: "@vuepress/theme-default",
  themeConfig: {
    repo: "pomerium/pomerium",
    editLinks: true,
    docsDir: "docs",
    editLinkText: "Edit this page on GitHub",
    lastUpdated: "Last Updated",
    nav: [
      { text: "Documentation", link: "/docs/" },
      { text: "Quick Start", link: "/guide/" },
      { text: "Config Reference", link: "/reference/" },
      {
        text: "Versions",
        items: [
          { text: "v0.1.0", link: "https://v0-1-0.docs.pomerium.io/" },
          { text: "v0.0.5", link: "https://v0-0-5.docs.pomerium.io/" },
          { text: "v0.0.4", link: "https://v0-0-4.docs.pomerium.io/" }
        ]
      }
    ],
    sidebar: {
      "/guide/": guideSidebar("Quick Start"),
      "/docs/": docsSidebar("Documentation")
    }
  }
};

function guideSidebar(title) {
  return [
    {
      title,
      collapsable: false,
      children: ["", "binary", "from-source", "helm", "kubernetes", "synology"]
    }
  ];
}

function docsSidebar(title) {
  return [
    {
      title,
      collapsable: false,
      children: [
        "",
        "identity-providers",
        "signed-headers",
        "certificates",
        "examples",
        "impersonation",
        "programmatic-access",
        "upgrading",
        "contributing"
      ]
    }
  ];
}
