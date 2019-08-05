// .vuepress/config.js
module.exports = {
  title: "Pomerium",
  description:
    "Pomerium is a beyond-corp inspired, zero trust, open source identity-aware access proxy.",
  plugins: {
    sitemap: {
      hostname: "https://www.pomerium.io"
    },
    "@vuepress/google-analytics": {
      ga: "UA-129872447-2"
    }
  },
  markdown: {
    externalLinkSymbol: false
  },
  themeConfig: {
    logo: "/logo-long-civez.png",
    editLinks: true,
    docsDir: "docs",
    editLinkText: "Edit this page on GitHub",
    lastUpdated: "Last Updated",
    nav: [
      { text: "Documentation", link: "/docs/" },
      { text: "Community", link: "/community/" }

      // {
      //   text: "Versions",
      //   items: [
      //     { text: "v0.1.0", link: "https://v0-1-0.docs.pomerium.io/" },
      //     { text: "v0.0.5", link: "https://v0-0-5.docs.pomerium.io/" },
      //     { text: "v0.0.4", link: "https://v0-0-4.docs.pomerium.io/" }
      //   ]
      // }
    ],

    sidebar: {
      "/docs/": [
        {
          title: "",
          type: "group",
          collapsable: false,
          sidebarDepth: 0,
          children: ["", "background", "releases", "upgrading", "CHANGELOG"]
        },
        {
          title: "Quick Start",
          collapsable: false,
          path: "/docs/quick-start/",
          type: "group",
          sidebarDepth: 0,
          children: [
            "quick-start/",
            "quick-start/binary",
            "quick-start/helm",
            "quick-start/kubernetes",
            "quick-start/synology"
          ]
        },
        {
          title: "Identity Providers",
          collapsable: false,
          path: "/docs/identity-providers/",
          type: "group",
          sidebarDepth: 0,
          children: [
            "identity-providers/",
            "identity-providers/azure",
            "identity-providers/gitlab",
            "identity-providers/google",
            "identity-providers/okta",
            "identity-providers/one-login"
          ]
        },
        {
          title: "Reference",
          collapsable: true,
          path: "/docs/reference/",
          type: "group",
          collapsable: false,
          sidebarDepth: 1,
          children: [
            "reference/certificates",
            "reference/impersonation",
            "reference/signed-headers",
            "reference/examples",
            "reference/reference"
          ]
        }
      ],
      "/community/": [
        {
          title: "Community",
          type: "group",

          collapsable: false,
          sidebarDepth: 1,
          children: [
            "",
            "contributing",
            "developers-guide",
            "code-of-conduct",
            "security"
          ]
        }
      ]
    }
  }
};
