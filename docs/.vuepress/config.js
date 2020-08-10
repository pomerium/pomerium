// .vuepress/config.js
module.exports = {
  title: "Pomerium",
  description:
    "Pomerium is a beyond-corp inspired, zero trust, open source identity-aware access proxy.",
  plugins: {
    "check-md": {
      pattern: "**/*.md",
    },
    sitemap: {
      hostname: "https://www.pomerium.io",
    },
    "@vuepress/google-analytics": {
      ga: "UA-129872447-2",
    },
  },
  markdown: {
    externalLinkSymbol: false,
  },
  themeConfig: {
    home: false,
    logo: "/logo-long-civez.png",
    repo: "pomerium/pomerium",
    editLinks: true,
    docsDir: "docs",
    editLinkText: "Edit this page on GitHub",
    lastUpdated: "Last Updated",
    nav: [
      { text: "Documentation", link: "/docs/" },
      { text: "Reference", link: "/reference/" },
      { text: "Guides", link: "/guides/" },
      {
        text: "Enterprise",
        link: "https://www.pomerium.com/",
        target: "_self",
        rel: "",
      },
      {
        text: "v0.10.x", // current tagged version
        ariaLabel: "Version menu",
        items: [
          { text: "🚧Dev", link: "https://master.docs.pomerium.io/docs" },
          { text: "v0.10.x", link: "https://0-10-0.docs.pomerium.io/docs" },
          { text: "v0.9.x", link: "https://0-9-0.docs.pomerium.io/docs" },
          { text: "v0.8.x", link: "https://0-8-0.docs.pomerium.io/docs" },
          { text: "v0.7.x", link: "https://0-7-0.docs.pomerium.io/docs" },
          { text: "v0.6.x", link: "https://0-6-0.docs.pomerium.io/docs" },
          { text: "v0.5.x", link: "https://0-5-0.docs.pomerium.io/docs" },
          { text: "v0.4.x", link: "https://0-4-0.docs.pomerium.io/docs" },
          { text: "v0.3.x", link: "https://0-3-0.docs.pomerium.io/docs" },
          { text: "v0.2.x", link: "https://0-2-0.docs.pomerium.io/docs" },
          { text: "v0.1.x", link: "https://0-1-0.docs.pomerium.io/docs" },
        ],
      },
    ],
    algolia: {
      apiKey: "1653e881f3a6c17d3ad37f4d4c428e20",
      indexName: "pomerium",
    },
    sidebar: {
      "/docs/": [
        {
          title: "",
          type: "group",
          collapsable: false,
          sidebarDepth: 0,
          children: [
            "",
            "background",
            "releases",
            "installation",
            "upgrading",
            "CHANGELOG",
            "FAQ",
          ],
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
            "quick-start/synology",
            "quick-start/from-source",
          ],
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
            "identity-providers/cognito",
            "identity-providers/github",
            "identity-providers/gitlab",
            "identity-providers/google",
            "identity-providers/okta",
            "identity-providers/one-login",
          ],
        },
        {
          title: "Topics",
          collapsable: true,
          path: "/docs/topics/",
          type: "group",
          collapsable: false,
          sidebarDepth: 1,
          children: [
            "topics/certificates",
            "topics/data-storage",
            "topics/getting-users-identity",
            "topics/kubernetes-integration",
            "topics/production-deployment",
            "topics/programmatic-access",
            "topics/impersonation",
          ],
        },
        {
          title: "Community",
          collapsable: false,
          path: "/docs/community/",
          type: "group",
          sidebarDepth: 0,
          children: [
            "community/",
            "community/contributing",
            "community/code-of-conduct",
            "community/security",
          ],
        },
      ],
      "/guides/": [
        {
          title: "Guides",
          type: "group",

          collapsable: false,
          sidebarDepth: 1,
          children: [
            "",
            "ad-guard",
            "argo",
            "cloud-run",
            "istio",
            "kubernetes",
            "kubernetes-dashboard",
            "local-oidc",
            "mtls",
            "tiddlywiki",
            "vs-code-server",
          ],
        },
      ],
      "/reference/": [
        {
          title: "",
          type: "group",
          collapsable: false,
          sidebarDepth: 1,
          children: [""],
        },
      ],
    },
  },
};
