// .vuepress/config.js
module.exports = {
  title: "Pomerium",
  description:
    "Pomerium is a beyond-corp inspired, zero trust, open source identity-aware access proxy.",
  plugins: {
    sitemap: {
      hostname: "https://www.pomerium.io",
    },
    "@vuepress/google-analytics": {
      ga: "UA-129872447-2",
    },
    "@vuepress/blog": {
      directories: [
        {
          id: "post",
          dirname: "_posts",
          path: "/posts/",
          itemPermalink: "/posts/:year/:month/:day/:slug",
        },
      ],
    },
    "vuepress-plugin-mailchimp": {
      title: "Sign up to be notified of new features and updates",
      content: " ",
      endpoint:
        "https://pomerium.us19.list-manage.com/subscribe/post?u=76f0996a737c138396687fd6b&amp;id=2f4f70cf07",
      sitemap: {
        hostname: "https://www.pomerium.io",
      },
    },
  },
  markdown: {
    externalLinkSymbol: false,
  },
  themeConfig: {
    logo: "/logo-long-civez.png",
    repo: "pomerium/pomerium",
    editLinks: true,
    docsDir: "docs",
    editLinkText: "Edit this page on GitHub",
    lastUpdated: "Last Updated",
    nav: [
      { text: "Documentation", link: "/docs/" },
      { text: "Configuration", link: "/configuration/" },
      { text: "Recipes", link: "/recipes/" },
      { text: "Enterprise", link: "/enterprise/" },
      {
        text: "v0.8.x", // current tagged version
        ariaLabel: "Version menu",
        items: [
          { text: "🚧Dev", link: "https://master.docs.pomerium.io/docs" },
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
            "identity-providers/gitlab",
            "identity-providers/github",
            "identity-providers/google",
            "identity-providers/okta",
            "identity-providers/one-login",
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
            "reference/programmatic-access",
            "reference/getting-users-identity",
            "reference/production-deployment",
          ],
        },
      ],
      "/recipes/": [
        {
          title: "Recipes",
          type: "group",

          collapsable: false,
          sidebarDepth: 1,
          children: ["", "ad-guard", "vs-code-server", "kubernetes"],
        },
      ],
      "/enterprise/": [
        {
          title: "Enterprise",
          type: "group",
          collapsable: false,
          sidebarDepth: 1,
          children: [""],
        },
      ],
      "/configuration/": [
        {
          title: "Configuration",
          type: "group",
          collapsable: false,
          sidebarDepth: 1,
          children: ["", "examples"],
        },
      ],
    },
  },
};
