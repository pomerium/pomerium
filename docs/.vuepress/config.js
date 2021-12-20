// .vuepress/config.js
module.exports = {
  title: "Pomerium",
  description:
    "Pomerium is a beyond-corp inspired, zero trust, open source identity-aware access proxy.",
  plugins: [
    "vuepress-plugin-element-tabs",
    "vuepress-plugin-mermaidjs",
    ["vuepress-plugin-code-copy", true],
    [
      "vuepress-plugin-mailchimp",
      {
        endpoint: "https://pomerium.us19.list-manage.com/subscribe/post?u=76f0996a737c138396687fd6b&amp;id=2f4f70cf07",
        title: "Pomerium Newsletter",
        content: "Updates on Pomerium and related security news.",
        submitText: "Subscribe"
      }
    ],
    [
      "check-md",
      {
        pattern: "**/*.md",
      },
    ],
    [
      "sitemap",
      {
        hostname: "https://www.pomerium.com",
        outFile: "docs/sitemap.xml",
      },
    ],
    [
      "@vuepress/google-analytics",
      {
        ga: "UA-129872447-2",
      },
    ],
  ],
  markdown: {
    externalLinkSymbol: false,
    extendMarkdown: (md) => {
      md.use(require("markdown-it-include"), {
        root: "./docs/partials/",
      });
    },
  },
  themeConfig: {
    home: false,
    activeHeaderLinks: false,
    logo: "/img/logo_white.svg",
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
        link: "/enterprise/about/",
      },
      {
        text: "v0.15.x", // current tagged version
        ariaLabel: "Version menu",
        items: [
          { text: "🚧Dev", link: "https://master.docs.pomerium.io/docs" },
          { text: "v0.15.x", link: "https://0-15-0.docs.pomerium.io/docs" },
          { text: "v0.14.x", link: "https://0-14-0.docs.pomerium.io/docs" },
          { text: "v0.13.x", link: "https://0-13-0.docs.pomerium.io/docs" },
          { text: "v0.12.x", link: "https://0-12-0.docs.pomerium.io/docs" },
          { text: "v0.11.x", link: "https://0-11-0.docs.pomerium.io/docs" },
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
          title: "Overview",
          type: "group",
          collapsable: false,
          sidebarDepth: 0,
          children: [
            "",
            "releases",
            "architecture",
            "background",
            "FAQ",
            "upgrading",
            "CHANGELOG",
          ],
        },
        {
          title: "Install",
          collapsable: false,
          path: "/docs/install/",
          type: "group",
          sidebarDepth: 0,
          children: [
            "install/",
            ["k8s/helm", "Kubernetes"],
            "install/binary",
            "install/from-source",
          ],
        },
        {
          title: "Identity Providers",
          collapsable: true,
          path: "/docs/identity-providers/",
          type: "group",
          sidebarDepth: 0,
          initialOpenGroupIndex: 0,
          children: [
            "identity-providers/",
            "identity-providers/auth0",
            "identity-providers/azure",
            "identity-providers/cognito",
            "identity-providers/github",
            "identity-providers/gitlab",
            "identity-providers/google",
            "identity-providers/okta",
            "identity-providers/one-login",
            "identity-providers/ping",
          ],
        },
        {
          title: "TCP Connections",
          collapsable: false,
          path: "/docs/tcp/",
          type: "group",
          sidebarDepth: 1,
          children: [
            "tcp/",
            "tcp/client",
            {
              title: "Examples",
              collapsable: true,
              type: "group",
              sidebarDepth: 0,
              children: ["tcp/mysql", "tcp/rdp", "tcp/redis", "tcp/ssh"],
            },
          ],
        },
        {
          title: "Kubernetes",
          collapsable: false,
          path: "/docs/k8s/",
          type: "group",
          sidebarDepth: 0,
          children: [
            "k8s/",
            "k8s/helm",
            "k8s/ingress",
          ]
        },
        {
          title: "Topics",
          collapsable: false,
          path: "/docs/topics/",
          type: "group",
          sidebarDepth: 0,
          children: [
            "topics/certificates",
            "topics/data-storage",
            "topics/device-identity",
            "topics/getting-users-identity",
            "topics/original-request-context",
            "topics/ppl",
            "topics/production-deployment",
            "topics/programmatic-access",
            "topics/single-sign-out",
            "topics/load-balancing",
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
            "code-server",
            "enroll-device",
            "grafana",
            "istio",
            "jwt-verification",
            "kubernetes",
            "kubernetes-dashboard",
            "local-oidc",
            "mtls",
            "nginx",
            "synology",
            "tcp",
            "tiddlywiki",
            "traefik-ingress",
            "transmission",
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
      "/enterprise/": [
        {
          title: "Enterprise",
          type: "group",
          collapsable: false,
          sidebarDepth: 2,
          children: [
            "about",
            "concepts",
            {
              title: "Install",
              type: "group",
              collapsable: false,
              path: "/enterprise/install/",
              sidebarDepth: 2,
              children: [
                "/enterprise/install/quickstart",
                "/enterprise/install/helm",
              ],
            },
            "metrics",
            {
              title: "Reference",
              type: "group",
              collapsable: false,
              path: "/enterprise/reference/configure",
              sidebarDepth: 2,
              children: [
                "/enterprise/reference/config.md",
                "/enterprise/reference/reports",
                "/enterprise/reference/manage",
                "/enterprise/reference/configure",
              ],
            },
            "api",
            "upgrading",
            "changelog",
          ],
        },
      ],
    },
  },
  head: [
    //Hack: Make clicking on the logo go to home url
    [
      "script",
      {},
      `
      const logoUrlChanger = setInterval(function() {
      //Anchor above the logo image
      const homeEls = document.getElementsByClassName("home-link");
      if(homeEls.length > 0) {
        const homeEl = homeEls[0];
        homeEl.setAttribute("href", "https://www.pomerium.com");
        homeEl.setAttribute("onclick", "document.location='https://www.pomerium.com';return false;");
        clearInterval(logoUrlChanger);
      }

      //Actual logo image
      const logoEls = document.getElementsByClassName("logo")
      if(logoEls.length > 0) {
        const logoEl = logoEls[0]
        logoEl.setAttribute("onclick", "document.location='https://www.pomerium.com';return false;");
        clearInterval(logoUrlChanger);
      }
      }, 1000)

      `,
    ],
  ],
};
