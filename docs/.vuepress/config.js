// .vuepress/config.js
module.exports = {
	title: "Pomerium",
	description: "An open source identity-aware access proxy.",
	plugins: {
		'sitemap': {
			hostname: 'https://www.pomerium.io'
		},
		'@vuepress/google-analytics': {
			ga: 'UA-129872447-2'
		}
	},
	themeConfig: {
		repo: "pomerium/pomerium",
		editLinks: true,
		docsDir: "docs",
		editLinkText: "Edit this page on GitHub",
		lastUpdated: "Last Updated",
		nav: [
			{ text: "Documentation", link: "/docs/" },
			{ text: "Quick Start", link: "/guide/" },
			{ text: "Config Reference", link: "/reference/" }

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
			children: ["", "helm", "kubernetes", "synology", "from-source"]
		}
	];
}

function docsSidebar(title) {
	return [
		{
			title,
			collapsable: false,
			children: ["", "identity-providers", "signed-headers", "certificates", "examples", "upgrading"]
		}
	];
}
