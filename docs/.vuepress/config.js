// .vuepress/config.js
module.exports = {
	title: "Pomerium",
	description: "An open source identity-aware access proxy.",

	themeConfig: {
		repo: "pomerium/pomerium",
		editLinks: true,
		docsDir: "docs",
		editLinkText: "Edit this page on GitHub",
		lastUpdated: "Last Updated",
		nav: [{ text: "Quick Start", link: "/guide/" },
		{ text: "Documentation", link: "/docs/" }],
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
			children: ["", "kubernetes", "from-source"]
		}
	];
}

function docsSidebar(title) {
	return [
		{
			title,
			collapsable: false,
			children: ["", "identity-providers", "signed-headers", "examples","config-reference"]
		}
	];
}
