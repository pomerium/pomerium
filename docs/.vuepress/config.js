// .vuepress/config.js
module.exports = {
	title: "Pomerium",
	description: "Just playing around",

	themeConfig: {
		repo: "pomerium/pomerium",
		editLinks: true,
		docsDir: "docs",
		editLinkText: "Edit this page on GitHub",
		lastUpdated: "Last Updated",
		nav: [{ text: "Guide", link: "/guide/" }],
		sidebar: {
			"/guide/": genSidebarConfig("Guide")
		}
	}
};

function genSidebarConfig(title) {
	return [
		{
			title,
			collapsable: false,
			children: ["", "identity-providers", "signed-headers"]
		}
	];
}
