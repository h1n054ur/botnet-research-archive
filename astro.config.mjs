// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
	site: 'https://h1n054ur.github.io',
	base: '/botnet-research-archive',
	markdown: {
		smartypants: false,
	},
	integrations: [
		starlight({
			title: 'Botnet Research Archive',
			description: 'Educational documentation and academic analysis of historical botnet source code',
			customCss: ['./src/styles/hacker-theme.css'],
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/h1n054ur/botnet-research-archive' },
			],
			sidebar: [
				{
					label: 'Malware Families',
					items: [
						{ slug: 'families/rbot-rxbot' },
						{ slug: 'families/sdbot-spybot' },
						{ slug: 'families/phatbot-agobot' },
						{ slug: 'families/zeus' },
						{ slug: 'families/other-families' },
					],
				},
				{
					label: 'Categories',
					items: [
						{ slug: 'categories/exploit-packs' },
						{ slug: 'categories/worms' },
						{ slug: 'categories/rats' },
						{ slug: 'categories/stealers-crypters' },
						{ slug: 'categories/cross-platform' },
						{ slug: 'categories/ddos-iot' },
					],
				},
				{
					label: 'Analysis',
					items: [
						{ slug: 'analysis/evolution-timeline' },
						{ slug: 'analysis/irc-vs-http' },
						{ slug: 'analysis/malware-economy' },
						{ slug: 'analysis/cve-mapping' },
						{ slug: 'analysis/mitre-attack' },
						{ slug: 'analysis/defensive-lessons' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ slug: 'reference/inventory' },
						{ slug: 'reference/glossary' },
						{ slug: 'reference/bibliography' },
						{ slug: 'reference/about' },
					],
				},
			],
		}),
	],
});
