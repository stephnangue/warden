// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
  site: 'https://wardengateway.com',
  integrations: [
    starlight({
      title: 'Warden',
      description:
        'The secure gateway connecting AI agents to the enterprise systems they need to do real work.',
      logo: {
        light: './src/assets/logo-light.svg',
        dark: './src/assets/logo-dark.svg',
        replacesTitle: true,
      },
      favicon: '/favicon.svg',
      customCss: ['./src/styles/custom.css'],
      // HashiCorp-style: charcoal code blocks in both light and dark themes.
      expressiveCode: {
        themes: ['github-dark'],
        styleOverrides: { borderRadius: '0.6rem' },
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/stephnangue/warden',
        },
      ],
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'Home', link: '/' },
            { slug: 'agent-flow' },
            { slug: 'architecture' },
          ],
        },
        {
          // Concepts follow the curated reading order from concepts/index.md,
          // not alphabetical.
          label: 'Concepts',
          items: [
            { slug: 'concepts' },
            { slug: 'concepts/dev-server' },
            { slug: 'concepts/authentication' },
            { slug: 'concepts/tokens' },
            { slug: 'concepts/roles' },
            { slug: 'concepts/policies' },
            { slug: 'concepts/cel-conditions' },
            { slug: 'concepts/credentials' },
            { slug: 'concepts/providers' },
            { slug: 'concepts/mcp' },
            { slug: 'concepts/discovery-and-skills' },
            { slug: 'concepts/delegation' },
            { slug: 'concepts/namespaces' },
            { slug: 'concepts/audit' },
            { slug: 'concepts/seal-unseal' },
            { slug: 'concepts/storage' },
            { slug: 'concepts/high-availability' },
          ],
        },
        { label: 'Use cases', autogenerate: { directory: 'use-cases' } },
        {
          // Grouped by upstream theme, mirroring the README "Supported systems"
          // table. Subgroups collapse by default; the active page's group opens.
          label: 'Providers',
          items: [
            { slug: 'provider-backends' },
            {
              label: 'MCP servers',
              collapsed: true,
              items: [
                { slug: 'provider-backends/mcp' },
                { slug: 'provider-backends/mcp_aws' },
                { slug: 'provider-backends/mcp-github' },
                { slug: 'provider-backends/mcp-slack' },
              ],
            },
            {
              label: 'LLM APIs',
              collapsed: true,
              items: [
                { slug: 'provider-backends/anthropic' },
                { slug: 'provider-backends/openai' },
                { slug: 'provider-backends/mistral' },
                { slug: 'provider-backends/cohere' },
              ],
            },
            {
              label: 'Cloud infrastructure',
              collapsed: true,
              items: [
                { slug: 'provider-backends/aws' },
                { slug: 'provider-backends/azure' },
                { slug: 'provider-backends/gcp' },
                { slug: 'provider-backends/alicloud' },
                { slug: 'provider-backends/ibmcloud' },
                { slug: 'provider-backends/ovh' },
                { slug: 'provider-backends/scaleway' },
                { slug: 'provider-backends/cloudflare' },
              ],
            },
            {
              label: 'Code hosting & CI/CD',
              collapsed: true,
              items: [
                { slug: 'provider-backends/github' },
                { slug: 'provider-backends/gitlab' },
                { slug: 'provider-backends/atlassian' },
                { slug: 'provider-backends/ansible_tower' },
                { slug: 'provider-backends/tfe' },
              ],
            },
            {
              label: 'Observability',
              collapsed: true,
              items: [
                { slug: 'provider-backends/datadog' },
                { slug: 'provider-backends/dynatrace' },
                { slug: 'provider-backends/elastic' },
                { slug: 'provider-backends/grafana' },
                { slug: 'provider-backends/honeycomb' },
                { slug: 'provider-backends/newrelic' },
                { slug: 'provider-backends/prometheus' },
                { slug: 'provider-backends/sentry' },
                { slug: 'provider-backends/splunk' },
              ],
            },
            {
              label: 'Incident & ITSM',
              collapsed: true,
              items: [
                { slug: 'provider-backends/pagerduty' },
                { slug: 'provider-backends/servicenow' },
                { slug: 'provider-backends/slack' },
              ],
            },
            {
              label: 'Databases',
              collapsed: true,
              items: [
                { slug: 'provider-backends/rds' },
                { slug: 'provider-backends/redshift' },
              ],
            },
            {
              label: 'Kubernetes',
              collapsed: true,
              items: [{ slug: 'provider-backends/kubernetes' }],
            },
            {
              label: 'Secrets backend',
              collapsed: true,
              items: [{ slug: 'provider-backends/vault' }],
            },
            {
              label: 'Generic REST',
              collapsed: true,
              items: [{ slug: 'provider-backends/rest' }],
            },
          ],
        },
        {
          label: 'Credential drivers',
          autogenerate: { directory: 'credential-drivers' },
        },
        { label: 'Auth methods', autogenerate: { directory: 'auth-methods' } },
        { label: 'Agent identity', autogenerate: { directory: 'agent-identity' } },
        { label: 'CLI', autogenerate: { directory: 'cli' } },
        { label: 'Quickstarts', autogenerate: { directory: 'quickstarts' } },
        { label: 'Tutorials', autogenerate: { directory: 'tutorials' } },
        { label: 'Install', autogenerate: { directory: 'install' } },
      ],
    }),
  ],
});
