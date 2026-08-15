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
      // Starlight emits og:title/type/url per page; add the shared social card.
      head: [
        {
          tag: 'meta',
          attrs: { property: 'og:image', content: 'https://wardengateway.com/og.png' },
        },
        {
          tag: 'meta',
          attrs: { property: 'og:site_name', content: 'Warden' },
        },
        {
          tag: 'meta',
          attrs: { name: 'twitter:card', content: 'summary_large_image' },
        },
        {
          tag: 'meta',
          attrs: { name: 'twitter:image', content: 'https://wardengateway.com/og.png' },
        },
      ],
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
        { label: 'Use cases', autogenerate: { directory: 'use-cases' } },
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
        {
          // Federation & keyless identity: the OIDC issuer and the keyless
          // credential story that builds on it. Curated reading order.
          label: 'Federation & keyless identity',
          items: [
            { slug: 'federation' },
            { slug: 'federation/oidc-issuer' },
            { slug: 'federation/keyless-credentials' },
            { slug: 'federation/assertion-claims' },
            { slug: 'federation/credential-chaining' },
            {
              // The signing key lives in an external KMS (also listed under
              // Configuration, since it is a server-config stanza).
              label: 'Signer',
              collapsed: true,
              items: [
                { slug: 'configuration/signer' },
                { slug: 'configuration/signer/transit' },
              ],
            },
            {
              // Push the issuer's public keys to a bucket/CDN (runtime config).
              label: 'Publishers',
              collapsed: true,
              items: [
                { slug: 'federation/publishers' },
                { slug: 'federation/publishers/s3' },
                { slug: 'federation/publishers/gcs' },
                { slug: 'federation/publishers/azure-blob' },
                { slug: 'federation/publishers/http-put' },
                { slug: 'federation/publishers/local-file' },
              ],
            },
          ],
        },
        {
          // Grouped by upstream theme, mirroring the README "Supported systems"
          // table. Subgroups collapse by default; the active page's group opens.
          label: 'Providers',
          items: [
            { slug: 'provider-backends' },
            { slug: 'provider-backends/local-dev-setup' },
            { slug: 'provider-backends/configuration' },
            {
              label: 'MCP',
              collapsed: true,
              items: [
                { slug: 'provider-backends/mcp' },
                { slug: 'provider-backends/mcp_aws' },
                { slug: 'provider-backends/mcp-github' },
                { slug: 'provider-backends/mcp-slack' },
              ],
            },
            {
              label: 'LLM',
              collapsed: true,
              items: [
                { slug: 'provider-backends/anthropic' },
                { slug: 'provider-backends/openai' },
                { slug: 'provider-backends/mistral' },
                { slug: 'provider-backends/cohere' },
              ],
            },
            {
              label: 'Cloud',
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
              label: 'CI/CD',
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
              label: 'ITSM',
              collapsed: true,
              items: [
                { slug: 'provider-backends/pagerduty' },
                { slug: 'provider-backends/servicenow' },
                { slug: 'provider-backends/slack' },
              ],
            },
            {
              // Kubernetes, the Vault secrets backend, and databases.
              label: 'Infrastructure',
              collapsed: true,
              items: [
                { slug: 'provider-backends/kubernetes' },
                { slug: 'provider-backends/vault' },
                { slug: 'provider-backends/rds' },
                { slug: 'provider-backends/redshift' },
              ],
            },
            {
              label: 'Generic',
              collapsed: true,
              items: [{ slug: 'provider-backends/rest' }],
            },
          ],
        },
        {
          // A flat A–Z list: drivers are multi-mode, so the index page's
          // capability matrix — not the sidebar — is the real map.
          label: 'Credential drivers',
          items: [
            { slug: 'credential-drivers' },
            { slug: 'credential-drivers/alicloud' },
            { slug: 'credential-drivers/aws' },
            { slug: 'credential-drivers/azure' },
            { slug: 'credential-drivers/elastic' },
            { slug: 'credential-drivers/gcp' },
            { slug: 'credential-drivers/github' },
            { slug: 'credential-drivers/gitlab' },
            { slug: 'credential-drivers/grafana' },
            { slug: 'credential-drivers/vault' },
            { slug: 'credential-drivers/honeycomb' },
            { slug: 'credential-drivers/ibm' },
            { slug: 'credential-drivers/kubernetes' },
            { slug: 'credential-drivers/local' },
            { slug: 'credential-drivers/oauth2' },
            { slug: 'credential-drivers/ovh' },
            { slug: 'credential-drivers/scaleway' },
            { slug: 'credential-drivers/apikey' },
            { slug: 'credential-drivers/token-exchange' },
          ],
        },
        { label: 'Auth methods', autogenerate: { directory: 'auth-methods' } },
        { label: 'Agent identity', autogenerate: { directory: 'agent-identity' } },
        { label: 'CLI', autogenerate: { directory: 'cli' } },
        {
          // Server HCL config reference, in reading order. The seal subgroup
          // has one page per seal type and collapses by default.
          label: 'Configuration',
          items: [
            { slug: 'configuration' },
            { slug: 'configuration/listener' },
            { slug: 'configuration/storage' },
            {
              label: 'Seal',
              collapsed: true,
              items: [
                { slug: 'configuration/seal' },
                { slug: 'configuration/seal/shamir' },
                { slug: 'configuration/seal/awskms' },
                { slug: 'configuration/seal/azurekeyvault' },
                { slug: 'configuration/seal/gcpkms' },
                { slug: 'configuration/seal/transit' },
                { slug: 'configuration/seal/pkcs11' },
                { slug: 'configuration/seal/ocikms' },
                { slug: 'configuration/seal/kmip' },
                { slug: 'configuration/seal/static' },
              ],
            },
            { slug: 'configuration/audit' },
            {
              // The signer stanza; also surfaced under Federation.
              label: 'Signer',
              collapsed: true,
              items: [
                { slug: 'configuration/signer' },
                { slug: 'configuration/signer/transit' },
              ],
            },
          ],
        },
        { label: 'Audit devices', autogenerate: { directory: 'audit-devices' } },
        { label: 'Quickstarts', autogenerate: { directory: 'quickstarts' } },
        { label: 'Tutorials', autogenerate: { directory: 'tutorials' } },
        { label: 'Install', autogenerate: { directory: 'install' } },
        { label: 'Upgrade', autogenerate: { directory: 'upgrade' } },
      ],
    }),
  ],
});
