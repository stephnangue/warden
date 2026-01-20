# AWS Provider for Warden

The AWS provider enables secure proxying of AWS API requests with credential injection and signature verification.

## DNS Configuration Requirements

The AWS provider requires **wildcard DNS configuration** to properly handle certain AWS services that use virtual-hosted style URLs, particularly:

- **S3 Control API** (ListTagsForResource, GetAccessPointPolicy, etc.)
- **S3 Access Points**
- Any service where the account ID or resource name is prepended to the hostname

### How It Works

When AWS SDKs make S3 Control API requests, they construct URLs like:

```
https://<account-id>.s3-control.<region>.amazonaws.com/...
```

When these requests are proxied through Warden, the SDK rewrites the URL to:

```
https://<account-id>.<proxy-domain>:<port>/v1/aws/gateway/...
```

For example, with `proxy_domains=["localhost"]` and account `123456789012`:

```
https://123456789012.localhost:5000/v1/aws/gateway/v20180820/tags/...
```

### DNS Setup

For this to work, DNS must resolve wildcard subdomains to the Warden server.

#### Local Development Options

**Option 1: Using dnsmasq (recommended for macOS)**

```bash
# Install dnsmasq
brew install dnsmasq

# Configure wildcard for localhost
echo "address=/localhost/127.0.0.1" >> /opt/homebrew/etc/dnsmasq.conf

# Start dnsmasq
sudo brew services start dnsmasq

# Configure macOS to use dnsmasq for .localhost
sudo mkdir -p /etc/resolver
echo "nameserver 127.0.0.1" | sudo tee /etc/resolver/localhost
```

**Option 2: Manual /etc/hosts entry (limited, one account at a time)**

```
127.0.0.1 123456789012.localhost
```

**Option 3: Use a domain with wildcard support**

Services like [nip.io](https://nip.io) or [sslip.io](https://sslip.io) provide wildcard DNS:

```hcl
proxy_domains = ["127.0.0.1.nip.io"]
```

#### Production Setup

Configure wildcard DNS records pointing to your Warden server:

```
*.warden.yourdomain.com  →  A record or CNAME to Warden server
warden.yourdomain.com    →  A record to Warden server
```

Then configure Warden with:

```hcl
proxy_domains = ["warden.yourdomain.com"]
```

### TLS/SSL Considerations

For HTTPS in production, you'll need a **wildcard SSL certificate**:

```
*.warden.yourdomain.com
```

This can be obtained from:

- **Let's Encrypt** (free, supports wildcard via DNS-01 challenge)
- Commercial certificate authorities
- Internal PKI for private deployments

## Configuration

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `proxy_domains` | list(string) | `["localhost"]` | Domains that Warden listens on for proxied requests |
| `max_body_size` | int | `10485760` (10MB) | Maximum request body size in bytes |
| `timeout` | duration | `"30s"` | Request timeout |

### Example Configuration

```hcl
provider "aws" {
  path = "aws"
  config = {
    proxy_domains = ["warden.yourdomain.com"]
    max_body_size = 10485760  // 10MB
    timeout       = "30s"
  }
}
```

## Request Flow

1. Client signs request with Warden-issued credentials (Access Key ID / Secret Access Key)
2. Request is sent to Warden proxy endpoint
3. Warden verifies the incoming signature using the stored secret key
4. Warden retrieves real AWS credentials from the configured credential store
5. Warden re-signs the request with valid AWS credentials
6. Request is forwarded to the actual AWS endpoint
7. Response is returned to the client

## Supported AWS Services

The provider includes specialized processors for:

- **S3** - Standard S3 operations with virtual-hosted and path-style bucket addressing
- **S3 Control** - Account-level S3 operations (tagging, access points, etc.)
- **S3 Access Points** - Single and multi-region access point operations
- **Generic AWS** - Fallback processor for all other AWS services (EC2, Lambda, DynamoDB, etc.)

## Known Limitations

### Multi-Region Access Points (MRAP) Data Plane Operations

**MRAP data plane operations (PutObject, GetObject, DeleteObject, etc.) cannot be proxied through Warden.** This is a fundamental limitation of how the AWS SDK handles MRAP requests:

1. **SigV4A Signing**: MRAP data operations use Signature Version 4A (`AWS4-ECDSA-P256-SHA256`), a different signing algorithm than standard SigV4 (`AWS4-HMAC-SHA256`). Warden currently only supports SigV4.

2. **SDK Endpoint Resolution**: The AWS SDK resolves MRAP ARNs to virtual-hosted style URLs (`{alias}.mrap.accesspoint.s3-global.amazonaws.com`) and sends requests directly to AWS global endpoints, completely bypassing `AWS_ENDPOINT_URL`.

3. **Global Routing**: MRAPs are designed to automatically route requests to the nearest region, and the SDK handles this internally without respecting custom endpoints.

**What works:**
| Operation | Supported | Notes |
|-----------|-----------|-------|
| MRAP creation/deletion (S3 Control API) | ✓ Yes | Uses standard SigV4 |
| MRAP policy management (S3 Control API) | ✓ Yes | Uses standard SigV4 |
| MRAP tagging (S3 Control API) | ✓ Yes | Uses standard SigV4 |
| MRAP data operations (PutObject, GetObject) | ✗ No | Uses SigV4A, bypasses proxy |

**What doesn't work:**
```hcl
# This will NOT go through Warden - the SDK sends it directly to AWS
resource "aws_s3_object" "mrap_object" {
  bucket  = aws_s3control_multi_region_access_point.main.arn  # MRAP ARN
  key     = "my-file.txt"
  content = "Hello"
}
```

**Workaround**: For MRAP data operations, use the underlying regional buckets directly instead of the MRAP ARN, or ensure your application has direct AWS credentials for MRAP operations.

### Standard (Single-Region) Access Points

Standard S3 Access Points **are fully supported**. When using `AWS_ENDPOINT_URL`, the AWS SDK places the Access Point ARN in the request path, and Warden correctly routes these requests.

```hcl
# This works correctly through Warden
resource "aws_s3_object" "ap_object" {
  bucket  = aws_s3_access_point.main.arn  # Standard Access Point ARN
  key     = "my-file.txt"
  content = "Hello"
}
```

## Troubleshooting

### "Signature does not match" errors for S3 Control requests

1. **Verify DNS resolves correctly:**
   ```bash
   nslookup <account-id>.<proxy-domain>
   # e.g., nslookup 123456789012.localhost
   ```

2. **Check the Host header** matches what the SDK signed

3. **Ensure Warden is listening** on the resolved address

### Requests fail to reach Warden

1. The wildcard DNS is not configured
2. The `proxy_domain` doesn't match the endpoint URL configured in your AWS SDK
3. Firewall rules are blocking the connection

### S3 Control API returns 403

This typically means:
- DNS is not resolving `<account-id>.<proxy-domain>` to Warden
- The request is reaching Warden but signature verification fails due to host mismatch

### Debug Logging

Enable trace-level logging in Warden to see detailed request processing:

```hcl
log_level = "trace"
```

This will show:
- Incoming request details
- Signature verification steps
- Processor selection
- Target URL construction
- Re-signing operations
