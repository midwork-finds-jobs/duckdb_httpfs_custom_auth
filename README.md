# cloudfront_auth

DuckDB extension for AWS CloudFront signed cookie authentication. Automatically generates signed cookies for CloudFront distributions, enabling authenticated HTTP access to protected content.

## Quick Start

```sql
LOAD cloudfront_auth;
LOAD httpfs;

-- Create CloudFront secret
CREATE SECRET cf_auth (
    TYPE cloudfront,
    KEY_PAIR_ID 'YYYYYYYYYYY',
    PRIVATE_KEY_PATH '/path/to/private_key.pem',
    SCOPE 'https://XXXXXXXX.cloudfront.net/'
);

-- Query your protected CloudFront content
SELECT * FROM read_parquet('https://XXXXXXXX.cloudfront.net/data.parquet');

-- Call your protected lambda function
SELECT * FROM read_parquet('https://XXXXXXXX.cloudfront.net/api/?params=values');
```

## Installation

```sql
-- Install from community extensions (when available)
INSTALL cloudfront_auth FROM community;
LOAD cloudfront_auth;
```

## Usage

### Config Provider (Default)

Specify credentials directly in the CREATE SECRET statement:

```sql
CREATE SECRET my_cf_secret (
    TYPE cloudfront,
    KEY_PAIR_ID 'K2JCJMDEHXQW5F',
    PRIVATE_KEY_PATH '/path/to/private_key.pem',
    SCOPE 'https://d111111abcdef8.cloudfront.net/'
);
```

#### Using inline private key

Pass the PEM content directly instead of a file path:

```sql
-- Read key content from file and pass inline
CREATE SECRET my_cf_secret (
    TYPE cloudfront,
    KEY_PAIR_ID 'K2JCJMDEHXQW5F',
    PRIVATE_KEY (SELECT content FROM read_text('private_key.pem')),
    SCOPE 'https://d111111abcdef8.cloudfront.net/'
);
```

### Env Provider

Read credentials from environment variables:

```sql
CREATE SECRET my_cf_secret (
    TYPE cloudfront,
    PROVIDER env,
    SCOPE 'https://d111111abcdef8.cloudfront.net/'
);
```

Environment variables:

| Variable | Description |
|----------|-------------|
| `CLOUDFRONT_KEY_PAIR_ID` | CloudFront key pair ID (required) |
| `CLOUDFRONT_PRIVATE_KEY` | PEM private key content |
| `CLOUDFRONT_PRIVATE_KEY_PATH` | Path to PEM private key file |
| `CLOUDFRONT_RESOURCE_PATTERN` | Resource pattern (optional, default: `*`) |
| `CLOUDFRONT_EXPIRATION_HOURS` | Cookie expiration hours (optional, default: `24`) |

Note: Either `CLOUDFRONT_PRIVATE_KEY` or `CLOUDFRONT_PRIVATE_KEY_PATH` must be set.

You can override env values with explicit parameters:

```sql
CREATE SECRET my_cf_secret (
    TYPE cloudfront,
    PROVIDER env,
    KEY_PAIR_ID 'OVERRIDE_KEY_ID',  -- overrides CLOUDFRONT_KEY_PAIR_ID
    SCOPE 'https://d111111abcdef8.cloudfront.net/'
);
```

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `KEY_PAIR_ID` | Yes | - | CloudFront key pair ID |
| `PRIVATE_KEY` | Yes* | - | PEM private key content |
| `PRIVATE_KEY_PATH` | Yes* | - | Path to PEM private key file |
| `SCOPE` | Yes | - | CloudFront URL scope (must start with `https://`) |
| `RESOURCE_PATTERN` | No | `*` | Resource pattern for signed policy |
| `EXPIRATION_HOURS` | No | `24` | Cookie expiration in hours |

*Either `PRIVATE_KEY` or `PRIVATE_KEY_PATH` is required.

### Viewing Secrets

```sql
-- List all secrets
SELECT name, type, scope FROM duckdb_secrets();

-- View secret details (shows cookie values)
SELECT * FROM duckdb_secrets() WHERE name = 'my_cf_secret';
```

### How It Works

The extension:

1. Generates CloudFront signed cookies (Policy, Signature, Key-Pair-Id)
2. Creates an internal `http` type secret with cookies in `extra_http_headers`
3. httpfs automatically uses matching secrets for HTTP requests

Cookies are generated once at secret creation and reused for all requests.

## Building

### Dependencies

Requires OpenSSL. Use VCPKG:

```sh
git clone https://github.com/Microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh
export VCPKG_TOOLCHAIN_PATH=$(pwd)/vcpkg/scripts/buildsystems/vcpkg.cmake
```

### Build

```sh
git submodule update --init --recursive
make release GEN=ninja VCPKG_TOOLCHAIN_PATH=$(pwd)/vcpkg/scripts/buildsystems/vcpkg.cmake
```

### Test

```sh
make test
```

## AWS CloudFront Setup

### Prerequisites

1. S3 bucket with your data (or a Lambda)
2. CloudFront distribution
3. CloudFront key pair for signing

### Terraform Example

Complete example to provision S3, CloudFront, and signing keys:

```hcl
# main.tf

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Generate RSA key pair for CloudFront signing
resource "tls_private_key" "cloudfront_signing" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# S3 bucket for data
resource "aws_s3_bucket" "data" {
  bucket_prefix = "my-cloudfront-data-"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudFront Origin Access Control
resource "aws_cloudfront_origin_access_control" "data" {
  name                              = "s3-oac"
  description                       = "OAC for S3 bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# CloudFront public key for cookie signing
resource "aws_cloudfront_public_key" "signing" {
  name        = "cloudfront-signing-key"
  encoded_key = tls_private_key.cloudfront_signing.public_key_pem
}

# CloudFront key group
resource "aws_cloudfront_key_group" "signing" {
  name  = "cloudfront-signing-group"
  items = [aws_cloudfront_public_key.signing.id]
}

# CloudFront distribution
resource "aws_cloudfront_distribution" "data" {
  enabled             = true
  default_root_object = "index.html"
  price_class         = "PriceClass_100"

  origin {
    domain_name              = aws_s3_bucket.data.bucket_regional_domain_name
    origin_id                = "S3Origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.data.id
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3Origin"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    # Require signed cookies
    trusted_key_groups = [aws_cloudfront_key_group.signing.id]

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

# S3 bucket policy for CloudFront access
resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontServicePrincipal"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.data.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.data.arn
          }
        }
      }
    ]
  })
}

# Output the values needed for DuckDB
output "cloudfront_domain" {
  value       = aws_cloudfront_distribution.data.domain_name
  description = "CloudFront distribution domain"
}

output "cloudfront_key_pair_id" {
  value       = aws_cloudfront_public_key.signing.id
  description = "CloudFront key pair ID for signing"
}

output "private_key_pem" {
  value       = tls_private_key.cloudfront_signing.private_key_pem
  sensitive   = true
  description = "Private key for signing (save to file)"
}

output "s3_bucket" {
  value       = aws_s3_bucket.data.id
  description = "S3 bucket name for uploading data"
}
```

### Deploy and Use

```sh
# Deploy infrastructure
terraform init
terraform apply

# Save private key
terraform output -raw private_key_pem > cloudfront_private_key.pem
chmod 600 cloudfront_private_key.pem

# Get values
export CF_DOMAIN=$(terraform output -raw cloudfront_domain)
export CF_KEY_PAIR_ID=$(terraform output -raw cloudfront_key_pair_id)
export S3_BUCKET=$(terraform output -raw s3_bucket)

# Upload test data
aws s3 cp data.parquet s3://$S3_BUCKET/

# Query with DuckDB
duckdb -c "
LOAD cloudfront_auth;
LOAD httpfs;

CREATE SECRET cf (
    TYPE cloudfront,
    KEY_PAIR_ID '$CF_KEY_PAIR_ID',
    PRIVATE_KEY_PATH 'cloudfront_private_key.pem',
    SCOPE 'https://$CF_DOMAIN/'
);

SELECT * FROM read_parquet('https://$CF_DOMAIN/data.parquet');
"
```

### Using Environment Variables

For production, use environment variables:

```sh
# Set environment variables
export CLOUDFRONT_KEY_PAIR_ID=$(terraform output -raw cloudfront_key_pair_id)
export CLOUDFRONT_PRIVATE_KEY=$(terraform output -raw private_key_pem)

# Query with env provider
duckdb -c "
LOAD cloudfront_auth;
LOAD httpfs;

CREATE SECRET cf (
    TYPE cloudfront,
    PROVIDER env,
    SCOPE 'https://$(terraform output -raw cloudfront_domain)/'
);

SELECT * FROM read_parquet('https://$(terraform output -raw cloudfront_domain)/data.parquet');
"
```

## Troubleshooting

### "Access Denied" from CloudFront

- Verify key pair ID matches the CloudFront key group
- Check private key is correct (matches public key in CloudFront)
- Ensure SCOPE matches the CloudFront domain exactly
- Verify CloudFront distribution has signed cookies enabled

### "Cannot open private key file"

- Check file path is correct
- Verify file permissions (readable by DuckDB process)
- Use absolute path or path relative to working directory

### "Failed to parse private key"

- Ensure PEM format is correct
- Key should start with `-----BEGIN PRIVATE KEY-----` or `-----BEGIN RSA PRIVATE KEY-----`
- Check for extra whitespace or encoding issues

## License

MIT
