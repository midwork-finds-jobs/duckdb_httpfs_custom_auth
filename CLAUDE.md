# duckdb extension to make custom auth headers for httpfs

`httpfs` core extension for duckdb already supports custom headers like this:

```sql
CREATE SECRET http_auth (
    TYPE http,
    EXTRA_HTTP_HEADERS MAP {
        'Authorization': 'Bearer token'
    }
);
```

## Cloudfront cookies

I want to have ability to tell duckdb to generate cloudfront cookies like ../cloudfront-commoncrawl/duckdb-arrow.sh does but directly integrated into duckdb custom extension.

the syntax should integrate directly to http secret type or into new cloudfront type:

```sql
-- this is directly integrating to http
CREATE SECRET http_auth (
    TYPE http,
    CLOUDFRONT_COOKIE_SIGNING_KEY './path/to/privatekey.key'
    SCOPE 'https://ds5q9oxwqwsfj.cloudfront.net/'
);

-- this is a new secret type
CREATE SECRET cloudfront_cookies (
    TYPE cloudfront,
    COOKIE_SIGNING_PRIVATE_KEY './path/to/privatekey.key'
    SCOPE 'https://ds5q9oxwqwsfj.cloudfront.net/'
);
```

**NOTE: Search also which kind of syntax is typically used here and use idiomatic DuckDB terms.**
