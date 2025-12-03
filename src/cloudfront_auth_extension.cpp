#define DUCKDB_EXTENSION_MAIN

#include "cloudfront_auth_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension_helper.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"
#include "duckdb/main/database.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace duckdb {

//===--------------------------------------------------------------------===//
// CloudFront Cookie Signing Implementation
//===--------------------------------------------------------------------===//

static string MakeUrlSafeBase64(const string &data) {
	BIO *bio = BIO_new(BIO_s_mem());
	BIO *b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bio = BIO_push(b64, bio);

	BIO_write(bio, data.c_str(), static_cast<int>(data.size()));
	BIO_flush(bio);

	BUF_MEM *buffer;
	BIO_get_mem_ptr(bio, &buffer);

	string encoded(buffer->data, buffer->length);
	BIO_free_all(bio);

	// Make URL-safe: + -> -, = -> _, / -> ~
	for (auto &c : encoded) {
		if (c == '+')
			c = '-';
		else if (c == '=')
			c = '_';
		else if (c == '/')
			c = '~';
	}

	return encoded;
}

static string SignWithRSA(const string &data, EVP_PKEY *pkey) {
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		throw IOException("Failed to create EVP_MD_CTX");
	}

	if (EVP_DigestSignInit(ctx, nullptr, EVP_sha1(), nullptr, pkey) <= 0) {
		EVP_MD_CTX_free(ctx);
		throw IOException("Failed to initialize signing context");
	}

	if (EVP_DigestSignUpdate(ctx, data.c_str(), data.size()) <= 0) {
		EVP_MD_CTX_free(ctx);
		throw IOException("Failed to update signing context");
	}

	size_t sig_len = 0;
	if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) <= 0) {
		EVP_MD_CTX_free(ctx);
		throw IOException("Failed to get signature length");
	}

	string signature(sig_len, '\0');
	if (EVP_DigestSignFinal(ctx, reinterpret_cast<unsigned char *>(&signature[0]), &sig_len) <= 0) {
		EVP_MD_CTX_free(ctx);
		throw IOException("Failed to sign data");
	}

	EVP_MD_CTX_free(ctx);
	signature.resize(sig_len);
	return signature;
}

static EVP_PKEY *LoadPrivateKeyFromFile(const string &key_path) {
	FILE *fp = fopen(key_path.c_str(), "r");
	if (!fp) {
		throw IOException("Cannot open private key file: " + key_path);
	}

	EVP_PKEY *pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
	fclose(fp);

	if (!pkey) {
		throw IOException("Failed to read private key from: " + key_path);
	}

	return pkey;
}

static EVP_PKEY *LoadPrivateKeyFromString(const string &key_content) {
	BIO *bio = BIO_new_mem_buf(key_content.c_str(), static_cast<int>(key_content.size()));
	if (!bio) {
		throw IOException("Failed to create BIO for private key");
	}

	EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);

	if (!pkey) {
		throw IOException("Failed to parse private key from string");
	}

	return pkey;
}

struct CloudFrontCookies {
	string policy;
	string signature;
	string key_pair_id;
};

static CloudFrontCookies GenerateSignedCookiesWithKey(const string &cloudfront_domain, const string &key_pair_id,
                                                      EVP_PKEY *pkey, const string &resource_pattern = "*",
                                                      int64_t expiration_hours = 24) {
	auto now = std::chrono::system_clock::now();
	auto expiration = now + std::chrono::hours(expiration_hours);
	auto expiration_epoch = std::chrono::duration_cast<std::chrono::seconds>(expiration.time_since_epoch()).count();

	string resource_url = "https://" + cloudfront_domain + "/" + resource_pattern;

	std::ostringstream policy_stream;
	policy_stream << "{\"Statement\":[{\"Resource\":\"" << resource_url
	              << "\",\"Condition\":{\"DateLessThan\":{\"AWS:EpochTime\":" << expiration_epoch << "}}}]}";
	string policy_json = policy_stream.str();

	string signature = SignWithRSA(policy_json, pkey);

	CloudFrontCookies cookies;
	cookies.policy = MakeUrlSafeBase64(policy_json);
	cookies.signature = MakeUrlSafeBase64(signature);
	cookies.key_pair_id = key_pair_id;

	return cookies;
}

static string GenerateCookieHeaderWithKey(const string &domain, const string &key_pair_id, EVP_PKEY *pkey,
                                          const string &resource_pattern = "*", int64_t expiration_hours = 24) {
	auto cookies = GenerateSignedCookiesWithKey(domain, key_pair_id, pkey, resource_pattern, expiration_hours);
	return "CloudFront-Policy=" + cookies.policy + "; CloudFront-Signature=" + cookies.signature +
	       "; CloudFront-Key-Pair-Id=" + cookies.key_pair_id;
}

//===--------------------------------------------------------------------===//
// Helper to get environment variable (case-insensitive)
//===--------------------------------------------------------------------===//

static const char *TryGetEnv(const char *name) {
	const char *res = std::getenv(name);
	if (res) {
		return res;
	}
	return std::getenv(StringUtil::Upper(name).c_str());
}

//===--------------------------------------------------------------------===//
// Helper to extract domain from scope
//===--------------------------------------------------------------------===//

static string ExtractDomainFromScope(const vector<string> &scope) {
	if (scope.empty()) {
		throw InvalidInputException("CloudFront secret requires SCOPE parameter");
	}

	const string &scope_str = scope[0];
	if (!StringUtil::StartsWith(scope_str, "https://")) {
		throw InvalidInputException("SCOPE must start with https://");
	}

	string domain = scope_str.substr(8);
	auto slash_pos = domain.find('/');
	if (slash_pos != string::npos) {
		domain = domain.substr(0, slash_pos);
	}
	return domain;
}

//===--------------------------------------------------------------------===//
// Helper to create the secret with cookie header
//===--------------------------------------------------------------------===//

static unique_ptr<KeyValueSecret> CreateCloudFrontSecret(const vector<string> &scope, const string &provider,
                                                         const string &name, const string &cookie_header) {
	auto secret = make_uniq<KeyValueSecret>(scope, "http", provider, name);

	// Set extra_http_headers with Cookie
	vector<Value> keys = {Value("Cookie")};
	vector<Value> values = {Value(cookie_header)};
	auto cookie_map = Value::MAP(LogicalType::VARCHAR, LogicalType::VARCHAR, std::move(keys), std::move(values));
	secret->secret_map["extra_http_headers"] = cookie_map;

	return secret;
}

//===--------------------------------------------------------------------===//
// CloudFront Secret Type - Config Provider
// Usage: CREATE SECRET (TYPE cloudfront, KEY_PAIR_ID 'xxx', PRIVATE_KEY_PATH 'path', SCOPE 'https://...')
// Or:    CREATE SECRET (TYPE cloudfront, KEY_PAIR_ID 'xxx', PRIVATE_KEY '-----BEGIN...', SCOPE 'https://...')
//===--------------------------------------------------------------------===//

static unique_ptr<BaseSecret> CreateCloudFrontSecretFromConfig(ClientContext &context, CreateSecretInput &input) {
	string key_pair_id;
	string private_key_path;
	string private_key_content;
	string resource_pattern = "*";
	int64_t expiration_hours = 24;

	// Get KEY_PAIR_ID (required)
	auto key_pair_it = input.options.find("key_pair_id");
	if (key_pair_it == input.options.end()) {
		throw InvalidInputException("CloudFront secret requires KEY_PAIR_ID parameter");
	}
	key_pair_id = key_pair_it->second.ToString();

	// Get PRIVATE_KEY or PRIVATE_KEY_PATH (one required)
	auto private_key_it = input.options.find("private_key");
	auto private_key_path_it = input.options.find("private_key_path");

	if (private_key_it != input.options.end()) {
		private_key_content = private_key_it->second.ToString();
	} else if (private_key_path_it != input.options.end()) {
		private_key_path = private_key_path_it->second.ToString();
	} else {
		throw InvalidInputException("CloudFront secret requires PRIVATE_KEY or PRIVATE_KEY_PATH parameter");
	}

	// Optional parameters
	auto resource_it = input.options.find("resource_pattern");
	if (resource_it != input.options.end()) {
		resource_pattern = resource_it->second.ToString();
	}

	auto expiration_it = input.options.find("expiration_hours");
	if (expiration_it != input.options.end()) {
		expiration_hours = expiration_it->second.GetValue<int64_t>();
	}

	// Extract domain from scope
	string domain = ExtractDomainFromScope(input.scope);

	// Load private key and generate cookie header
	EVP_PKEY *pkey;
	if (!private_key_content.empty()) {
		pkey = LoadPrivateKeyFromString(private_key_content);
	} else {
		pkey = LoadPrivateKeyFromFile(private_key_path);
	}

	string cookie_header = GenerateCookieHeaderWithKey(domain, key_pair_id, pkey, resource_pattern, expiration_hours);
	EVP_PKEY_free(pkey);

	return CreateCloudFrontSecret(input.scope, input.provider, input.name, cookie_header);
}

//===--------------------------------------------------------------------===//
// CloudFront Secret Type - Env Provider
// Usage: CREATE SECRET (TYPE cloudfront, PROVIDER env, SCOPE 'https://...')
// Reads from: CLOUDFRONT_KEY_PAIR_ID, CLOUDFRONT_PRIVATE_KEY or CLOUDFRONT_PRIVATE_KEY_PATH
//===--------------------------------------------------------------------===//

static unique_ptr<BaseSecret> CreateCloudFrontSecretFromEnv(ClientContext &context, CreateSecretInput &input) {
	string key_pair_id;
	string private_key_path;
	string private_key_content;
	string resource_pattern = "*";
	int64_t expiration_hours = 24;

	// Get KEY_PAIR_ID from env or override
	auto key_pair_it = input.options.find("key_pair_id");
	if (key_pair_it != input.options.end()) {
		key_pair_id = key_pair_it->second.ToString();
	} else {
		const char *env_key_pair_id = TryGetEnv("CLOUDFRONT_KEY_PAIR_ID");
		if (!env_key_pair_id) {
			throw InvalidInputException(
			    "CloudFront secret requires KEY_PAIR_ID parameter or CLOUDFRONT_KEY_PAIR_ID environment variable");
		}
		key_pair_id = env_key_pair_id;
	}

	// Get PRIVATE_KEY or PRIVATE_KEY_PATH from env or override
	auto private_key_it = input.options.find("private_key");
	auto private_key_path_it = input.options.find("private_key_path");

	if (private_key_it != input.options.end()) {
		private_key_content = private_key_it->second.ToString();
	} else if (private_key_path_it != input.options.end()) {
		private_key_path = private_key_path_it->second.ToString();
	} else {
		// Try environment variables
		const char *env_private_key = TryGetEnv("CLOUDFRONT_PRIVATE_KEY");
		const char *env_private_key_path = TryGetEnv("CLOUDFRONT_PRIVATE_KEY_PATH");

		if (env_private_key) {
			private_key_content = env_private_key;
		} else if (env_private_key_path) {
			private_key_path = env_private_key_path;
		} else {
			throw InvalidInputException("CloudFront secret requires PRIVATE_KEY/PRIVATE_KEY_PATH parameter or "
			                            "CLOUDFRONT_PRIVATE_KEY/CLOUDFRONT_PRIVATE_KEY_PATH environment variable");
		}
	}

	// Optional parameters (from options or env)
	auto resource_it = input.options.find("resource_pattern");
	if (resource_it != input.options.end()) {
		resource_pattern = resource_it->second.ToString();
	} else {
		const char *env_resource = TryGetEnv("CLOUDFRONT_RESOURCE_PATTERN");
		if (env_resource) {
			resource_pattern = env_resource;
		}
	}

	auto expiration_it = input.options.find("expiration_hours");
	if (expiration_it != input.options.end()) {
		expiration_hours = expiration_it->second.GetValue<int64_t>();
	} else {
		const char *env_expiration = TryGetEnv("CLOUDFRONT_EXPIRATION_HOURS");
		if (env_expiration) {
			expiration_hours = std::stoll(env_expiration);
		}
	}

	// Extract domain from scope
	string domain = ExtractDomainFromScope(input.scope);

	// Load private key and generate cookie header
	EVP_PKEY *pkey;
	if (!private_key_content.empty()) {
		pkey = LoadPrivateKeyFromString(private_key_content);
	} else {
		pkey = LoadPrivateKeyFromFile(private_key_path);
	}

	string cookie_header = GenerateCookieHeaderWithKey(domain, key_pair_id, pkey, resource_pattern, expiration_hours);
	EVP_PKEY_free(pkey);

	return CreateCloudFrontSecret(input.scope, input.provider, input.name, cookie_header);
}

//===--------------------------------------------------------------------===//
// Scalar Functions
//===--------------------------------------------------------------------===//

static void CloudFrontVersionFunc(DataChunk &args, ExpressionState &state, Vector &result) {
	result.SetValue(0, Value("cloudfront_auth v0.1.0"));
}

//===--------------------------------------------------------------------===//
// Extension Loading
//===--------------------------------------------------------------------===//

static void LoadInternal(ExtensionLoader &loader) {
	// Register CloudFront secret type
	SecretType cloudfront_type;
	cloudfront_type.name = "cloudfront";
	cloudfront_type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	cloudfront_type.default_provider = "config";
	loader.RegisterSecretType(cloudfront_type);

	// Register CloudFront secret function (config provider)
	CreateSecretFunction cloudfront_config_func;
	cloudfront_config_func.secret_type = "cloudfront";
	cloudfront_config_func.provider = "config";
	cloudfront_config_func.function = CreateCloudFrontSecretFromConfig;
	cloudfront_config_func.named_parameters["key_pair_id"] = LogicalType::VARCHAR;
	cloudfront_config_func.named_parameters["private_key"] = LogicalType::VARCHAR;
	cloudfront_config_func.named_parameters["private_key_path"] = LogicalType::VARCHAR;
	cloudfront_config_func.named_parameters["resource_pattern"] = LogicalType::VARCHAR;
	cloudfront_config_func.named_parameters["expiration_hours"] = LogicalType::BIGINT;
	loader.RegisterFunction(cloudfront_config_func);

	// Register CloudFront secret function (env provider)
	CreateSecretFunction cloudfront_env_func;
	cloudfront_env_func.secret_type = "cloudfront";
	cloudfront_env_func.provider = "env";
	cloudfront_env_func.function = CreateCloudFrontSecretFromEnv;
	cloudfront_env_func.named_parameters["key_pair_id"] = LogicalType::VARCHAR;
	cloudfront_env_func.named_parameters["private_key"] = LogicalType::VARCHAR;
	cloudfront_env_func.named_parameters["private_key_path"] = LogicalType::VARCHAR;
	cloudfront_env_func.named_parameters["resource_pattern"] = LogicalType::VARCHAR;
	cloudfront_env_func.named_parameters["expiration_hours"] = LogicalType::BIGINT;
	loader.RegisterFunction(cloudfront_env_func);

	// Register version function
	auto version_func = ScalarFunction("cloudfront_auth_version", {}, LogicalType::VARCHAR, CloudFrontVersionFunc);
	loader.RegisterFunction(version_func);
}

void CloudfrontAuthExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

std::string CloudfrontAuthExtension::Name() {
	return "cloudfront_auth";
}

std::string CloudfrontAuthExtension::Version() const {
#ifdef EXT_VERSION_CLOUDFRONT_AUTH
	return EXT_VERSION_CLOUDFRONT_AUTH;
#else
	return "0.1.0";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(cloudfront_auth, loader) {
	duckdb::LoadInternal(loader);
}
}
