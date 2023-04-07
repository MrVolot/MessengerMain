#pragma once
#pragma warning(disable : 4996)
#include <string>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <memory>
#include <boost/asio/ssl.hpp>

namespace certificateUtils {

	std::shared_ptr<EVP_PKEY> generate_private_key(int bits);

	std::shared_ptr<X509> generate_self_signed_certificate(const std::string& cn, EVP_PKEY* pkey, int days);

	std::shared_ptr<X509> load_ca_certificate();

	std::string private_key_to_pem(EVP_PKEY* pkey);

	std::string certificate_to_pem(X509* cert);

	bool custom_verify_callback(bool preverified, boost::asio::ssl::verify_context& ctx, const std::string& expected_cn);
}
