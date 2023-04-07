#include "certificateUtils.h"

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdexcept>

namespace certificateUtils {

    std::shared_ptr<EVP_PKEY> generate_private_key(int bits) {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!pctx) {
            throw std::runtime_error("Failed to create EVP_PKEY_CTX");
        }

        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("Failed to initialize keygen context");
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, bits) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("Failed to set RSA keygen bits");
        }

        EVP_PKEY* raw_pkey = NULL;
        if (EVP_PKEY_keygen(pctx, &raw_pkey) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            throw std::runtime_error("Failed to generate RSA private key");
        }

        std::shared_ptr<EVP_PKEY> pkey(raw_pkey, ::EVP_PKEY_free);
        EVP_PKEY_CTX_free(pctx);
        return pkey;
    }

    std::shared_ptr<X509> generate_self_signed_certificate(
        const std::string& cn, EVP_PKEY* pkey, int days) {
        std::shared_ptr<X509> cert(X509_new(), ::X509_free);

        // Set the certificate version
        if (X509_set_version(cert.get(), 2) != 1) {
            throw std::runtime_error("Failed to set certificate version");
        }

        // Set a random serial number
        if (ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), rand()) != 1) {
            throw std::runtime_error("Failed to set certificate serial number");
        }

        // Set the subject and issuer name (same for self-signed certificates)
        X509_NAME* name = X509_get_subject_name(cert.get());
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
        X509_set_issuer_name(cert.get(), name);

        // Set the public key
        if (X509_set_pubkey(cert.get(), pkey) != 1) {
            throw std::runtime_error("Failed to set certificate public key");
        }

        // Set the validity period
        if (!X509_gmtime_adj(X509_get_notBefore(cert.get()), 0) ||
            !X509_gmtime_adj(X509_get_notAfter(cert.get()), days * 24 * 60 * 60)) {
            throw std::runtime_error("Failed to set certificate validity period");
        }

        // Sign the certificate
        if (X509_sign(cert.get(), pkey, EVP_sha256()) == 0) {
            throw std::runtime_error("Failed to sign certificate");
        }

        return cert;
    }

    std::shared_ptr<X509> load_ca_certificate() {
        const char* ca_certificate_pem = R"(
-----BEGIN CERTIFICATE-----
MIIDozCCAougAwIBAgIUav5ti5s4kAmaTL5EIJv6o4ub13MwDQYJKoZIhvcNAQEL
BQAwYTELMAkGA1UEBhMCcXcxCzAJBgNVBAgMAnF3MQswCQYDVQQHDAJxdzELMAkG
A1UECgwCcXcxCzAJBgNVBAsMAnF3MQswCQYDVQQDDAJxdzERMA8GCSqGSIb3DQEJ
ARYCcXcwHhcNMjMwNDA2MTgzODMzWhcNMjYwMTI0MTgzODMzWjBhMQswCQYDVQQG
EwJxdzELMAkGA1UECAwCcXcxCzAJBgNVBAcMAnF3MQswCQYDVQQKDAJxdzELMAkG
A1UECwwCcXcxCzAJBgNVBAMMAnF3MREwDwYJKoZIhvcNAQkBFgJxdzCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAN+tjwBcqVuHZr4Maa+OfvrRx0RehLpz
cZzBqbXTxjcA8OJlf8T2EX7aLDVzQDhjZy6F2QqkGJF8cBP0MiQmnP+lBvkUDDBq
9CN9J0x1UAcgAeiMlfwjnfyHX9S79p5KBuV6v9RRpcgUEOpyvKG1BROA+ubpCkqm
jMXExnrnnAXLHfeONt9yBm52jMwmbPv2Gd/9FsfDV3Xtt5j2ux2C4oYRBgs2nNcm
2EJPSas0vNv/rxjW3y6aGmFKlgLd7YQnxOBsJmhCdNqSHYN7zDR9Ds8r0upknZ1w
bGFepir89y1vVlKaJKObuaqkxNDlk/AD8XaUH0W3mT+qc+7OdG3zJ60CAwEAAaNT
MFEwHQYDVR0OBBYEFLhf5czi6SqXW8lOKGC2CX4IIyESMB8GA1UdIwQYMBaAFLhf
5czi6SqXW8lOKGC2CX4IIyESMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAMGVqY9kli/eOFR6tP9VnWNyI/Zt+pqYcii1Pf08DtR0j4Yqw9dWyNdX
NYM/Mi3n/B1PnYch83LlSlgUyar+N3uesQhCKih9kmwZe4KoymwUbEZ5jplNJqjL
i+wxx/YuWTfR3kGWeEu25GWR9dbKqsL7xGZO+hqZixcrxM8lyyPquus4rGQPumop
I18z9FcWrDzJgEwW/n7+ZR8PRODdVe/6h7RWq+XK8PU6dhet7K/fHZuuajTgPDFd
h3VsDIcdFNv+mkUnUXU8gYq+SZygkXIdxXiQLzda33U3NFRvzITTg+egSfEsHeQc
K/gBOfHkD2F27LYTDw837mA9bNECoUI=
-----END CERTIFICATE-----
)";

        BIO* bio = BIO_new_mem_buf(ca_certificate_pem, -1);
        if (!bio) {
            throw std::runtime_error("Failed to create BIO for CA certificate");
        }

        std::shared_ptr<X509> ca_cert(PEM_read_bio_X509(bio, nullptr, nullptr, nullptr), ::X509_free);
        BIO_free(bio);

        if (!ca_cert) {
            throw std::runtime_error("Failed to load CA certificate");
        }

        return ca_cert;
    }

    std::string private_key_to_pem(EVP_PKEY* pkey) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw std::runtime_error("Failed to create BIO for private key");
        }

        if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            BIO_free(bio);
            throw std::runtime_error("Failed to write private key to BIO");
        }

        BUF_MEM* mem;
        BIO_get_mem_ptr(bio, &mem);
        std::string pem_key(mem->data, mem->length);
        BIO_free(bio);

        return pem_key;
    }

    std::string certificate_to_pem(X509* cert) {
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw std::runtime_error("Failed to create BIO for certificate");
        }
        if (PEM_write_bio_X509(bio, cert) != 1) {
            BIO_free(bio);
            throw std::runtime_error("Failed to write certificate to BIO");
        }

        BUF_MEM* mem;
        BIO_get_mem_ptr(bio, &mem);
        std::string pem_cert(mem->data, mem->length);
        BIO_free(bio);

        return pem_cert;
    }

    bool custom_verify_callback(bool preverified, boost::asio::ssl::verify_context& ctx, const std::string& expected_cn)
    {
        // Get the X509_STORE_CTX object
        X509_STORE_CTX* store_ctx = ctx.native_handle();

        // Get the current certificate and its depth in the chain
        int depth = X509_STORE_CTX_get_error_depth(store_ctx);
        X509* cert = X509_STORE_CTX_get_current_cert(store_ctx);

        // Convert the X509 certificate to a human-readable format
        BIO* bio = BIO_new(BIO_s_mem());
        X509_print(bio, cert);
        BUF_MEM* mem;
        BIO_get_mem_ptr(bio, &mem);
        std::string cert_info(mem->data, mem->length);
        BIO_free(bio);


        // Retrieve the subject name from the certificate
        X509_NAME* subject_name = X509_get_subject_name(cert);
        if (subject_name == NULL) {
            return false; // Reject the certificate
        }

        // Get the CN (Common Name) from the subject name
        char common_name[256];
        X509_NAME_get_text_by_NID(subject_name, NID_commonName, common_name, sizeof(common_name));

        // Check if the CN matches the expected value
        if (expected_cn == common_name) {
            return true;
        }
        else {
            return false; // Reject the certificate if the CN does not match
        }
    }
}