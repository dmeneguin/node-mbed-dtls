#ifndef __DTLS_SERVER_H__
#define __DTLS_SERVER_H__

#include <napi.h>
#include <uv.h>

// NOTE: These include files are order-sensitive!
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

class DtlsServer : public Napi::ObjectWrap<DtlsServer> {
public:
  static Napi::FunctionReference constructor;
  static Napi::Object Initialize(Napi::Env env, Napi::Object exports);
  void SetHandshakeTimeoutMin(const Napi::CallbackInfo& info, const Napi::Value& value);
  DtlsServer(const Napi::CallbackInfo& info);
  inline mbedtls_ssl_config* config() { return &conf; }
  Napi::FunctionReference get_psk;
  char *getPskFromIdentity(char *identity);
  ~DtlsServer();
private:
  Napi::Env env;
  void throwError(int ret);
  mbedtls_ssl_cookie_ctx cookie_ctx;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt srvcert;
  mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_context cache;
#endif

};

#endif
