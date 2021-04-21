
#include "DtlsServer.h"

#include <stdio.h>
#include <sys/time.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf

using namespace Napi;

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
  ((void) level);

  struct timeval tp;
  gettimeofday(&tp, NULL);
  long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;

  mbedtls_fprintf((FILE *) ctx, "%013ld:%s:%04d: %s", ms, file, line, str);
  fflush((FILE *) ctx);
}


/*
 * Callback to get PSK given identity. Use the js callback to get the key.
 */
int fetchPSKGivenID(void *parameter, mbedtls_ssl_context *ssl, const unsigned char *psk_identity, size_t identity_len) {
  int status = 1;
  char *psk;
  char *pskIdentity = (char *)malloc(sizeof(char) * (identity_len+1));
  DtlsServer *dtlsServer = (DtlsServer *)parameter;

  strncpy(pskIdentity,(char*)psk_identity,identity_len);
  pskIdentity[identity_len]='\0';

  psk = dtlsServer->getPskFromIdentity(pskIdentity);

  if (!psk) {
    goto clean_and_exit;
  }

  mbedtls_ssl_set_hs_psk(ssl, (const unsigned char*)psk, strlen(psk));
  status = 0;

clean_and_exit:
  free(psk);
  free(pskIdentity);
  return status;
}


Napi::FunctionReference DtlsServer::constructor;

Napi::Object DtlsServer::Initialize(Napi::Env env, Napi::Object exports) {
	Napi::HandleScope scope(env);

	Napi::Function func = DefineClass(env, "DtlsServer", {
		InstanceAccessor("handshakeTimeoutMin", nullptr, &DtlsServer::SetHandshakeTimeoutMin),
	});

	constructor = Napi::Persistent(func);
	constructor.SuppressDestruct();

	exports.Set("DtlsServer", func);

	return exports;
}

DtlsServer::DtlsServer(const Napi::CallbackInfo& info) : Napi::ObjectWrap<DtlsServer>(info),
		env(info.Env())  {

  if (info.Length() < 2) {
    Napi::TypeError::New(env, "Expecting at least two parameters").ThrowAsJavaScriptException();
    return;
  }

  if (!info[0].IsBuffer()) {
    Napi::TypeError::New(env, "Expecting key to be a buffer").ThrowAsJavaScriptException();
    return;
  }

  if (info[1].IsFunction() == false) {
   Napi::TypeError::New(env, "Expecting param 2 to be a function").ThrowAsJavaScriptException();
   return; 
  }

	Napi::Buffer<unsigned char> key_buffer = info[0].As<Napi::Buffer<unsigned char>>();
	size_t key_len = key_buffer.Length();
	unsigned char * key = key_buffer.Data();

  get_psk = Napi::Persistent(info[1].As<Napi::Function>());

  int debug_level = 0;
  if (info.Length() > 1) {
    debug_level = info[2].ToNumber().Uint32Value();
  }

  //key     key_len  
  //srv_key srv_key_len  

  int ret;

  const char *pers = "dtls_server";
  mbedtls_ssl_config_init(&conf);
  mbedtls_ssl_cookie_init(&cookie_ctx);
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_init(&cache);
#endif
  mbedtls_x509_crt_init(&srvcert);
  mbedtls_pk_init(&pkey);

  mbedtls_ssl_conf_psk_cb(&conf, fetchPSKGivenID, this);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
  mbedtls_debug_set_threshold(debug_level);
#endif

  ret = mbedtls_pk_parse_key(&pkey,
               (const unsigned char *)key,
               key_len,
               NULL,
               0);
  if (ret != 0) goto exit;

  // TODO re-use node entropy and randomness
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
                  mbedtls_entropy_func,
                  &entropy,
                  (const unsigned char *) pers,
                  strlen(pers));
  if (ret != 0) goto exit;

  ret = mbedtls_ssl_config_defaults(&conf,
                  MBEDTLS_SSL_IS_SERVER,
                  MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                  MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) goto exit;

  mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

  // TODO use node random number generator?
  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

  ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
  if (ret != 0) goto exit;

  ret = mbedtls_ssl_cookie_setup(&cookie_ctx,
                                 mbedtls_ctr_drbg_random,
                                 &ctr_drbg);
  if (ret != 0) goto exit;

  mbedtls_ssl_conf_dtls_cookies(&conf,
                                mbedtls_ssl_cookie_write,
                                mbedtls_ssl_cookie_check,
                                &cookie_ctx);

  // needed for server to send CertificateRequest
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

  return;
exit:
  throwError(ret);
  return;
}

void DtlsServer::SetHandshakeTimeoutMin(const Napi::CallbackInfo& info, const Napi::Value& value) {
  uint32_t hs_timeout_min = value.As<Napi::Number>().Uint32Value();
	mbedtls_ssl_conf_handshake_timeout(this->config(), hs_timeout_min, this->config()->hs_timeout_max);
}

char *DtlsServer::getPskFromIdentity(char *identity) {
  char *psk = NULL;
  std::string identity_string = identity;
  Napi::Value jsPsk = get_psk.Call({
		Napi::Buffer<unsigned char>::Copy(env, (unsigned char *)identity, (size_t)identity_string.length())
	});
  Napi::String jsPsk_string = jsPsk.As<Napi::String>();
  std::string jsUtf8Psk = jsPsk_string.Utf8Value();
  int pskLen = jsUtf8Psk.length();
  if (pskLen > 0) {
    psk = (char *)malloc(sizeof(char)*(pskLen+1));
    strcpy(psk, &jsUtf8Psk[0]);
  }

  return psk;
}

void DtlsServer::throwError(int ret) {
  char error_buf[100];
  mbedtls_strerror(ret, error_buf, 100);
  Napi::Error::New(env, error_buf).ThrowAsJavaScriptException();

}

DtlsServer::~DtlsServer() {
  mbedtls_x509_crt_free( &srvcert );
  mbedtls_pk_free( &pkey );
  mbedtls_ssl_config_free( &conf );
  mbedtls_ssl_cookie_free( &cookie_ctx );
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_free( &cache );
#endif
  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy );
}
