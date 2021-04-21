#ifndef __DTLS_CLI_SOCKET_H__
#define __DTLS_CLI_SOCKET_H__

#include <napi.h>
#include <uv.h>

#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/timing.h"
#include "mbedtls/debug.h"

#define MAX_CIPHERSUITE_COUNT  30  // Number is arbitrary. Should be enough.
#define KEY_BUF_LENGTH 256
#define RECV_BUF_LENGTH 1024

class DtlsClientSocket : public Napi::ObjectWrap<DtlsClientSocket> {
public:
  static Napi::FunctionReference constructor;
  static Napi::Object Initialize(Napi::Env env, Napi::Object& target);
  Napi::Value ReceiveDataFromNode(const Napi::CallbackInfo& info);
  Napi::Value Close(const Napi::CallbackInfo& info);
  Napi::Value Send(const Napi::CallbackInfo& info);
  Napi::Value Connect(const Napi::CallbackInfo& info);
  DtlsClientSocket(const Napi::CallbackInfo& info);
  int recv(unsigned char *buf, size_t len);
  int receive_data(unsigned char *buf, int len);
  int send_encrypted(const unsigned char *buf, size_t len);
  int send(const unsigned char *buf, size_t len);
  int step();
  int close();
  void store_data(const unsigned char *buf, size_t len);
  void error(int ret);
  ~DtlsClientSocket();
private:
  Napi::Env env;
  void throwError(int ret);
  int allowed_ciphersuites[MAX_CIPHERSUITE_COUNT];
  Napi::FunctionReference send_cb;
  Napi::FunctionReference error_cb;
  Napi::FunctionReference handshake_cb;
  mbedtls_ssl_context ssl_context;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt clicert;
  mbedtls_x509_crt cacert;
  mbedtls_pk_context pkey;
  mbedtls_timing_delay_context timer;
  const unsigned char *recv_buf;
  size_t recv_len;
};

#endif
