#include "DtlsClientSocket.h"

#include <stdlib.h>

#include "mbedtls/error.h"

#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf


using namespace Napi;

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
  ((void) level);

  mbedtls_fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
  fflush((FILE *) ctx);
}

int net_send_cli( void *ctx, const unsigned char *buf, size_t len ) {
  DtlsClientSocket* socket = (DtlsClientSocket*)ctx;
  if (NULL == buf) {
    printf("Tried to send from a NULL buffer!\n");
    return 0;
  }
  return socket->send_encrypted(buf, len);
}

int net_recv_cli( void *ctx, unsigned char *buf, size_t len ) {
  DtlsClientSocket* socket = (DtlsClientSocket*)ctx;
  if (NULL == buf) {
    printf("Tried to recv into a NULL buffer!\n");
    return 0;
  }
  return socket->recv(buf, len);
}


Napi::FunctionReference DtlsClientSocket::constructor;

Napi::Object DtlsClientSocket::Initialize(Napi::Env env, Napi::Object& exports) {
  Napi::HandleScope scope(env);
  // Constructor
	Napi::Function func = DefineClass(env, "DtlsClientSocket", {
		InstanceMethod("receiveData", &DtlsClientSocket::ReceiveDataFromNode),
		InstanceMethod("close", &DtlsClientSocket::Close),
		InstanceMethod("send", &DtlsClientSocket::Send),
		InstanceMethod("connect", &DtlsClientSocket::Connect),
	});

	constructor = Napi::Persistent(func);
	constructor.SuppressDestruct();

	exports.Set("DtlsClientSocket", func);

	return exports;
}

Napi::Value DtlsClientSocket::ReceiveDataFromNode(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	Napi::HandleScope scope(env);

	if (info.Length() >= 1 && info[0].IsBuffer()) {
		Napi::Buffer<unsigned char> recv = info[0].As<Napi::Buffer<unsigned char>>();
		store_data(reinterpret_cast<unsigned char *>(recv.Data()), recv.Length());
	}

	unsigned char buf[RECV_BUF_LENGTH];
	memset(buf, 0, RECV_BUF_LENGTH);
	int len = receive_data(buf, RECV_BUF_LENGTH);
  
  return len > 0 ? Napi::Buffer<unsigned char>::Copy(env, buf, len) : env.Undefined();
}

Napi::Value DtlsClientSocket::Close(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	int ret = close();

	return Napi::Number::New(env, ret);
}

Napi::Value DtlsClientSocket::Send(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	Napi::Buffer<unsigned char> buf = info[0].As<Napi::Buffer<unsigned char>>();
	int ret = send(buf.Data(), buf.Length());
	return Napi::Number::New(env, ret);
}


Napi::Value DtlsClientSocket::Connect(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  mbedtls_ssl_set_bio(&ssl_context, this, net_send_cli, net_recv_cli, NULL);
	int ret = step();
	return Napi::Number::New(env, ret);
}


DtlsClientSocket::DtlsClientSocket(const Napi::CallbackInfo& info) :
		Napi::ObjectWrap<DtlsClientSocket>(info),
		env(info.Env()) {
	Napi::HandleScope scope(env);

  size_t priv_key_len = 0;
  size_t ca_pem_len = 0;
  size_t psk_len = 0;
  size_t ident_len = 0;
  unsigned char * priv_key =  NULL;
  unsigned char * ca_pem =  NULL;
  unsigned char * psk =  NULL;
  unsigned char * ident =  NULL;

  if(info[0].IsBuffer()){
    Napi::Buffer<unsigned char> priv_key_buffer = info[0].As<Napi::Buffer<unsigned char>>();
    priv_key_len = priv_key_buffer.Length();
    priv_key = (priv_key_len) ? priv_key_buffer.Data() : NULL;
  } else {
    mbedtls_printf("priv key is null\n");
  }

  if(info[2].IsBuffer()){
    Napi::Buffer<unsigned char> ca_pem_buffer = info[2].As<Napi::Buffer<unsigned char>>();
    ca_pem_len = ca_pem_buffer.Length();
    ca_pem = (ca_pem_len) ? ca_pem_buffer.Data() : NULL;
  } else {
    mbedtls_printf("ca pem is null\n");
  }

  if(info[3].IsBuffer()){
    Napi::Buffer<unsigned char> psk_buffer = info[3].As<Napi::Buffer<unsigned char>>();
    psk_len = psk_buffer.Length();
    psk = (psk_len) ? psk_buffer.Data() : NULL;
  } else {
    mbedtls_printf("psk is null\n");
  }

  if(info[4].IsBuffer()){
    Napi::Buffer<unsigned char> ident_buffer = info[4].As<Napi::Buffer<unsigned char>>();
    ident_len = ident_buffer.Length();
    ident = (ident_len) ? ident_buffer.Data() : NULL;
  } else {
    mbedtls_printf("ident is null\n");
  }

  send_cb  = Napi::Persistent(info[5].As<Napi::Function>());
  handshake_cb    = Napi::Persistent(info[6].As<Napi::Function>());
  error_cb = Napi::Persistent(info[7].As<Napi::Function>());

  int debug_level = 0;
  if (info.Length() > 8) {
    debug_level = info[8].ToNumber().Uint32Value();
  }

  int ret;
  const char *pers = "dtls_client";

  recv_len = 0;
  recv_buf = nullptr;

  #if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(debug_level);
  #endif

  // mbedTLS will expect this array to be null-terminated. Zero it all...
  for (int x = 0; x < MAX_CIPHERSUITE_COUNT; x++) allowed_ciphersuites[x] = 0;

  /*
  * This is essential for limiting the size of handshake packets. Many IoT
  *   devices will only support a single ciphersuite, which may not be in this list.
  * Therefore....
  * TODO: Might-could automatically scope this down based on the provded credentials.
  */
  allowed_ciphersuites[0] = MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8;   // IoTivity
  allowed_ciphersuites[1] = MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256;
  allowed_ciphersuites[2] = MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256;
  allowed_ciphersuites[3] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
  allowed_ciphersuites[4] = MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8;

  mbedtls_ssl_init(&ssl_context);
  mbedtls_x509_crt_init(&clicert);
  mbedtls_x509_crt_init(&cacert);
  mbedtls_pk_init(&pkey);
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
                              mbedtls_entropy_func,
                              &entropy,
                              (const unsigned char *) pers,
                              strlen(pers));
  if (ret != 0) goto exit;

  mbedtls_ssl_config_init(&conf);
  ret = mbedtls_ssl_config_defaults(&conf,
                                    MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) goto exit;
  mbedtls_ssl_conf_ciphersuites(&conf, allowed_ciphersuites);

  mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

  if ((NULL != ca_pem) && (ca_pem_len > 0)) {
    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) ca_pem, ca_pem_len);
    if (ret != 0) goto exit;
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
  }

  if ((NULL != priv_key) && (priv_key_len > 0)) {
    ret = mbedtls_ssl_conf_own_cert(&conf, &clicert, &pkey);
    if (ret != 0) goto exit;
  }

  if ((NULL != ident) && (NULL != psk)) {
    ret = mbedtls_ssl_conf_psk(&conf, (const unsigned char*)psk, psk_len, (const unsigned char*) ident, ident_len);
    if (ret != 0) goto exit;
  }

  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

  if((ret = mbedtls_ssl_setup(&ssl_context, &conf)) != 0) goto exit;

  mbedtls_ssl_set_timer_cb(&ssl_context,
                           &timer,
                           mbedtls_timing_set_delay,
                           mbedtls_timing_get_delay);

  // TODO: Below needs audit and (at minimum) a case-off.
  if( ( ret = mbedtls_ssl_set_hostname(&ssl_context, "localhost" ) ) != 0 ) {
    mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned 0x%04x\n\n", ret);
    goto exit;
  }

  return;
exit:
  throwError(ret);
  return;
}

int DtlsClientSocket::send_encrypted(const unsigned char *buf, size_t len) {
  send_cb.Call({
		Napi::Buffer<unsigned char>::Copy(env, (unsigned char *)buf, len)
	});
  return len;
}

int DtlsClientSocket::recv(unsigned char *buf, size_t len) {
  if (recv_len != 0) {
    len = recv_len;
    memcpy(buf, recv_buf, recv_len);
    recv_buf = NULL;
    recv_len = 0;
    return len;
  }

  return MBEDTLS_ERR_SSL_WANT_READ;
}

int DtlsClientSocket::send(const unsigned char *buf, size_t len) {
  int ret;
  ret = mbedtls_ssl_write(&ssl_context, buf, len);
  if (ret < 0)
  {
    error(ret);
    return ret;
  }
  len = ret;
  return ret;
}

int DtlsClientSocket::receive_data(unsigned char *buf, int len) {
  int ret;

  if (ssl_context.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
    // normal reading of unencrypted data
    memset(buf, 0, len);
    ret = mbedtls_ssl_read(&ssl_context, buf, len);
    if (ret <= 0) {
      error(ret);
      return 0;
    }
    return ret;
  }
  return step();
}


const char* _mbedtls_state_to_string(int x) {
  switch (x) {
    case MBEDTLS_SSL_HELLO_REQUEST:                     return "HELLO_REQUEST";
    case MBEDTLS_SSL_CLIENT_HELLO:                      return "CLIENT_HELLO";
    case MBEDTLS_SSL_SERVER_HELLO:                      return "SERVER_HELLO";
    case MBEDTLS_SSL_SERVER_CERTIFICATE:                return "SERVER_CERTIFICATE";
    case MBEDTLS_SSL_SERVER_KEY_EXCHANGE:               return "SERVER_KEY_EXCHANGE";
    case MBEDTLS_SSL_CERTIFICATE_REQUEST:               return "CERTIFICATE_REQUEST";
    case MBEDTLS_SSL_SERVER_HELLO_DONE:                 return "SERVER_HELLO_DONE";
    case MBEDTLS_SSL_CLIENT_CERTIFICATE:                return "CLIENT_CERTIFICATE";
    case MBEDTLS_SSL_CLIENT_KEY_EXCHANGE:               return "CLIENT_KEY_EXCHANGE";
    case MBEDTLS_SSL_CERTIFICATE_VERIFY:                return "CERTIFICATE_VERIFY";
    case MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC:         return "CLIENT_CHANGE_CIPHER_SPEC";
    case MBEDTLS_SSL_CLIENT_FINISHED:                   return "CLIENT_FINISHED";
    case MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC:         return "SERVER_CHANGE_CIPHER_SPEC";
    case MBEDTLS_SSL_SERVER_FINISHED:                   return "SERVER_FINISHED";
    case MBEDTLS_SSL_FLUSH_BUFFERS:                     return "FLUSH_BUFFERS";
    case MBEDTLS_SSL_HANDSHAKE_WRAPUP:                  return "HANDSHAKE_WRAPUP";
    case MBEDTLS_SSL_HANDSHAKE_OVER:                    return "HANDSHAKE_OVER";
    case MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET:         return "SERVER_NEW_SESSION_TICKET";
    case MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT:  return "SERVER_HELLO_VERIFY_REQUEST_SENT";
  }
  return "UNKNOWN HANDSHAKE STATE";
}



int DtlsClientSocket::step() {
  mbedtls_printf("step() beginning\n");
  int stacked_state = ssl_context.state;
  if (stacked_state != MBEDTLS_SSL_HANDSHAKE_OVER) {
    int ret = mbedtls_ssl_handshake(&ssl_context);
    switch (ret) {
      case MBEDTLS_ERR_SSL_WANT_READ:
      case MBEDTLS_ERR_SSL_WANT_WRITE:
        // The library is still waiting on the net stack. Do nothing.
        return ret;
      case 0:
        // The nominal outcome.
        break;
      default:
        // Something went sideways during the handshake.
        error(ret);
        return 0;
    }
  }

  if (stacked_state != ssl_context.state) {
    mbedtls_printf("step() state %s --> %s.\n", _mbedtls_state_to_string(stacked_state), _mbedtls_state_to_string(ssl_context.state));
  }

  if (ssl_context.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
    // this should only be called once when we first finish the handshake
    handshake_cb.Call({});
  }
  return 0;
}



void DtlsClientSocket::throwError(int ret) {
	char error_buf[255];
	mbedtls_strerror(ret, error_buf, 254);
	Napi::Error::New(env, error_buf).ThrowAsJavaScriptException();

}

void DtlsClientSocket::error(int ret) {
	char error_buf[255];
	mbedtls_strerror(ret, error_buf, 254);
  error_cb.Call({
		Napi::Number::New(env, ret),
		Napi::String::New(env, error_buf)
	});
}

void DtlsClientSocket::store_data(const unsigned char *buf, size_t len) {
  recv_buf = buf;
  recv_len = len;
}

int DtlsClientSocket::close() {
  if(ssl_context.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
    return 1;
  }
  return mbedtls_ssl_close_notify(&ssl_context);
}

DtlsClientSocket::~DtlsClientSocket() {
  recv_buf = nullptr;
  mbedtls_x509_crt_free(&clicert);
  mbedtls_x509_crt_free(&cacert);
  mbedtls_pk_free(&pkey);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  mbedtls_ssl_free(&ssl_context);
}
