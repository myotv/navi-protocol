#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <pthread.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/md5.h>

#include "utils.h"
#include "libnavi.h"
#include "navi-protocol.h"
#include "libnavi-internal.h"

#define NAVI_EC_CURVE NID_secp384r1
//#define NAVI_EC_CURVE NID_X9_62_prime256v1

static
EVP_PKEY *generate_pkey(struct navi_protocol_ctx_s *navi_ctx) {
  EVP_PKEY_CTX *ctx, *kctx;
  EVP_PKEY *params=NULL, *res=NULL;

  ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  if (!ctx) {
    DEBUG_FAILURE(navi_ctx, NULL, "can't get pkey_ctx\n");
    return NULL;
  }

  if (!EVP_PKEY_paramgen_init(ctx)) {
    EVP_PKEY_CTX_free(ctx);
    DEBUG_FAILURE(navi_ctx, NULL, "error in EVP_PKEY_paramgen_init\n");
    return NULL;
  }

  if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NAVI_EC_CURVE)) {
    EVP_PKEY_CTX_free(ctx);
    DEBUG_FAILURE(navi_ctx, NULL, "error in EVP_PKEY_CTX_set_ec_paramgen_curve_nid\n");
    return NULL;
  }

  if (!EVP_PKEY_paramgen(ctx, &params)) {
    EVP_PKEY_CTX_free(ctx);
    DEBUG_FAILURE(navi_ctx, NULL, "error in EVP_PKEY_paramgen\n");
    return NULL;
  }

  kctx=EVP_PKEY_CTX_new(params, NULL);
  if (!ctx) {
    EVP_PKEY_CTX_free(ctx);
    DEBUG_FAILURE(navi_ctx, NULL, "can't get pkey_kctx\n");
    return NULL;
  }

  if (!EVP_PKEY_keygen_init(kctx)) {
    EVP_PKEY_CTX_free(ctx);
    DEBUG_FAILURE(navi_ctx, NULL, "error in EVP_PKEY_keygen_init\n");
    return NULL;
  }

  if (!EVP_PKEY_keygen(kctx, &res)) {
    DEBUG_FAILURE(navi_ctx, NULL, "error in EVP_PKEY_keygen\n");
    res=NULL;
  }

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
  EC_KEY_set_asn1_flag (res->pkey.ec, OPENSSL_EC_NAMED_CURVE);
  EC_KEY_set_conv_form (res->pkey.ec, POINT_CONVERSION_COMPRESSED);
#else
  EC_KEY_set_conv_form (EVP_PKEY_get0_EC_KEY (res), POINT_CONVERSION_COMPRESSED);
#endif

  EVP_PKEY_CTX_free(kctx);
  EVP_PKEY_CTX_free(ctx);
  return res;
}

static
uint8_t *export_pkey(EVP_PKEY *key, int *export_len) {
  int len;
  uint8_t *key_data,*key_data_ptr;

  len=i2d_PUBKEY(key, NULL);
  if (len<=0) {
    *export_len=0;
    return NULL;
  }
  key_data=(uint8_t*)malloc(len);
  key_data_ptr=&key_data[0];
  len=i2d_PUBKEY(key, &key_data_ptr);
  if (len<=0) {
    free(key_data);
    *export_len=0;
    return NULL;
  }
  *export_len=len;
  return key_data;
}

static
EVP_PKEY *import_public_key(const uint8_t *key_data, int data_len) {
  return d2i_PUBKEY(NULL, &key_data, data_len);
}

static 
uint8_t *generate_secret(struct navi_protocol_ctx_s *navi_ctx, EVP_PKEY *local_key, EVP_PKEY *remote_key, size_t *secret_len) {
  EVP_PKEY_CTX *ctx;
  uint8_t *secret;

  ctx=EVP_PKEY_CTX_new(local_key, NULL);
  if (!ctx)	{
    DEBUG_FAILURE(navi_ctx, NULL, "create ctx\n");
    *secret_len=0;
    return NULL;
  }
  if (!EVP_PKEY_derive_init(ctx)) {
    EVP_PKEY_CTX_free(ctx);
    DEBUG_FAILURE(navi_ctx, NULL, "derive init\n");
    *secret_len=0;
    return NULL;
  }

  if (!EVP_PKEY_derive_set_peer(ctx, remote_key)) {
    EVP_PKEY_CTX_free(ctx);
    DEBUG_FAILURE(navi_ctx, NULL, "derive set remote key\n");
    *secret_len=0;
    return NULL;
  }

  if (!EVP_PKEY_derive(ctx, NULL, secret_len)) {
    EVP_PKEY_CTX_free(ctx);
    DEBUG_FAILURE(navi_ctx, NULL, "get secret len\n");
    *secret_len=0;
    return NULL;
  }

  secret=(uint8_t *)malloc(*secret_len);
  if (!EVP_PKEY_derive(ctx, secret, secret_len)) {
    EVP_PKEY_CTX_free(ctx);
    DEBUG_FAILURE(navi_ctx, NULL, "get secret data\n");
    free(secret);
    *secret_len=0;
    return NULL;
  }

  return secret;
}

void *navi_encrypt_with_secret(struct navi_protocol_ctx_s *navi_ctx, void *payload, const int payload_len, int *encrypted_len) {
  uint8_t *res=NULL;
  int res_len;
  int head_len;
  int tail_len;
  EVP_CIPHER_CTX *ctx;
  uint16_t head[2]={ 
    htobe16(payload_len), 
    htobe16(crc16(payload, 0xFFFF, payload_len))
  };

  ctx=EVP_CIPHER_CTX_new();
  if (!ctx) return NULL;

  res=malloc(payload_len+EVP_MAX_BLOCK_LENGTH+16 /* iv len */+2 /* length */ + 2 /* crc16 */);
  RAND_bytes(res, 16);

  if (!EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, navi_ctx->secret_hash, res /* iv */, 1)) {
    EVP_CIPHER_CTX_free(ctx);
    free(res);
    DEBUG_FAILURE(navi_ctx, NULL, "can't init cipher\n");
    *encrypted_len=0;
    return NULL;
  }
  EVP_CIPHER_CTX_set_padding(ctx, 1);

  EVP_CipherUpdate(ctx, res+16, &head_len, (uint8_t*)head, sizeof(head));
  
  EVP_CipherUpdate(ctx, res+16+head_len, &res_len, payload, payload_len);

  EVP_CipherFinal_ex(ctx, res+head_len+res_len+16, &tail_len);

  *encrypted_len=head_len+res_len+tail_len+16;

  EVP_CIPHER_CTX_free(ctx);

  return (void*)res;
}

void *navi_decrypt_with_secret(struct navi_protocol_ctx_s *navi_ctx, void *payload, const int payload_len, int *decrypted_len) {
  void *decrypted_data;
  void *res;
  uint16_t *head;
  int res_len;
  int tail_len;
  EVP_CIPHER_CTX *ctx;
  uint8_t *payload_ptr=(uint8_t *)payload;

  if (payload_len<32) return NULL;

  ctx=EVP_CIPHER_CTX_new();
  if (!ctx) return NULL;

  decrypted_data=alloca(payload_len+EVP_MAX_BLOCK_LENGTH);

  if (!EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, navi_ctx->secret_hash, payload_ptr /* iv */, 0)) {
    EVP_CIPHER_CTX_free(ctx);
    DEBUG_FAILURE(navi_ctx, NULL, "can't init cipher\n");
    *decrypted_len=0;
    return NULL;
  }
  
  EVP_CIPHER_CTX_set_padding(ctx, 1);

  if (!EVP_CipherUpdate(ctx, decrypted_data, &res_len, payload_ptr+16, payload_len-16)) {
    EVP_CIPHER_CTX_free(ctx);
    DEBUG_FAILURE(navi_ctx, NULL, "can't update cipher\n");
    *decrypted_len=0;
    return NULL;
  }

  if (!EVP_CipherFinal_ex(ctx, decrypted_data+res_len, &tail_len)) {
    EVP_CIPHER_CTX_free(ctx);
    DEBUG_FAILURE(navi_ctx, NULL, "can't decrypt\n");
    *decrypted_len=0;
    return NULL;
  }

  EVP_CIPHER_CTX_free(ctx);

  res_len+=tail_len;

  head=decrypted_data;

  if (res_len!=(be16toh(head[0])+4)) {
    *decrypted_len=0;
    DEBUG_FAILURE(navi_ctx, NULL, "bad decrypted length\n");
    return NULL;
  }

  if (be16toh(head[1])!=crc16(&head[2], 0xFFFF, res_len-4)) {
    *decrypted_len=0;
    DEBUG_FAILURE(navi_ctx, NULL, "bad decrypted crc\n");
    return NULL;
  }

  res=malloc(res_len-4);
  memcpy(res, &head[2], res_len-4);
  *decrypted_len=res_len-4;

  return res;
}

int navi_generate_keys(struct navi_protocol_ctx_s *navi_ctx) {
  EVP_PKEY *key;

  if (navi_ctx->local_pkey) {
    EVP_PKEY_free((EVP_PKEY *)navi_ctx->local_pkey);
    navi_ctx->local_pkey=NULL;
  }
  if (navi_ctx->local_pkey_data) {
    FREEP(navi_ctx->local_pkey_data);
    navi_ctx->local_pkey_len=0;
  }
  if (navi_ctx->remote_pkey_data) {
    FREEP(navi_ctx->remote_pkey_data);
  }

  key=generate_pkey(navi_ctx);
  if (!key) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't generate DH key\n");
    return -1;
  }
  navi_ctx->local_pkey_data=export_pkey(key, &navi_ctx->local_pkey_len);
  if (!navi_ctx->local_pkey_data) {
    EVP_PKEY_free(key);
    DEBUG_FAILURE(navi_ctx, NULL, "Can't export DH key\n");
    return -1;
  }
  navi_ctx->local_pkey=key;
  navi_ctx->remote_pkey_data=malloc(navi_ctx->local_pkey_len);

  MD5(navi_ctx->local_pkey_data, navi_ctx->local_pkey_len, navi_ctx->local_iv);

  return 0;
}

int navi_generate_secret(struct navi_protocol_ctx_s *navi_ctx) {
  uint8_t *secret;
  size_t secret_len;
  MD5_CTX md5;

  EVP_PKEY *remote_key=import_public_key(navi_ctx->remote_pkey_data, navi_ctx->local_pkey_len);
  if (!remote_key) {
    DEBUG_FAILURE(navi_ctx, NULL, "can't import public key\n");
    return -1;
  }

  secret=generate_secret(navi_ctx, navi_ctx->local_pkey, remote_key, &secret_len);
  EVP_PKEY_free(remote_key);
  if (!secret) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't generate secret\n");
    return -1;
  }

  MD5_Init(&md5);
  MD5_Update(&md5, secret, secret_len);
  MD5_Update(&md5, navi_ctx->config.domain_name, strlen(navi_ctx->config.domain_name));
  MD5_Update(&md5, navi_ctx->config.domain_secret, strlen(navi_ctx->config.domain_secret));
  MD5_Final(navi_ctx->encryption_key, &md5);
  free(secret);

  DEBUG_printf(navi_ctx,NULL,"encryption key\n");
  DEBUG_hexdump(navi_ctx->encryption_key,sizeof(navi_ctx->encryption_key));

  MD5(navi_ctx->remote_pkey_data, navi_ctx->local_pkey_len, navi_ctx->remote_iv);

  return 0;
}

int navi_generate_mcast_secret(struct navi_protocol_ctx_s *navi_ctx) {
  MD5_CTX md5;

  MD5_Init(&md5);
  MD5_Update(&md5, navi_ctx->config.domain_name, strlen(navi_ctx->config.domain_name));
  MD5_Update(&md5, navi_ctx->config.domain_secret, strlen(navi_ctx->config.domain_secret));
  if (navi_ctx->config.multicast_secret && navi_ctx->config.multicast_secret[0]) {
    MD5_Update(&md5, navi_ctx->config.multicast_secret, strlen(navi_ctx->config.multicast_secret));
  }
  MD5_Final(navi_ctx->mcast.encryption_key, &md5);

  RAND_bytes(navi_ctx->mcast.local_iv, sizeof(navi_ctx->mcast.local_iv));

  navi_ctx->mcast.secret_valid=true;

  return 0;
}

void *navi_encrypt_with_dh_secret(struct navi_protocol_ctx_s *navi_ctx, void *payload, const int payload_len, int *encrypted_len, void *dst_buffer) {
  uint8_t *res=(uint8_t *)dst_buffer;
  int res_len;
  int tail_len;
  EVP_CIPHER_CTX *ctx=(EVP_CIPHER_CTX *)navi_ctx->encrypt_ctx;

  if (!ctx) { // reuse context
    ctx=EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    navi_ctx->encrypt_ctx=ctx;
  }

  if (!res) res=malloc(payload_len+EVP_MAX_BLOCK_LENGTH);

  if (!EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, navi_ctx->encryption_key, navi_ctx->local_iv, 1)) {
    if (!dst_buffer) free(res);
    EVP_CIPHER_CTX_free(ctx);
    navi_ctx->encrypt_ctx=NULL;
    DEBUG_FAILURE(navi_ctx, NULL, "can't init cipher\n");
    *encrypted_len=0;
    return NULL;
  }
  EVP_CIPHER_CTX_set_padding(ctx, 1);

  EVP_CipherUpdate(ctx, res, &res_len, payload, payload_len);

  EVP_CipherFinal_ex(ctx, res+res_len, &tail_len);

  *encrypted_len=res_len+tail_len;

  return (void*)res;
}

void *navi_decrypt_with_dh_secret(struct navi_protocol_ctx_s *navi_ctx, void *payload, const int payload_len, int *decrypted_len) {
  uint8_t *res=NULL;
  int res_len;
  int tail_len;
  EVP_CIPHER_CTX *ctx=(EVP_CIPHER_CTX *)navi_ctx->decrypt_ctx;

  if (!ctx) { // reuse context
    ctx=EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    navi_ctx->decrypt_ctx=ctx;
  }

  res=malloc(payload_len+EVP_MAX_BLOCK_LENGTH);

  if (!EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, navi_ctx->encryption_key, navi_ctx->remote_iv, 0)) {
    free(res);
    EVP_CIPHER_CTX_free(ctx);
    navi_ctx->decrypt_ctx=NULL;
    DEBUG_FAILURE(navi_ctx, NULL, "can't init cipher\n");
    *decrypted_len=0;
    return NULL;
  }
  EVP_CIPHER_CTX_set_padding(ctx, 1);

  EVP_CipherUpdate(ctx, res, &res_len, payload, payload_len);

  EVP_CipherFinal_ex(ctx, res+res_len, &tail_len);

  *decrypted_len=res_len+tail_len;

  return (void*)res;
}

#if NAVI_WITH_MULTICAST==1
void *navi_encrypt_with_mcast_secret(struct navi_protocol_ctx_s *navi_ctx, void *payload, const int payload_len, int *encrypted_len, void *dst_buffer) {
  uint8_t *res=(uint8_t *)dst_buffer;
  int res_len;
  int tail_len;
  EVP_CIPHER_CTX *ctx=(EVP_CIPHER_CTX *)navi_ctx->mcast.encrypt_ctx;

  if (!ctx) { // reuse context
    ctx=EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    navi_ctx->mcast.encrypt_ctx=ctx;
  }

  if (!res) res=malloc(payload_len+EVP_MAX_BLOCK_LENGTH+sizeof(navi_ctx->mcast.local_iv));

  if (!EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, navi_ctx->mcast.encryption_key, navi_ctx->mcast.local_iv, 1)) {
    if (!dst_buffer) free(res);
    EVP_CIPHER_CTX_free(ctx);
    navi_ctx->mcast.encrypt_ctx=NULL;
    DEBUG_FAILURE(navi_ctx, NULL, "can't init cipher\n");
    *encrypted_len=0;
    return NULL;
  }
  EVP_CIPHER_CTX_set_padding(ctx, 1);

  memcpy(res, navi_ctx->mcast.local_iv, sizeof(navi_ctx->mcast.local_iv));

  EVP_CipherUpdate(ctx, res+sizeof(navi_ctx->mcast.local_iv), &res_len, payload, payload_len);

  EVP_CipherFinal_ex(ctx, res+res_len+sizeof(navi_ctx->mcast.local_iv), &tail_len);

  *encrypted_len=res_len+tail_len+sizeof(navi_ctx->mcast.local_iv);

  return (void*)res;
}

void *navi_decrypt_with_mcast_secret(struct navi_protocol_ctx_s *navi_ctx, void *payload, const int payload_len, int *decrypted_len) {
  uint8_t *res=NULL;
  int res_len;
  int tail_len;
  EVP_CIPHER_CTX *ctx=(EVP_CIPHER_CTX *)navi_ctx->mcast.decrypt_ctx;
  uint8_t *remote_iv=(uint8_t*)payload;

  if (payload_len<=0) return NULL;

  if (payload_len<=sizeof(sizeof(navi_ctx->mcast.local_iv))) {
    DEBUG_FAILURE(navi_ctx, NULL, "mcast: short packet, len %d\n",payload_len);
    return NULL;
  }

  if (!ctx) { // reuse context
    ctx=EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    navi_ctx->mcast.decrypt_ctx=ctx;
  }

  res=malloc(payload_len+EVP_MAX_BLOCK_LENGTH);

  if (!EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, navi_ctx->mcast.encryption_key, remote_iv, 0)) {
    free(res);
    EVP_CIPHER_CTX_free(ctx);
    navi_ctx->mcast.decrypt_ctx=NULL;
    DEBUG_FAILURE(navi_ctx, NULL, "can't init cipher\n");
    *decrypted_len=0;
    return NULL;
  }
  EVP_CIPHER_CTX_set_padding(ctx, 1);

  EVP_CipherUpdate(ctx, res, &res_len, remote_iv+sizeof(navi_ctx->mcast.local_iv), payload_len-sizeof(navi_ctx->mcast.local_iv));

  EVP_CipherFinal_ex(ctx, res+res_len, &tail_len);

  *decrypted_len=res_len+tail_len;

  return (void*)res;
}
#endif

void test_encryption(void) {
  ERR_load_crypto_strings();

  EVP_PKEY *pk1=generate_pkey(NULL);
  DEBUG_printf_a("pk1 %p %d\n",pk1,EVP_PKEY_id(pk1));  

  EVP_PKEY *pk2=generate_pkey(NULL);
  DEBUG_printf_a("pk2 %p %d\n",pk2,EVP_PKEY_id(pk2));  


  int klen;
  uint8_t *data=export_pkey(pk1, &klen);
  DEBUG_hexdump(data, klen);

  EVP_PKEY *ikey=import_public_key(data, klen);
  ERR_print_errors_fp(stdout);
  DEBUG_printf_a("ipk %p\n",ikey);

  size_t secret_len;
  uint8_t *secret=generate_secret(NULL, pk2, ikey, &secret_len);
  DEBUG_printf_a("secret %p len %lu\n",secret,secret_len);
  if (secret) {
    DEBUG_hexdump(secret, secret_len);
  }
}
