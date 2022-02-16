#ifndef _ENCRYPTION_H_
#define _ENCRYPTION_H_

// aes128 encrypted block tail length
#define NAVI_AES128_TAIL_LEN 16

#define NAVI_AES_ENCRYPTED_LEN(size,align) (((size)+(align)-1) & ~((align)-1))

void *navi_encrypt_with_secret(struct navi_protocol_ctx_s *navi_ctx, void *payload, const int payload_len, int *encrypted_len);
void *navi_decrypt_with_secret(struct navi_protocol_ctx_s *navi_ctx, void *payload, const int payload_len, int *decrypted_len);
int navi_generate_keys(struct navi_protocol_ctx_s *navi_ctx);
int navi_generate_secret(struct navi_protocol_ctx_s *navi_ctx);

int navi_generate_mcast_secret(struct navi_protocol_ctx_s *navi_ctx);

void *navi_encrypt_with_dh_secret(struct navi_protocol_ctx_s *navi_ctx, void *payload, const int payload_len, int *encrypted_len, void *dst_buffer);
void *navi_decrypt_with_dh_secret(struct navi_protocol_ctx_s *navi_ctx, void *payload, const int payload_len, int *decrypted_len);

void *navi_encrypt_with_mcast_secret(struct navi_protocol_ctx_s *navi_ctx, void *payload, const int payload_len, int *encrypted_len, void *dst_buffer);
void *navi_decrypt_with_mcast_secret(struct navi_protocol_ctx_s *navi_ctx, void *payload, const int payload_len, int *decrypted_len);

#endif