#ifndef _TLV_H_
#define _TLV_H_

#define TLV_KEY_TYPE uint8_t

#define TLV_END (0)
#define TLV_ARRAY_OF(x,_count) (0xF000|(x)),(_count)

#define TLV_IS_ARRAY(x) (((x)&0xFF00)==0xF000?(x&0xFF):0)

#define TLV_MAX_TYPE(x) { .type=x, .encode=NULL, .encode_array=NULL, .decode=NULL, .decode_array=NULL }
#define TLV_DICT(t,en,arr_en,de,arr_de) { .type=t, .encode=en, .encode_array=arr_en, .decode=de, .decode_array=arr_de }

#define TLV_NARGS(...) (sizeof((tlv_dictionary_element[]){__VA_ARGS__})/sizeof(tlv_dictionary_element))

#define TLV_MAKE_DICT(_var, _dict...) static const tlv_dictionary_element _var[]={ \
  TLV_MAX_TYPE(TLV_NARGS(_dict)), \
  _dict \
}

#define TLV_ENCODER(_name, _type) int _name(va_list ap, uint8_t *dst, void *user_ctx) { \
  _type value=va_arg(ap, _type); \
  if (dst) memcpy(dst, &value, sizeof(_type)); \
  return sizeof(_type); \
}

#define TLV_ARRAY_ENCODER(_name, _type) int _name(void *ptr, const int idx, uint8_t *dst, void *user_ctx) { \
  _type *arr=(_type *)ptr; \
  if (dst) memcpy(dst, &(arr[idx]), sizeof(_type)); \
  return sizeof(_type); \
}

#define TLV_ENCODER_TR(_name, _type, _transform) int _name(va_list ap, uint8_t *dst, void *user_ctx) { \
  _type value=_transform(va_arg(ap, _type)); \
  if (dst) memcpy(dst, &value, sizeof(_type)); \
  return sizeof(_type); \
}

#define TLV_ARRAY_ENCODER_TR(_name, _type, _transform) int _name(void *ptr, const int idx, uint8_t *dst, void *user_ctx) { \
  _type *arr=(_type *)ptr; \
  _type value=_transform(arr[idx]); \
  if (dst) memcpy(dst, &value, sizeof(_type)); \
  return sizeof(_type); \
}

#define TLV_ENCODER_P(_name, _type) int _name(va_list ap, uint8_t *dst, void *user_ctx) { \
  _type *value=va_arg(ap, _type *); \
  if (dst) memcpy(dst, value, sizeof(_type)); \
  return sizeof(_type); \
}

#define TLV_DECODER(_name, _type) int _name(uint8_t *src, const int src_len, void *dst, void *user_ctx) { \
  if (src_len!=sizeof(_type)) return -1; \
  if (dst) memcpy(dst, src, sizeof(_type)); \
  return sizeof(_type); \
}

#define TLV_ARRAY_DECODER(_name, _type) int _name(uint8_t *src, const int src_len, void *dst, const int idx, void *user_ctx) { \
  if (src_len!=sizeof(_type)) return -1; \
  if (dst) { \
    _type *t_array=(_type *)dst; \
    memcpy(&t_array[idx], src, sizeof(_type)); \
  } \
  return sizeof(_type); \
}

#define TLV_DECODER_TR(_name, _type, _transform) int _name(uint8_t *src, const int src_len, void *dst, void *user_ctx) { \
  if (src_len!=sizeof(_type)) return -1; \
  if (!dst) return sizeof(_type); \
  _type tmp; \
  memcpy(&tmp, src, sizeof(_type)); \
  tmp=_transform(tmp); \
  memcpy(dst, &tmp, sizeof(_type)); \
  return sizeof(_type); \
}

#define TLV_ARRAY_DECODER_TR(_name, _type, _transform) int _name(uint8_t *src, const int src_len, void *dst, const int idx, void *user_ctx) { \
  _type tmp; \
  _type *t_array=(_type *)dst; \
  if (src_len!=sizeof(_type)) return -1; \
  if (!dst) return sizeof(_type); \
  memcpy(&tmp, src, sizeof(_type)); \
  tmp=_transform(tmp); \
  memcpy(&t_array[idx], &tmp, sizeof(_type)); \
  return sizeof(_type); \
}

typedef struct tlv_dictionary_element_s {
  TLV_KEY_TYPE type;
  int (*encode)(va_list ap, uint8_t *dst, void *user_ctx);
  int (*encode_array)(void *ptr, const int idx, uint8_t *dst, void *user_ctx);
  int (*decode)(uint8_t *src, const int src_len, void *dst, void *user_ctx);
  int (*decode_array)(uint8_t *src, const int src_len, void *dst, const int idx, void *user_ctx);
} tlv_dictionary_element;

int tlv_encode(struct navi_protocol_ctx_s *navi_ctx, void *dst_data, const struct tlv_dictionary_element_s *dictionary, void *user_ctx, ...);
int tlv_decode(struct navi_protocol_ctx_s *navi_ctx, void *src_data, const int src_len, const struct tlv_dictionary_element_s *dictionary, void *user_ctx, ...);

int encode_strz(va_list ap, uint8_t *dst, void *user_ctx);
int decode_strz(uint8_t *src, const int src_len, void *dst, void *user_ctx);
int decode_strz_arr(uint8_t *src, const int src_len, void *dst, const int idx, void *user_ctx);

int encode_u8(va_list ap, uint8_t *dst, void *user_ctx);
int encode_u8_arr(void *ptr, const int idx, uint8_t *dst, void *user_ctx);
int decode_u8(uint8_t *src, const int src_len, void *dst, void *user_ctx);
int decode_u8_arr(uint8_t *src, const int src_len, void *dst, const int idx, void *user_ctx);

int encode_u16(va_list ap, uint8_t *dst, void *user_ctx);
int encode_u16_arr(void *ptr, const int idx, uint8_t *dst, void *user_ctx);
int decode_u16(uint8_t *src, const int src_len, void *dst, void *user_ctx);
int decode_u16_arr(uint8_t *src, const int src_len, void *dst, const int idx, void *user_ctx);

int encode_u32(va_list ap, uint8_t *dst, void *user_ctx);
int encode_u32_arr(void *ptr, const int idx, uint8_t *dst, void *user_ctx);
int decode_u32(uint8_t *src, const int src_len, void *dst, void *user_ctx);
int decode_u32_arr(uint8_t *src, const int src_len, void *dst, const int idx, void *user_ctx);

int encode_double(va_list ap, uint8_t *dst, void *user_ctx);
int encode_double_arr(void *ptr, const int idx, uint8_t *dst, void *user_ctx);
int decode_double(uint8_t *src, const int src_len, void *dst, void *user_ctx);
int decode_double_arr(uint8_t *src, const int src_len, void *dst, const int idx, void *user_ctx);

#endif
