#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <endian.h>
#include <alloca.h>
#include <string.h>

#include "libnavi.h"
#include "tlv.h"

struct tlv_header_s {
  TLV_KEY_TYPE type;
  uint16_t len;
  uint8_t data[0];
} __attribute__((packed));

int tlv_encode(struct navi_protocol_ctx_s *navi_ctx, void *dst_data, const struct tlv_dictionary_element_s *dictionary, void *user_ctx, ...) {
  va_list ap;
  int res=0;
  int arg=0;
  uint8_t *dst_ptr=(uint8_t *)dst_data;

  const int max_type=dictionary[0].type;

  va_start(ap, user_ctx);

  for(;;) {
    int type=va_arg(ap, int);
    int is_array=TLV_IS_ARRAY(type);
    int repeat_count=1;

    if (type==TLV_END) break;

    if (is_array) {
      type=is_array;
      repeat_count=va_arg(ap, int);
      if (repeat_count<1) {
        DEBUG_FAILURE(navi_ctx, "bad repeat count %d arg %d\n",repeat_count,arg);
        return -1;
      }
    }

    if (type>max_type) {
      DEBUG_FAILURE(navi_ctx, "bad tlv type %d arg %d\n",type,arg);
      return -1;
    }
    if (dictionary[type].type!=type) {
      DEBUG_FAILURE(navi_ctx, "bad tlv dict type %d (%d) arg %d\n",type,dictionary[type].type,arg);
      return -1;
    }

    if (dst_data) {
      void *array_ptr=is_array?va_arg(ap, void *):NULL;
      for (int idx=0; idx<repeat_count; ++idx) {
        struct tlv_header_s *H=(struct tlv_header_s *)dst_ptr;
        int encode_size;
        if (!is_array) {
          encode_size=dictionary[type].encode(ap, H->data, user_ctx);
        } else {
          if (!dictionary[type].encode_array) {
            DEBUG_FAILURE(navi_ctx, "no array encoder for arg %d\n",arg);
            return -1;
          }
          if (!array_ptr) {
            DEBUG_FAILURE(navi_ctx, "null array pointer for arg %d\n",arg);
            return -1;
          }
          encode_size=dictionary[type].encode_array(array_ptr, idx, H->data, user_ctx);
        }
        if (encode_size<0) {
          DEBUG_FAILURE(navi_ctx, "can't encode type %d arg %d\n",type,arg);
          return -1;
        }
        H->type=type;
        H->len=htobe16(encode_size&0xFFFF);
        res+=encode_size+sizeof(struct tlv_header_s);
        dst_ptr+=sizeof(struct tlv_header_s)+encode_size;
      }
    } else {
      void *array_ptr=is_array?va_arg(ap, void *):NULL;
      for (int idx=0; idx<repeat_count; ++idx) {
        int encode_size;
        if (!is_array) {
          encode_size=dictionary[type].encode(ap, NULL, user_ctx);
        } else {
          if (!dictionary[type].encode_array) {
            DEBUG_FAILURE(navi_ctx, "no array encoder for arg %d\n",arg);
            return -1;
          }
          if (!array_ptr) {
            DEBUG_FAILURE(navi_ctx, "null array pointer for arg %d\n",arg);
            return -1;
          }
          encode_size=dictionary[type].encode_array(array_ptr, idx, NULL, user_ctx);
        }
        if (encode_size<0) {
          DEBUG_FAILURE(navi_ctx, "can't encode type %d arg %d\n",type,arg);
          return -1;
        }
        res+=encode_size+sizeof(struct tlv_header_s);
      }
    }
    ++arg;
  }
  return res;
}

int tlv_decode(struct navi_protocol_ctx_s *navi_ctx, void *src_data, const int src_len, const struct tlv_dictionary_element_s *dictionary, void *user_ctx, ...) {
  va_list ap;
  int res=0;
  uint8_t *src_ptr=(uint8_t *)src_data;
  void **dst_data;
  int *array_size;
  int *array_ptr;

  const TLV_KEY_TYPE max_type=dictionary[0].type;

  va_start(ap, user_ctx);

  dst_data=alloca(sizeof(void *)*(max_type+1));
  memset(dst_data, 0, sizeof(void *)*(max_type+1));

  array_size=(int*)alloca(sizeof(int)*(max_type+1));
  memset(array_size, 0, sizeof(int)*(max_type+1));

  array_ptr=(int*)alloca(sizeof(int)*(max_type+1));
  memset(array_ptr, 0, sizeof(int)*(max_type+1));

  for (int type=va_arg(ap, int), arg=0; type!=TLV_END; type=va_arg(ap, int),++arg) {
    int is_array=TLV_IS_ARRAY(type);
    if (is_array) {
      type=is_array;
    }
    if (type>max_type) {
      DEBUG_FAILURE(navi_ctx, "bad type %d arg %d\n",type,arg);
      return -1;
    }
    if (is_array) {
      array_size[type]=va_arg(ap, int);
      if (!dictionary[type].decode_array) {
        DEBUG_FAILURE(navi_ctx,"No array decoder for type %d\n",type);
        return -1;
      }
    }
    dst_data[type]=va_arg(ap, void *);
    ++arg;
  }

  while (res<src_len) {
    struct tlv_header_s *H=(struct tlv_header_s *)src_ptr;
    int decode_res;
    int len;
    if (H->type==TLV_END) break;
    if (H->type>max_type) {
      DEBUG_FAILURE(navi_ctx, "bad type at ptr %d\n",res);
      return -1;
    }
    len=be16toh(H->len);
    if (array_size[H->type] || dst_data[H->type]) {
      if (array_size[H->type]) {
        if (array_ptr[H->type]<array_size[H->type]) {
          decode_res=dictionary[H->type].decode_array(H->data, len, dst_data[H->type], array_ptr[H->type]++, user_ctx);
        } else {
          DEBUG_FAILURE(navi_ctx,"array overflow for type %d ptr %d\n",H->type,res);
          return -1;
        }
      } else {
        decode_res=dictionary[H->type].decode(H->data, len, dst_data[H->type], user_ctx);
      }
      if (decode_res<0) {
        DEBUG_FAILURE(navi_ctx, "can't decode type %d at %d size %d\n",H->type,res,len);
        return -1;
      }
    }
    src_ptr+=len+sizeof(struct tlv_header_s);
    res+=len+sizeof(struct tlv_header_s);
  }

  return res;
}

int encode_strz(va_list ap, uint8_t *dst, void *user_ctx) {
  char *str=va_arg(ap, char *);
  if (!str) return 0;
  else {
    size_t len=strlen(str);
    if (dst) memcpy(dst, str, len+1);
    return len+1;
  }
  return -1;
}

int decode_strz(uint8_t *src, const int src_len, void *dst, void *user_ctx) {
  char **dst_str=(char **)dst;
  if (!dst) return sizeof(char *);
  if (src_len==0) {
    *dst_str=NULL;
    return 0;
  } else {
    *dst_str=(char *)malloc(src_len);
    memcpy(*dst_str, src, src_len);
  }
  return sizeof(char *);
}

int decode_strz_arr(uint8_t *src, const int src_len, void *dst, const int idx, void *user_ctx) {
  char **dst_str=(char **)dst;
  dst_str+=idx;
  if (!dst) return sizeof(char *);
  if (src_len==0) {
    *dst_str=NULL;
    return 0;
  } else {
    *dst_str=(char *)malloc(src_len);
    memcpy(*dst_str, src, src_len);
  }
  return sizeof(char *);
}

TLV_ENCODER(encode_double, double);
TLV_ARRAY_ENCODER(encode_double_arr, double);
TLV_DECODER(decode_double, double);
TLV_ARRAY_DECODER(decode_double_arr, double);

int encode_u8(va_list ap, uint8_t *dst, void *user_ctx) { 
  uint8_t value=va_arg(ap, int); 
  if (dst) dst[0]=value;
  return sizeof(uint8_t); 
}

int encode_u8_arr(void *ptr, const int idx, uint8_t *dst, void *user_ctx) { 
  uint8_t value=((uint8_t *)ptr)[idx];
  if (dst) dst[0]=value;
  return sizeof(uint8_t); 
}

int decode_u8(uint8_t *src, const int src_len, void *dst, void *user_ctx) {
  if (src_len!=sizeof(uint8_t)) return -1; 
  if (dst) *((uint8_t*)dst)=src[0];
  return sizeof(uint8_t);
}

int decode_u8_arr(uint8_t *src, const int src_len, void *dst, const int idx, void *user_ctx) {
  if (src_len!=sizeof(uint8_t)) return -1; 
  if (dst) {
    uint8_t *dst_u8=(uint8_t *)dst;
    dst_u8[idx]=src[0];
  }
  return sizeof(uint8_t);
}

int encode_u16(va_list ap, uint8_t *dst, void *user_ctx) { 
  uint16_t value=va_arg(ap, int); 
  if (dst) *((uint16_t*)dst)=htobe16(value);
  return sizeof(uint16_t); 
}

int encode_u16_arr(void *ptr, const int idx, uint8_t *dst, void *user_ctx) { 
  uint16_t value=((uint16_t *)ptr)[idx];
  if (dst) *((uint16_t*)dst)=htobe16(value);
  return sizeof(uint16_t); 
}

int decode_u16(uint8_t *src, const int src_len, void *dst, void *user_ctx) {
  if (src_len!=sizeof(uint16_t)) return -1; 
  if (dst) *((uint16_t*)dst)=be16toh(*(uint16_t *)src);
  return sizeof(uint16_t);
}

int decode_u16_array(uint8_t *src, const int src_len, void *dst, const int idx, void *user_ctx) {
  if (src_len!=sizeof(uint16_t)) return -1; 
  if (dst) {
    uint16_t *dst_u16=(uint16_t *)dst;
    dst_u16[idx]=be16toh(*(uint16_t *)src);
  }
  return sizeof(uint16_t);
}

int encode_u32(va_list ap, uint8_t *dst, void *user_ctx) { 
  uint32_t value=va_arg(ap, uint32_t); 
  if (dst) *((uint32_t*)dst)=htobe32(value);
  return sizeof(uint32_t); 
}

int encode_u32_arr(void *ptr, const int idx, uint8_t *dst, void *user_ctx) { 
  uint16_t value=((uint32_t *)ptr)[idx];
  if (dst) *((uint32_t*)dst)=htobe32(value);
  return sizeof(uint32_t); 
}

int decode_u32(uint8_t *src, const int src_len, void *dst, void *user_ctx) {
  if (src_len!=sizeof(uint32_t)) return -1; 
  if (dst) *((uint32_t*)dst)=be32toh(*(uint32_t *)src);
  return sizeof(uint32_t);
}

int decode_u32_array(uint8_t *src, const int src_len, void *dst, const int idx, void *user_ctx) {
  if (src_len!=sizeof(uint32_t)) return -1; 
  if (dst) {
    uint32_t *dst_u32=(uint32_t *)dst;
    dst_u32[idx]=be32toh(*(uint32_t *)src);
  }
  return sizeof(uint32_t);
}
