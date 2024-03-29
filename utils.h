#ifndef _UTILS_H_
#define _UTILS_H_

#define hexdump(ptr,len) _navi_hexdump(ptr,len,__FILE__,__LINE__)
void _navi_hexdump(const void *p, size_t len, const char *file, const int line);
void navi_hexstr(char *outbuf, const void *src, const size_t len);
#ifdef _ALLOCA_H
#define HEXSTR(buf,len) ({ char *hexbuf=(char *)alloca((len)*2+2); navi_hexstr(hexbuf, (buf), (len)); hexbuf; })
#endif

typedef struct memclean_list_s {
  struct memclean_list_s *next;
  void *ptr;
  void (*free_func)(void *);
} memclean_list;

#ifdef _ALLOCA_H
#define MEMCLEAN_ALLOC_ELEMENT() alloca(sizeof(memclean_list))
#define MEMCLEAN_FREE(_list) do { \
  while (_list) { \
    memclean_list *_mc_next=_list->next; \
    _list->free_func(_list->ptr); \
    _list=_mc_next; \
  } \
} while (0)
#else // no alloca()
#define MEMCLEAN_ALLOC_ELEMENT(el) NAVI_malloc(sizeof(memclean_list))
#define MEMCLEAN_FREE(_list) do { \
  while (_list) { \
    memclean_list *_mc_next=_list->next; \
    _list->free_func(_list->ptr); \
    free(_list); \
    _list=_mc_next; \
  } \
} while (0)
#endif

#define MEMCLEAN_ADD(_list, _ptr, _free_func) ({ \
  memclean_list *el=MEMCLEAN_ALLOC_ELEMENT(); \
  el->next=_list; \
  el->ptr=(_ptr); \
  el->free_func=(_free_func); \
  _list=el; \
  _list; \
})

uint16_t crc16(const void *buffer, const uint16_t start, const size_t len);
uint32_t crc32(const void *buffer, const uint32_t start, const size_t len);

#if NAVI_DEBUG_MEMORY_ALLOCATION!=0

void *_navi_internal_malloc(const size_t size, const int line, const char *file);
void _navi_internal_free(void *ptr, const int line, const char *file);

void _navi_memory_report(const uint64_t now_dt);
void _navi_check_pointer(void *ptr, const int line, const char *file);

#define NAVI_malloc(__size) _navi_internal_malloc(__size, __LINE__,__FILE__)
#define NAVI_free(__ptr) _navi_internal_free(__ptr, __LINE__,__FILE__)
#define NAVI_checkptr(__ptr) _navi_check_pointer(__ptr, __LINE__, __FILE__)

#else
#define NAVI_malloc(__size) malloc(__size)
#define NAVI_free(__ptr) free(__ptr)

#define _navi_memory_report(x)
#define NAVI_checkptr(x)

#endif

#endif
