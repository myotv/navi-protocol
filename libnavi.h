#ifndef _LIBNAVI_H_
#define _LIBNAVI_H_

#include "navi-config.h"

enum navi_loglevel_e {
  LL_NAVI_NONE=0,
  LL_NAVI_CRITICAL,
  LL_NAVI_ERROR,
  LL_NAVI_INFO,
  LL_NAVI_DEBUG,
  LL_NAVI_TRACE
};

extern enum navi_loglevel_e navi_loglevel;

#define NAVI_SIGNALLING_STATE_READY 0
#define NAVI_SIGNALLING_STATE_BUSY 1
#define NAVI_SIGNALLING_STATE_RECONNECT 2

#define RIFFTAG(c1,c2,c3,c4) ((c1) | ((c2) << 8) | ((c3) << 16) | ((uint32_t)(c4) << 24))

enum navi_protocol_state_e {
  NAVI_STATE_NOREPORT=-1,
  NAVI_STATE_INIT=0,
  NAVI_STATE_ICE,
  NAVI_STATE_DH_GENERATE,
  NAVI_STATE_DH_SEND,
  NAVI_STATE_DH_RECEIVED,
  NAVI_STATE_WAIT_START,
  NAVI_STATE_PROCED_STREAMS,
  NAVI_STATE_ONLINE,
  NAVI_STATE_DISCONNECT,
  NAVI_STATE_RECONNECT,
};

struct navi_protocol_ctx_s;
struct navi_stream_ctx_s;

struct navi_config_s {
  int unicast_enable;
  char *domain_name;
  char *client_name;
  char *domain_secret;
  char *stun_server_host;
  int stun_server_port;
  char *turn_servers;
  char *signalling_server;
  int signalling_port;
  int multicast_enable;
  char *multicast_secret;
  char *multicast_tx_group;
};

struct navi_stream_desc_s {
  enum {
    NAVI_STREAM_NULL=0,
    NAVI_STREAM_VIDEO,
    NAVI_STREAM_AUDIO,
    NAVI_STREAM_DATA,
    NAVI_STREAM_NETWORK_L2,
    NAVI_STREAM_NETWORK_L3,
  } stream_type;
  uint32_t codec; // RIFF fourcc
  int bitrate; // in kbits
  union {
    struct {
      int width;
      int height;
      int fps_num,fps_den;
    } video;
    struct {
      int rate;
      int channels;
    } audio;
  };
  char *description;
  enum {
    NAVI_ENCRYPT_NONE = 0,
    NAVI_ENCRYPT_DATAHEADER,
    NAVI_ENCRYPT_KEYFRAME,
    NAVI_ENCRYPT_ALL,
  } encryption;
  int fec_level;
  int rx_queue_length;
  int stream_mss;
};

struct navi_protocol_stream_list_s {
  struct navi_protocol_stream_list_s *next;
  uint32_t stream_id;
  struct navi_stream_desc_s desc;
};

struct navi_received_frame_data_s {
  int32_t stream_id;
  long stream_api_id;
  int64_t pts;
  int64_t dts;
  int flags;
  int data_len;
  uint32_t packet_id;
  void *this_buffer; // memory block holding this frame, free() must called with this value
  uint8_t data[0];
};

struct navi_quality_s {
  double local_tx_net_rate; // including heaedrs
  double remote_rx_net_rate; // including headers
  double local_codec_tx_rate; // just codec data
  double remote_codec_rx_rate; // remote receive rate after all processing and fec
  double remote_recover_rate; // remote fec recover rate
  double remote_loss_pps; // remote loss packet rate
  uint64_t remote_loss_count; // remote loss packet count
  enum {
    NAVI_ADV_NONE = 0,
    NAVI_ADV_LOWER_RATE,
    NAVI_ADV_GROW_RATE
  } advisory;
};

struct navi_events_s {
  void *client_event_data;
  void (*client_event)(struct navi_protocol_ctx_s *navi_ctx, const uint32_t hash, const char *domain, const char *name, const char *sdp, const uint8_t state, const int is_mcast, const int nstreams, struct navi_protocol_stream_list_s *streams, void *user_data);
  void *answer_event_data;
  int (*answer_event)(struct navi_protocol_ctx_s *navi_ctx, const uint32_t hash, const char *name, const char *sdp, void *user_data);
  void *rx_stream_event_data;
  void (*rx_stream_event)(struct navi_protocol_ctx_s *navi_ctx, struct navi_stream_ctx_s *stream, const uint32_t stream_id, struct navi_stream_desc_s *desc, void *user_data);
  // this event called in SOME thread, not in the main one
  void *rx_data_event_data;
  void (*rx_data_event)(struct navi_protocol_ctx_s *navi_ctx, struct navi_stream_ctx_s *stream, const int64_t pts, const int64_t dts, const int flags, void *user_data);
  void *quality_event_data;
  void (*quality_event)(struct navi_protocol_ctx_s *navi_ctx, struct navi_stream_ctx_s *stream, const struct navi_quality_s *quality, void *user_data);
  void *state_event_data;
  void (*state_event)(struct navi_protocol_ctx_s *navi_ctx, void *user_data);
};

typedef uint64_t (*navi_timesource_func)(void *user_data);

typedef int (*navi_logger_t)(const enum navi_loglevel_e level, 
                             const struct navi_protocol_ctx_s *navi_ctx, 
                             struct navi_stream_ctx_s *stream_ctx, 
                             void *user_arg,
                             const char *format, ...);

void navi_library_init(void);

struct navi_protocol_ctx_s *navi_create_context(struct navi_config_s *config, struct navi_events_s *events);
void navi_free_context(struct navi_protocol_ctx_s *navi_ctx);
struct navi_stream_ctx_s *navi_add_stream(struct navi_protocol_ctx_s *navi_ctx, struct navi_stream_desc_s *stream_desc);

enum navi_protocol_state_e navi_protocol_state(struct navi_protocol_ctx_s *navi_ctx);

void navi_register_timesource(struct navi_protocol_ctx_s *navi_ctx, navi_timesource_func timesource_func, void *user_data);

// these flags are allowed for user
#define NAVI_DATA_FLAG_KEYFRAME 0x01
#define NAVI_DATA_FLAG_DEBUG_DATA_PATH 0x02
int navi_send_packet(struct navi_stream_ctx_s *stream_ctx, const int64_t pts, const int64_t dts, const int flags, const void *packet_data, int packet_size);

struct navi_received_frame_data_s *navi_get_stream_received_frame(struct navi_stream_ctx_s *stream_ctx);
struct navi_received_frame_data_s *navi_get_received_frame(struct navi_protocol_ctx_s *navi_ctx);
struct navi_received_frame_data_s *navi_peek_stream_received_frame(struct navi_stream_ctx_s *stream_ctx);
int navi_check_stream_received_frame(struct navi_stream_ctx_s *stream_ctx);
int navi_count_received_frames(struct navi_stream_ctx_s *stream_ctx);

#define navi_free_received_frame(frame) do { \
  if (frame) free(frame->this_buffer); \
} while (0)

int navi_transport_create(struct navi_protocol_ctx_s *navi_ctx);
int navi_transport_send_offer(struct navi_protocol_ctx_s *navi_ctx);
int navi_transport_get_clients(struct navi_protocol_ctx_s *navi_ctx);
int navi_transport_connect_client(struct navi_protocol_ctx_s *navi_ctx, const char *name, const char *sdp);
int navi_transport_work(struct navi_protocol_ctx_s *navi_ctx);

int navi_wait_protocol_frame(struct navi_protocol_ctx_s *navi_ctx, const int timeout);
int navi_wait_stream_frame(struct navi_stream_ctx_s *stream_ctx, const int timeout);

long navi_get_stream_api_id(struct navi_stream_ctx_s *stream_ctx);
uint32_t navi_get_stream_id(struct navi_stream_ctx_s *stream_ctx);
void navi_set_stream_api_id(struct navi_stream_ctx_s *stream_ctx, const long id);

uint32_t navi_crc32(const void *buffer, const uint32_t start, const size_t len);

void navi_get_stream_counters(struct navi_stream_ctx_s *stream_ctx, void (*receiver)(struct navi_stream_ctx_s *stream_ctx, void *user_data, ...), void *user_data, const uint64_t dt_now_ms);
void navi_get_stream_remote_counters(struct navi_stream_ctx_s *stream_ctx, void (*receiver)(struct navi_stream_ctx_s *stream_ctx, void *user_data, ...), void *user_data);

void navi_transport_set_discovery_group(const char *group_addr);
int navi_transport_set_multicast_discovery(const int enable);
int navi_transport_start_multicast(struct navi_protocol_ctx_s *navi_ctx);
int navi_transport_stop_multicast(struct navi_protocol_ctx_s *navi_ctx);

int navi_transport_multicast_ready(struct navi_protocol_ctx_s *navi_ctx);

navi_logger_t navi_set_logger(navi_logger_t func, void *user_arg);

extern pthread_spinlock_t navi_logger_lock;
extern navi_logger_t navi_logger_func;
extern void *navi_logger_func_arg;

#define NAVI_LOG(level, navi_ctx, stream_ctx, format...) do { \
  pthread_spin_lock(&navi_logger_lock); \
  navi_logger_t fn=navi_logger_func; \
  void *arg=navi_logger_func_arg; \
  pthread_spin_unlock(&navi_logger_lock); \
  if (fn) fn(level, navi_ctx, stream_ctx, navi_logger_func_arg, format); \
} while (0)

// these macros for debugging development library, must be removed in production build
#ifdef WITH_DEBUG
#define DEBUG_FAILURE(navi_ctx, stream_ctx, format...) do { \
  pthread_spin_lock(&navi_logger_lock); \
  navi_logger_t fn=navi_logger_func; \
  void *arg=navi_logger_func_arg; \
  pthread_spin_unlock(&navi_logger_lock); \
  if (fn) { \
    fn(LL_NAVI_DEBUG, navi_ctx, stream_ctx, navi_logger_func_arg, "fail at %s:%d ", __FILE__, __LINE__); \
    fn(LL_NAVI_DEBUG, navi_ctx, stream_ctx, navi_logger_func_arg, format); \
  } \
} while (0)
#define DEBUG_FAILURE_A(format...) do { \
  pthread_spin_lock(&navi_logger_lock); \
  navi_logger_t fn=navi_logger_func; \
  void *arg=navi_logger_func_arg; \
  pthread_spin_unlock(&navi_logger_lock); \
  if (fn) { \
    fn(LL_NAVI_DEBUG, NULL, NULL, navi_logger_func_arg, "fail at %s:%d ", __FILE__, __LINE__); \
    fn(LL_NAVI_DEBUG, NULL, NULL, navi_logger_func_arg, format); \
  } \
} while (0)
#define DEBUG_printf(navi_ctx, stream_ctx, format...) NAVI_LOG(LL_NAVI_DEBUG, navi_ctx, stream_ctx, format)
#define DEBUG_printf_a(format...) NAVI_LOG(LL_NAVI_DEBUG, NULL, NULL, format)
#define DEBUG_hexdump(ptr, size) hexdump(ptr, size)
#define DEBUG_code(flag) if (flag)
#else
#define DEBUG_FAILURE(ctx, format...)
#define DEBUG_FAILURE_A(format...)
#define DEBUG_printf(navi_ctx, stream_ctx, format...)
#define DEBUG_printf_a(format...)
#define DEBUG_hexdump(ptr, size)
#define DEBUG_code(flag) if (0)
#endif

#endif
