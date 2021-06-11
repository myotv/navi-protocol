#ifndef _LIBNAVI_H_
#define _LIBNAVI_H_

#define WITH_DEBUG 1

#ifdef WITH_DEBUG
#define DEBUG_IO_STREAM stdout
#define DEBUG_FAILURE(ctx, format...) do { \
  fprintf(DEBUG_IO_STREAM, "%p: fail at %s:%d ", ctx, __FILE__, __LINE__); \
  fprintf(DEBUG_IO_STREAM, format); \
  fflush(DEBUG_IO_STREAM); \
} while (0)
#define DEBUG_printf(format...) fprintf(DEBUG_IO_STREAM, format)
#define DEBUG_hexdump(ptr, size) hexdump(ptr, size)
#else
#define DEBUG_FAILURE(ctx, format...)
#define DEBUG_printf(format...)
#define DEBUG_hexdump(ptr, size)
#endif

#define RIFFTAG(c1,c2,c3,c4) ((c1) | ((c2) << 8) | ((c3) << 16) | ((uint32_t)(c4) << 24))

enum navi_protocol_state_e {
  NAVI_STATE_INIT=0,
  NAVI_STATE_ICE,
  NAVI_STATE_DH_GENERATE,
  NAVI_STATE_DH_SEND,
  NAVI_STATE_DH_RECEIVED,
  NAVI_STATE_WAIT_START,
  NAVI_STATE_PROCED_STREAMS,
  NAVI_STATE_ONLINE,
};

struct navi_protocol_ctx_s;
struct navi_stream_ctx_s;

struct navi_config_s {
  char *domain_name;
  char *client_name;
  char *domain_secret;
  char *stun_server_host;
  int stun_server_port;
  char *turn_servers;
  char *signalling_server;
  int signalling_port;
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

struct navi_events_s {
  void *client_event_data;
  void (*client_event)(struct navi_protocol_ctx_s *navi_ctx, const uint32_t hash, const char *name, const char *sdp, void *user_data);
  void *answer_event_data;
  int (*answer_event)(struct navi_protocol_ctx_s *navi_ctx, const uint32_t hash, const char *name, const char *sdp, void *user_data);
  void *rx_stream_event_data;
  void (*rx_stream_event)(struct navi_protocol_ctx_s *navi_ctx, struct navi_stream_ctx_s *stream, const uint32_t stream_id, struct navi_stream_desc_s *desc, void *user_data);
  // this event called in SOME thread, not in the main one
  void *rx_data_event_data;
  void (*rx_data_event)(struct navi_protocol_ctx_s *navi_ctx, struct navi_stream_ctx_s *stream, const int64_t pts, const int64_t dts, const int flags, void *user_data);
};

struct navi_protocol_ctx_s *navi_create_context(struct navi_config_s *config, struct navi_events_s *events);
void navi_free_context(struct navi_protocol_ctx_s *navi_ctx);
struct navi_stream_ctx_s *navi_add_stream(struct navi_protocol_ctx_s *navi_ctx, struct navi_stream_desc_s *stream_desc);

enum navi_protocol_state_e navi_protocol_state(struct navi_protocol_ctx_s *navi_ctx);

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
void navi_set_stream_api_id(struct navi_stream_ctx_s *stream_ctx, const long id);

uint32_t navi_crc32(const void *buffer, const uint32_t start, const size_t len);

#endif
