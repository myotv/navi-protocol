#ifndef _LIBNAVI_INTERNAL_H_
#define _LIBNAVI_INTERNAL_H_

#include <pthread.h>

struct navi_rx_packet_fragment_s {
  struct navi_rx_packet_fragment_s *next;
  struct NaviProtocolDataFrameHeader head;
  int data_len; // data length including encrypted header
  int payload_len; // stream data length
  int refs; // if it is fec packet - it is refs count
  struct navi_rx_packet_fragment_s *fec;
  uint8_t data[0];
};

struct navi_rx_packet_s {
  uint32_t packet_id;
  int fragment_count;
  int done;
  uint32_t packet_size;
  struct navi_rx_packet_fragment_s **fragments;
  struct navi_rx_packet_fragment_s *fec_packets;
};

struct navi_received_frame_s {
  struct navi_received_frame_s *next;
  struct navi_received_frame_data_s data;
};

struct navi_stream_ctx_s {
  uint32_t stream_id;
  long stream_api_id; // API client stream id
  struct navi_stream_ctx_s *next;
  struct navi_stream_desc_s desc;
  struct navi_protocol_ctx_s *navi_ctx;
  // live data
  uint32_t packet_id;
  // receive 
  uint32_t rx_queue_head; // id of the first packet in queue
  struct navi_rx_packet_s **rx_queue;
  struct navi_received_frame_s *rx_done_queue;
  pthread_mutex_t rx_mtx;
  pthread_cond_t rx_cond;
};

struct navi_protocol_ctx_s {
  struct navi_config_s config;
  struct navi_events_s events;
  void *ice_agent;
  volatile int ice_agent_state;
  uint8_t domain_hash[16];
  uint8_t secret_hash[16];
  uint32_t client_hash;
  int signalling_fd;
  pthread_spinlock_t lock;
  enum navi_protocol_state_e state;
  uint32_t candidate_list_version;
  void *offer_data;
  int offer_data_len;
  void *local_pkey;
  void *local_pkey_data;
  int local_pkey_len;
  void *remote_pkey_data;
  uint8_t encryption_key[16]; // 16 - for aes128
  uint8_t local_iv[16]; // local iv for encryption
  uint8_t remote_iv[16]; // remote iv for decryption
  void *encrypt_ctx;
  void *decrypt_ctx;
  int tx_stream_count;
  struct navi_stream_ctx_s *tx_streams;
  void *tx_streams_enc_data; // serialized and encrypted data
  int tx_streams_enc_len;
  int rx_stream_count;
  struct navi_stream_ctx_s *rx_streams;
  void *rx_streams_encrypted;
  int rx_streams_encrypted_len;
  int mss;
  pthread_mutex_t rx_mtx;
  pthread_cond_t rx_cond;
  struct navi_stream_ctx_s *last_rx_stream;
};

#define NAVI_LOCK_CTX(_ctx) do { pthread_spin_lock(&_ctx->lock); } while (0)
#define NAVI_UNLOCK_CTX(_ctx) do { pthread_spin_unlock(&_ctx->lock); } while (0)

static inline
enum navi_protocol_state_e navi_get_protocol_state(struct navi_protocol_ctx_s *navi_ctx) {
  enum navi_protocol_state_e res;
  NAVI_LOCK_CTX(navi_ctx);
  res=navi_ctx->state;
  NAVI_UNLOCK_CTX(navi_ctx);
  return res;
}

#ifdef WITH_DEBUG
#define navi_set_protocol_state(_ctx, _state, _with_lock) _navi_set_protocol_state(_ctx, _state, _with_lock, __FILE__, __LINE__)
static inline
void _navi_set_protocol_state(struct navi_protocol_ctx_s *navi_ctx, const enum navi_protocol_state_e state, const int with_lock, const char *file, const int line) {
  enum navi_protocol_state_e old_state;
  if (with_lock) NAVI_LOCK_CTX(navi_ctx);
  old_state=navi_ctx->state;
  navi_ctx->state=state;
  if (with_lock) NAVI_UNLOCK_CTX(navi_ctx);
  DEBUG_printf("%p: %s:%d: set state from %d to %d\n",navi_ctx, file, line, old_state, state);
}
#else 
static inline
void navi_set_protocol_state(struct navi_protocol_ctx_s *navi_ctx, const enum navi_protocol_state_e state, const int with_lock) {
  if (with_lock) NAVI_LOCK_CTX(navi_ctx);
  navi_ctx->state=state;
  if (with_lock) NAVI_UNLOCK_CTX(navi_ctx);
}
#endif

#define NAVI_REQUIRE_PROTOCOL_STATE_EQ(_ctx, _state) ({ \
  enum navi_protocol_state_e _proto_state=navi_get_protocol_state(_ctx); \
  if (_proto_state!=_state) DEBUG_FAILURE(_ctx,"bad protocol state %d\n",_proto_state); \
  _proto_state==_state; \
})

#define NAVI_REQUIRE_PROTOCOL_STATE_GT(_ctx, _state) ({ \
  enum navi_protocol_state_e _proto_state=navi_get_protocol_state(_ctx); \
  if (_proto_state<=_state) DEBUG_FAILURE(_ctx,"bad protocol state %d\n",_proto_state); \
  _proto_state>_state; \
})

#define NAVI_REQUIRE_PROTOCOL_STATE_LT(_ctx, _state) ({ \
  enum navi_protocol_state_e _proto_state=navi_get_protocol_state(_ctx); \
  if (_proto_state>_state) DEBUG_FAILURE(_ctx,"bad protocol state %d\n",_proto_state); \
  _proto_state<=_state; \
})

static inline
int navi_wait_for_state(struct navi_protocol_ctx_s *navi_ctx, const enum navi_protocol_state_e state, int ms) {
  while (ms>0) {
    if (navi_get_protocol_state(navi_ctx)>=state) return 1;
    usleep(1000);
    --ms;
  }
  return 0;
}

#define NAVI_NO_EXPORT __attribute__ ((visibility ("hidden")))

#endif