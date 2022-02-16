#ifndef _LIBNAVI_INTERNAL_H_
#define _LIBNAVI_INTERNAL_H_

#include <pthread.h>

#include "perfcounters.h"

#define NAVI_STATS_PERIOD 2000 // 2sec
#define NAVI_QUALITY_PERIOD 2000 // 2sec
#define NAVI_RECONNECT_DELAY 2000

#define NAVI_MCAST_ANNOUNCE_PERIOD 2000

struct navi_rx_packet_fragment_s {
  struct navi_rx_packet_fragment_s *next;
  struct NaviProtocolDataFrameHeader head;
  int data_len; // data length including encrypted header
  int payload_len; // stream data length
  int refs; // if it is fec packet - it is refs count
  struct navi_rx_packet_fragment_s *fec;
  uint8_t *decrypted_data;
  int decrypted_data_len;
  uint8_t data[0];
};

struct navi_rx_packet_s {
  uint32_t packet_id;
  int fragment_count;
  int done;
  uint32_t packet_size;
  bool mcast_src;
  struct navi_rx_packet_fragment_s **fragments;
  struct navi_rx_packet_fragment_s *fec_packets;
  void *debug_data;
  int debug_data_len;
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
  struct navi_rx_packet_s **rx_queue; // array of pointers
  struct navi_received_frame_s *rx_done_queue;
  pthread_mutex_t rx_mtx;
  pthread_cond_t rx_cond;
  uint64_t last_stats_time; // in ms
  uint64_t last_quality_time; // in ms
  uint64_t remote_counters_time; // in ms
  uint32_t last_rx_id;
  struct {
    navi_perfcounter rx_rate;
    navi_perfcounter tx_rate;
    navi_perfcounter rx_bytes;
    navi_perfcounter tx_bytes;
    navi_perfcounter rx_packets;
    navi_perfcounter tx_packets;
    navi_perfcounter tx_frames;
    navi_perfcounter rx_loss_rate;
    navi_perfcounter rx_loss_count;
    navi_perfcounter rx_recover_rate;
    navi_perfcounter rx_recover_count;
    navi_perfcounter tx_codec_rate;
    navi_perfcounter net_rx_rate;
    navi_perfcounter net_tx_rate;
  } counters, remote_counters;
  struct {
    struct {
      navi_perfcounter net_tx_rate;
    } counters;
  } mcast;
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
  void *remote_start_pkey;
  int remote_start_pkey_len;
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
  pthread_spinlock_t rx_streams_lock;
  struct navi_stream_ctx_s *rx_streams;
  void *rx_streams_encrypted;
  int rx_streams_encrypted_len;
  int mss;
  pthread_mutex_t rx_mtx;
  pthread_cond_t rx_cond;
  struct navi_stream_ctx_s *last_rx_stream;
  navi_timesource_func get_time_ms;
  void *get_time_ms_user_data;
  uint64_t last_stats_dt; // last statistics packet
  enum navi_protocol_state_e report_state_change;
  enum navi_protocol_state_e delayed_state_change;
  uint64_t delayed_state_change_time;
  struct {
    bool enable;
    void *encrypt_ctx;
    void *decrypt_ctx;
    uint8_t encryption_key[16]; // 16 - for aes128
    uint8_t local_iv[16]; // local iv for encryption
    int mcast_socket;
    struct sockaddr_in group_addr;
    uint64_t announce_time;
    void *announce_packet;
    int announce_packet_len;
    bool secret_valid;
    uint64_t membership_check;
    char *connect_to_client; // automaticaly connect to this client if found when discovery
    pthread_t rx_thread;
    volatile uint64_t rx_active;
    struct {
      navi_perfcounter rx_rate;
      navi_perfcounter tx_rate;
    } counters;
  } mcast;
  struct {
    navi_perfcounter signalling_tx;
    navi_perfcounter signalling_rx;
    navi_perfcounter signalling_rx_error;
    navi_perfcounter rx_rate;
    navi_perfcounter rx_errors;
    navi_perfcounter tx_rate;
    navi_perfcounter rx_bytes;
    navi_perfcounter tx_bytes;
    navi_perfcounter rx_packets;
    navi_perfcounter tx_packets;
  } counters;
};

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

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
  navi_ctx->report_state_change=state;
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

#define FREEP(x) do {  free(x); x=NULL; } while (0)

#define NAVI_INIT_PERFCOUNTER(container, name, is_gauge) navi_init_perfcounter(&container.name, TOSTRING(name), is_gauge)
#define NAVI_INIT_REMOTE_PERFCOUNTER(container, name, is_gauge) navi_init_remote_perfcounter(&container.name, TOSTRING(name), is_gauge)
#define NAVI_PRINT_PERFCOUNTER(perfcntr, dt_now) \
  perfcntr.gauge,\
  perfcntr.id,\
  navi_read_perfcounter(&perfcntr, dt_now)

static inline
uint64_t navi_current_time(struct navi_protocol_ctx_s *navi_ctx) {
  if (navi_ctx->get_time_ms) return navi_ctx->get_time_ms(navi_ctx->get_time_ms_user_data);
  return 0;
}

static inline
struct navi_stream_ctx_s *navi_get_rx_streams(struct navi_protocol_ctx_s *navi_ctx) {
  struct navi_stream_ctx_s *res=NULL;
  pthread_spin_lock(&navi_ctx->rx_streams_lock);
  res=navi_ctx->rx_streams;
  pthread_spin_unlock(&navi_ctx->rx_streams_lock);
  return res;
}

#endif