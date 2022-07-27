#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/ip.h>

#include <openssl/md5.h>

#include "libnavi.h"
#include "transport.h"
#include "utils.h"

#include "navi-protocol.h"
#include "libnavi-internal.h"
#include "perfcounters.h"

enum navi_loglevel_e navi_loglevel=LL_NAVI_INFO;

static int default_logger_func(const enum navi_loglevel_e navi_loglevel, const struct navi_protocol_ctx_s *navi_ctx, struct navi_stream_ctx_s *stream_ctx, void *user_arg, const char *format, ...);

pthread_spinlock_t navi_logger_lock;
navi_logger_t navi_logger_func=default_logger_func;
void *navi_logger_func_arg=NULL;

static
void calculate_hashes(struct navi_protocol_ctx_s *navi_ctx) {
  MD5_CTX md5;
  MD5_Init(&md5);
  MD5_Update(&md5, navi_ctx->config.domain_name, strlen(navi_ctx->config.domain_name));
  MD5_Update(&md5, navi_ctx->config.domain_secret, strlen(navi_ctx->config.domain_secret));
  MD5_Final(navi_ctx->domain_hash, &md5);

  MD5(navi_ctx->config.domain_secret, sizeof(navi_ctx->config.domain_secret), navi_ctx->secret_hash);

  navi_ctx->client_hash=crc32(navi_ctx->config.client_name, 0xFFFFFFFF, strlen(navi_ctx->config.client_name));
}

struct navi_protocol_ctx_s *navi_create_context(struct navi_config_s *config, struct navi_events_s *events) {
  struct navi_protocol_ctx_s *ctx=(struct navi_protocol_ctx_s*)malloc(sizeof(struct navi_protocol_ctx_s));

  memset(ctx, 0, sizeof(struct navi_protocol_ctx_s));

  ctx->config=*config;
  ctx->events=*events;
  ctx->report_state_change=NAVI_STATE_NOREPORT;
  ctx->delayed_state_change=NAVI_STATE_NOREPORT;
  pthread_spin_init(&ctx->lock, PTHREAD_PROCESS_PRIVATE);
  pthread_spin_init(&ctx->rx_streams_lock, PTHREAD_PROCESS_PRIVATE);
  
  calculate_hashes(ctx);

  if (navi_transport_create(ctx)) {
    DEBUG_FAILURE(ctx, NULL, "Can't create transport\n");
    free(ctx);
    return NULL;
  }

  // FIXME: calculate MSS based on real network data
  //ctx->mss=1408;  // length without navi header 
  ctx->mss=1300;  // length without navi header 

  ctx->mcast.enable=config->multicast_enable;

  DEBUG_printf(ctx,NULL,"navi create state: %d\n",navi_protocol_state(ctx));

  pthread_mutex_init(&ctx->rx_mtx, NULL);
  pthread_cond_init(&ctx->rx_cond, NULL);

  navi_init_perfcounter(&ctx->counters.signalling_tx, "sgn_tx", 1);
  navi_init_perfcounter(&ctx->counters.signalling_rx, "sgn_rx", 1);
  navi_init_perfcounter(&ctx->counters.signalling_rx_error, "sgn_rx_err", 1);
  navi_init_perfcounter(&ctx->counters.rx_rate, "rx_rate", 0);
  navi_init_perfcounter(&ctx->counters.rx_errors, "rx_errors", 1);
  navi_init_perfcounter(&ctx->counters.tx_rate, "tx_rate", 0);
  navi_init_perfcounter(&ctx->counters.tx_bytes, "tx_bytes", 1);
  navi_init_perfcounter(&ctx->counters.rx_bytes, "rx_bytes", 1);
  navi_init_perfcounter(&ctx->counters.tx_packets, "tx_packets", 1);
  navi_init_perfcounter(&ctx->counters.rx_packets, "rx_packets", 1);
  navi_init_perfcounter(&ctx->mcast.counters.rx_rate, "rx_rate", 0);
  navi_init_perfcounter(&ctx->mcast.counters.tx_rate, "tx_rate", 0);

  return ctx;
}

void navi_register_timesource(struct navi_protocol_ctx_s *navi_ctx, navi_timesource_func timesource_func, void *user_data) {
  pthread_spin_lock(&navi_ctx->lock);
  navi_ctx->get_time_ms=timesource_func;
  navi_ctx->get_time_ms_user_data=user_data;
  pthread_spin_unlock(&navi_ctx->lock);
}

struct navi_stream_ctx_s *navi_add_stream(struct navi_protocol_ctx_s *navi_ctx, struct navi_stream_desc_s *stream_desc) {
  struct navi_stream_ctx_s *stream=malloc(sizeof(struct navi_stream_ctx_s));
  stream->desc=*stream_desc;
  stream->stream_id=crc32(
    &stream_desc->bitrate, 
    crc32(
      &stream_desc->codec, 
      crc32(
        stream_desc->description, 
        0xFFFFFFFF, 
        strlen(stream_desc->description)
      ), 
      sizeof(stream_desc->codec)
    ),
    sizeof(stream_desc->bitrate)
  );
  
  stream->navi_ctx=navi_ctx;
  stream->packet_id=0;
  stream->rx_queue_head=0;
  stream->stream_api_id=0;
  if (stream->desc.stream_mss>navi_ctx->mss || stream->desc.stream_mss<1) {
    stream->desc.stream_mss=navi_ctx->mss;
  }

  stream->rx_queue=malloc(sizeof(struct navi_rx_packet_s *)*stream_desc->rx_queue_length);
  memset(stream->rx_queue, 0, sizeof(struct navi_rx_packet_s *)*stream_desc->rx_queue_length);

  stream->rx_done_queue=NULL;

  pthread_mutex_init(&stream->rx_mtx, NULL);
  pthread_cond_init(&stream->rx_cond, NULL);

#define INIT_PC(name, is_gauge) \
  NAVI_INIT_PERFCOUNTER(stream->counters,name,is_gauge); \
  NAVI_INIT_REMOTE_PERFCOUNTER(stream->remote_counters,name,is_gauge);

  INIT_PC(rx_rate,0);
  INIT_PC(tx_rate,0);
  INIT_PC(rx_bytes,1);
  INIT_PC(tx_bytes,1);
  INIT_PC(rx_packets,1);
  INIT_PC(tx_packets,1);
  INIT_PC(tx_frames,1);
  INIT_PC(rx_loss_rate,0);
  INIT_PC(rx_loss_count,1);
  INIT_PC(rx_loss_count,1);
  INIT_PC(rx_recover_rate,0);
  INIT_PC(rx_recover_count,1);
  INIT_PC(tx_codec_rate,0);
  INIT_PC(net_rx_rate,0);
  INIT_PC(net_tx_rate,0);

  NAVI_INIT_PERFCOUNTER(stream->mcast.counters,net_tx_rate, 0);

#undef INIT_PC

  stream->last_stats_time=0;

  DEBUG_printf(navi_ctx, stream, "add stream %s id %08x\n",stream_desc->description,stream->stream_id);

  stream->next=navi_ctx->tx_streams;
  navi_ctx->tx_streams=stream;
  ++navi_ctx->tx_stream_count;
  return stream;
}

enum navi_protocol_state_e navi_protocol_state(struct navi_protocol_ctx_s *navi_ctx) {
  return navi_get_protocol_state(navi_ctx);
}

struct navi_received_frame_data_s *navi_get_stream_received_frame(struct navi_stream_ctx_s *stream_ctx) {
  pthread_mutex_lock(&stream_ctx->rx_mtx);
  struct navi_received_frame_s *frame=stream_ctx->rx_done_queue;
  if (!frame) {
    pthread_mutex_unlock(&stream_ctx->rx_mtx);
    return NULL;
  }
  stream_ctx->rx_done_queue=frame->next;
  pthread_mutex_unlock(&stream_ctx->rx_mtx);
  return &frame->data;
}

struct navi_received_frame_data_s *navi_peek_stream_received_frame(struct navi_stream_ctx_s *stream_ctx) {
  pthread_mutex_lock(&stream_ctx->rx_mtx);
  struct navi_received_frame_s *frame=stream_ctx->rx_done_queue;
  pthread_mutex_unlock(&stream_ctx->rx_mtx);
  if (!frame) return NULL;
  return &frame->data;
}

int navi_check_stream_received_frame(struct navi_stream_ctx_s *stream_ctx) {
  int res;
  pthread_mutex_lock(&stream_ctx->rx_mtx);
  res=!!stream_ctx->rx_done_queue;
  pthread_mutex_unlock(&stream_ctx->rx_mtx);
  return res;
}

int navi_count_received_frames(struct navi_stream_ctx_s *stream_ctx) {
  int res=0;
  pthread_mutex_lock(&stream_ctx->rx_mtx);
  for (struct navi_received_frame_s *frame=stream_ctx->rx_done_queue; frame; frame=frame->next) {
    ++res;
  }
  pthread_mutex_unlock(&stream_ctx->rx_mtx);
  return res;
}

int navi_check_received_frame(struct navi_protocol_ctx_s *navi_ctx) {
  for (struct navi_stream_ctx_s *stream=navi_ctx->rx_streams; stream; stream=stream->next) {
    if (navi_check_stream_received_frame(stream)) {
      DEBUG_printf(navi_ctx,NULL,"navi_check_received_frame stream %p %08x\n",stream,stream->stream_id);
      return 1;
    }
  }
  return 0;
}

int navi_wait_protocol_frame(struct navi_protocol_ctx_s *navi_ctx, const int timeout) {
  struct timespec tm;
  ldiv_t d;
  int res=0;
  int save_errno=0;
  
  if (timeout>0) {
    if (clock_gettime(CLOCK_REALTIME, &tm)<0) return -1;
    tm.tv_nsec+=timeout*1000000L; // timeout in ms
    d=ldiv(tm.tv_nsec,1000000000L);
    tm.tv_sec+=d.quot;
    tm.tv_nsec=d.rem;
  }
  pthread_mutex_lock(&navi_ctx->rx_mtx);
  while (!navi_check_received_frame(navi_ctx)) {
    if (timeout>0) {
      res=pthread_cond_timedwait(&navi_ctx->rx_cond, &navi_ctx->rx_mtx, &tm);
      if (res==ETIMEDOUT) {
        pthread_mutex_unlock(&navi_ctx->rx_mtx);
        return 0;
      }
    } else {
      res=pthread_cond_wait(&navi_ctx->rx_cond, &navi_ctx->rx_mtx);
    }
    if (res) {
      save_errno=errno;
      break;
    }
  }
  pthread_mutex_unlock(&navi_ctx->rx_mtx);
  if (res==0 && navi_check_received_frame(navi_ctx)) return 1; // frame recevied
  errno=save_errno;
  return -1;
}

int navi_wait_stream_frame(struct navi_stream_ctx_s *stream_ctx, const int timeout) {
  struct timespec tm;
  ldiv_t d;
  int res=0;
  int save_errno=0;
  if (timeout>0) {
    if (clock_gettime(CLOCK_REALTIME, &tm)<0) return -1;
    tm.tv_nsec+=timeout*1000000; // timeout in ms
    d=ldiv(tm.tv_nsec,1000000000);
    tm.tv_sec+=d.quot;
    tm.tv_nsec=d.rem;
  }
  pthread_mutex_lock(&stream_ctx->rx_mtx);
  while (!navi_check_stream_received_frame(stream_ctx)) {
    if (timeout>0) {
      res=pthread_cond_timedwait(&stream_ctx->rx_cond, &stream_ctx->rx_mtx, &tm);
    } else {
      res=pthread_cond_wait(&stream_ctx->rx_cond, &stream_ctx->rx_mtx);
    }
    if (res<0) {
      save_errno=errno;
      break;
    }
  }
  pthread_mutex_unlock(&stream_ctx->rx_mtx);
  if (res==0) return 1; // frame recevied
  if (timeout>0 && save_errno==ETIMEDOUT) return 0;
  errno=save_errno;
  return -1;
}

void navi_free_context(struct navi_protocol_ctx_s *navi_ctx) {
  // TODO
}

struct navi_received_frame_data_s *navi_get_received_frame(struct navi_protocol_ctx_s *navi_ctx) {

  if (!navi_ctx->rx_streams) return NULL;

  for (int i=0; i<navi_ctx->rx_stream_count; ++i) {
    struct navi_received_frame_data_s *res;
    if (!navi_ctx->last_rx_stream) navi_ctx->last_rx_stream=navi_ctx->rx_streams;
    else {
      navi_ctx->last_rx_stream=navi_ctx->last_rx_stream->next;
      if (!navi_ctx->last_rx_stream) navi_ctx->last_rx_stream=navi_ctx->rx_streams;
    }
    
    if (!navi_ctx->last_rx_stream) return NULL;

    res=navi_get_stream_received_frame(navi_ctx->last_rx_stream);
    if (res) {
      if (res->flags&NAVI_DATA_FLAG_DEBUG_DATA_PATH) {
        DEBUG_printf(navi_ctx,NULL,"\ndebug RX packet from %08x size %d pts %ld dts %ld id %u crc %08x\n",navi_ctx->last_rx_stream->stream_id,res->data_len,res->pts,res->dts,res->packet_id,crc32(res->data,0xFFFFFFFF,res->data_len));

      }
      return res;
    }
  }
  return NULL;
}  

long navi_get_stream_api_id(struct navi_stream_ctx_s *stream_ctx) {
  return stream_ctx->stream_api_id;
}

uint32_t navi_get_stream_id(struct navi_stream_ctx_s *stream_ctx) {
  return stream_ctx->stream_id;
}

void navi_set_stream_api_id(struct navi_stream_ctx_s *stream_ctx, const long id) {
  stream_ctx->stream_api_id=id;
}

void navi_get_stream_counters(struct navi_stream_ctx_s *stream_ctx, void (*receiver)(struct navi_stream_ctx_s *stream_ctx, void *user_data, ...), void *user_data, const uint64_t dt_now_ms) {
  receiver(
    stream_ctx, user_data, 
    NAVI_PRINT_PERFCOUNTER(stream_ctx->counters.rx_rate,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->counters.tx_rate,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->counters.rx_bytes,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->counters.tx_bytes,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->counters.rx_packets,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->counters.tx_packets,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->counters.tx_frames,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->counters.rx_loss_rate,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->counters.rx_loss_count,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->counters.rx_recover_rate,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->counters.rx_recover_count,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->counters.tx_codec_rate,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->counters.net_rx_rate,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->counters.net_tx_rate,dt_now_ms),
    0,NULL,-1 // tail
  );
}

void navi_get_stream_remote_counters(struct navi_stream_ctx_s *stream_ctx, void (*receiver)(struct navi_stream_ctx_s *stream_ctx, void *user_data, ...), void *user_data) {
  const uint64_t dt_now_ms=0;
  receiver(
    stream_ctx, user_data, 
    NAVI_PRINT_PERFCOUNTER(stream_ctx->remote_counters.rx_rate,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->remote_counters.tx_rate,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->remote_counters.rx_bytes,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->remote_counters.tx_bytes,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->remote_counters.rx_packets,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->remote_counters.tx_packets,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->remote_counters.tx_frames,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->remote_counters.rx_loss_rate,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->remote_counters.rx_loss_count,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->remote_counters.rx_recover_rate,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->remote_counters.rx_recover_count,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->remote_counters.tx_codec_rate,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->remote_counters.net_rx_rate,dt_now_ms),
    NAVI_PRINT_PERFCOUNTER(stream_ctx->remote_counters.net_tx_rate,dt_now_ms),
    0,NULL,-1 // tail
  );
}

static 
int default_logger_func(const enum navi_loglevel_e loglevel, const struct navi_protocol_ctx_s *navi_ctx, struct navi_stream_ctx_s *stream_ctx, void *user_arg, const char *format, ...) {
  if (loglevel>navi_loglevel) return 0;
  printf("NAVI:%p:%p|",navi_ctx,stream_ctx);
  va_list ap;
  va_start(ap, format);
  const int res=vprintf(format, ap);
  va_end(ap);
  return res;
}

navi_logger_t navi_set_logger(navi_logger_t func, void *user_arg) {
  pthread_spin_lock(&navi_logger_lock);
  const navi_logger_t old_logger=navi_logger_func;
  navi_logger_func=func;
  navi_logger_func_arg=user_arg;
  pthread_spin_unlock(&navi_logger_lock);
  return old_logger;
}

#if NAVI_ALLOW_CONSTRUCTOR_INIT
void __attribute__((constructor)) navi_library_init(void) 
#else
void navi_library_init(void)
#endif
{
  static bool navi_is_initialized=false;
  if (navi_is_initialized) return;
  navi_is_initialized=true;

  pthread_spin_init(&navi_logger_lock, PTHREAD_PROCESS_PRIVATE);
}


