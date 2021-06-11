#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <openssl/md5.h>

#include "libnavi.h"
#include "transport.h"
#include "utils.h"

#include "navi-protocol.h"
#include "libnavi-internal.h"

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

  memset(ctx, 0, sizeof(ctx));

  ctx->config=*config;
  ctx->events=*events;
  pthread_spin_init(&ctx->lock, PTHREAD_PROCESS_PRIVATE);
  
  calculate_hashes(ctx);

  if (navi_transport_create(ctx)) {
    DEBUG_FAILURE(ctx, "Can't create transport\n");
    free(ctx);
    return NULL;
  }

  // FIXME: calculate MSS based on real network data
  ctx->mss=1408;  // length without navi header 

  pthread_mutex_init(&ctx->rx_mtx, NULL);
  pthread_cond_init(&ctx->rx_cond, NULL);

  return ctx;
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

  DEBUG_printf("add stream %s id %08x\n",stream_desc->description,stream->stream_id);

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
      DEBUG_printf("navi_check_received_frame stream %p %08x\n",stream,stream->stream_id);
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
    tm.tv_nsec+=timeout*1000000; // timeout in ms
    d=ldiv(tm.tv_nsec,1000000000);
    tm.tv_sec+=d.quot;
    tm.tv_nsec=d.rem;
  }
  pthread_mutex_lock(&navi_ctx->rx_mtx);
  while (!navi_check_received_frame(navi_ctx)) {
    if (timeout>0) {
      res=pthread_cond_timedwait(&navi_ctx->rx_cond, &navi_ctx->rx_mtx, &tm);
    } else {
      res=pthread_cond_wait(&navi_ctx->rx_cond, &navi_ctx->rx_mtx);
    }
    if (res<0) {
      save_errno=errno;
      break;
    }
  }
  pthread_mutex_unlock(&navi_ctx->rx_mtx);
  if (res==0) return 1; // frame recevied
  if (timeout>0 && save_errno==ETIMEDOUT) return 0;
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
        DEBUG_printf("\ndebug RX packet from %08x size %d pts %ld dts %ld id %u crc %08x\n",navi_ctx->last_rx_stream->stream_id,res->data_len,res->pts,res->dts,res->packet_id,crc32(res->data,0xFFFFFFFF,res->data_len));

      }
      return res;
    }
  }
  return NULL;
}  

long navi_get_stream_api_id(struct navi_stream_ctx_s *stream_ctx) {
  return stream_ctx->stream_api_id;
}

void navi_set_stream_api_id(struct navi_stream_ctx_s *stream_ctx, const long id) {
  stream_ctx->stream_api_id=id;
}
