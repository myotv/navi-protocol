#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>
#include <errno.h>
#include <fcntl.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <juice/juice.h>

#include "libnavi.h"
#include "encryption.h"
#include "transport.h"

#include "navi-protocol.h"
#include "libnavi-internal.h"

#include "utils.h"
#include "tlv.h"
#include "perfcounters.h"

enum {
  NS_ZERO = 0,
  NS_UPDATE_OFFER,
  NS_GET_CLIENTS,
  NS_UPDATE_ANSWER,
  NS_UPDATE_CANDIDATE,
  NS_UPDATE_STATE,
};

enum {
  DICT_OFFER_CLIENT_NAME=1,
  DICT_OFFER_SDP,
  DICT_GATHERING_DONE,
  DICT_CLIENT_STATE,
};

enum {
  DICT_MCAST_DOMAIN=1,
  DICT_MCAST_CLIENT_NAME=2,
  DICT_MCAST_STREAM_COUNT=3,
  DICT_MCAST_GROUP=4,
  DICT_MCAST_PORT=5,
  DICT_MCAST_STREAMS=6,
};

enum {
  DICT_MCAST_REPORT_DOMAIN=1,
  DICT_MCAST_REPORT_CLIENT_NAME,
  DICT_MCAST_REPORT_STREAM_COUNT,
  DICT_MCAST_REPORT_STREAMS,
};

enum {
  DICT_STREAM_REPORT_STREAM_ID=1,
  DICT_STREAM_REPORT_RX_BYTES,
  DICT_STREAM_REPORT_RX_PACKETS,
  DICT_STREAM_REPORT_RX_PACKETS_LOST,
};

enum {
  DICT_ANOUNCE_STREAM_COUNT=1,
  DICT_ANOUNCE_STREAM=2,
};

enum {
  DICT_STREAM_STREAM_ID=1,
  DICT_STREAM_TYPE,
  DICT_STREAM_CODEC,
  DICT_STREAM_BITRATE,
  DICT_STREAM_VIDEO_WIDTH,
  DICT_STREAM_VIDEO_HEIGHT,
  DICT_STREAM_VIDEO_FPS_NUM,
  DICT_STREAM_VIDEO_FPS_DEN,
  DICT_STREAM_AUDIO_RATE,
  DICT_STREAM_AUDIO_CHANNELS,
  DICT_STREAM_DESCRIPTION,
  DICT_STREAM_ENCRYPTION,
  DICT_STREAM_RX_QUEUE_LENGTH,
  DICT_STREAM_FEC_LEVEL,
  DICT_STREAM_MSS,
  DICT_STREAM_TIMEBASE_NUM,
  DICT_STREAM_TIMEBASE_DEN,
  DICT_STREAM_PROFILE,
  DICT_STREAM_LEVEL,
};

TLV_MAKE_DICT(signalling_data_dict, 
  TLV_DICT(DICT_OFFER_CLIENT_NAME, encode_strz, NULL, decode_strz, NULL), // client name
  TLV_DICT(DICT_OFFER_SDP, encode_strz, NULL, decode_strz, NULL),  // offer string
  TLV_DICT(DICT_GATHERING_DONE, encode_u8, NULL, decode_u8, NULL),  // gathering done flag
  TLV_DICT(DICT_CLIENT_STATE, encode_u8, NULL, decode_u8, NULL)  // state flag
);

static int encode_stream(va_list *ap, uint8_t *dst, void *user_ctx);
static int encode_stream_arr(void *ptr, const int idx, uint8_t *dst, void *user_ctx);
static int decode_stream(uint8_t *src, const int src_len, void *dst, void *user_ctx);
static int decode_stream_desc(uint8_t *src, const int src_len, void *dst, void *user_ctx); // dst here pointer to struct navi_protocol_stream_list_s *

static int encode_stream_report(va_list *ap, uint8_t *dst, void *user_ctx);
static int encode_stream_report_arr(void *ptr, const int idx, uint8_t *dst, void *user_ctx);
static int decode_stream_report(uint8_t *src, const int src_len, void *dst, void *user_ctx);

TLV_MAKE_DICT(protocol_data_dict,
  TLV_DICT(DICT_ANOUNCE_STREAM_COUNT, encode_u8, NULL, decode_u8, NULL), // stream count
  TLV_DICT(DICT_ANOUNCE_STREAM, encode_stream, encode_stream_arr, decode_stream, NULL), // stream data
);

#if NAVI_WITH_MULTICAST==1
TLV_MAKE_DICT(multicast_announce_dict,
  TLV_DICT(DICT_MCAST_DOMAIN, encode_strz, NULL, decode_strz, NULL), // domain name
  TLV_DICT(DICT_MCAST_CLIENT_NAME, encode_strz, NULL, decode_strz, NULL), // client name
  TLV_DICT(DICT_MCAST_STREAM_COUNT, encode_u8, NULL, decode_u8, NULL), // stream count
  TLV_DICT(DICT_MCAST_GROUP, encode_u32, NULL, decode_u32, NULL), // mcast group
  TLV_DICT(DICT_MCAST_PORT, encode_u16, NULL, decode_u16, NULL), // port
  TLV_DICT(DICT_MCAST_STREAMS, encode_stream, encode_stream_arr, decode_stream_desc, NULL), // stream data
);

TLV_MAKE_DICT(multicast_report_dict,
  TLV_DICT(DICT_MCAST_REPORT_DOMAIN, encode_strz, NULL, decode_strz, NULL), // domain name
  TLV_DICT(DICT_MCAST_REPORT_CLIENT_NAME, encode_strz, NULL, decode_strz, NULL), // client name
  TLV_DICT(DICT_MCAST_REPORT_STREAM_COUNT, encode_u8, NULL, decode_u8, NULL), // stream count
  TLV_DICT(DICT_MCAST_REPORT_STREAMS, encode_stream_report, encode_stream_report_arr, decode_stream_report, NULL), // stream data
);

TLV_MAKE_DICT(stream_report_dict,
  TLV_DICT(DICT_STREAM_REPORT_STREAM_ID, encode_u32, NULL, decode_u32, NULL),
  TLV_DICT(DICT_STREAM_REPORT_RX_BYTES, encode_u64, NULL, decode_u64, NULL),
  TLV_DICT(DICT_STREAM_REPORT_RX_PACKETS, encode_u32, NULL, decode_u32, NULL),
  TLV_DICT(DICT_STREAM_REPORT_RX_PACKETS_LOST, encode_u32, NULL, decode_u32, NULL),
);
#endif

TLV_MAKE_DICT(stream_data_dict,
  TLV_DICT(DICT_STREAM_STREAM_ID, encode_u32, NULL, decode_u32, NULL),
  TLV_DICT(DICT_STREAM_TYPE, encode_u8, NULL, decode_u8, NULL),
  TLV_DICT(DICT_STREAM_CODEC, encode_u32, NULL, decode_u32, NULL),
  TLV_DICT(DICT_STREAM_BITRATE, encode_u16, NULL, decode_u16, NULL), 
  TLV_DICT(DICT_STREAM_VIDEO_WIDTH, encode_u16, NULL, decode_u16, NULL), 
  TLV_DICT(DICT_STREAM_VIDEO_HEIGHT, encode_u16, NULL, decode_u16, NULL), 
  TLV_DICT(DICT_STREAM_VIDEO_FPS_NUM, encode_u16, NULL, decode_u16, NULL), 
  TLV_DICT(DICT_STREAM_VIDEO_FPS_DEN, encode_u16, NULL, decode_u16, NULL), 
  TLV_DICT(DICT_STREAM_AUDIO_RATE, encode_u16, NULL, decode_u16, NULL), 
  TLV_DICT(DICT_STREAM_AUDIO_CHANNELS, encode_u8, NULL, decode_u8, NULL), 
  TLV_DICT(DICT_STREAM_DESCRIPTION, encode_strz, NULL, decode_strz, NULL), 
  TLV_DICT(DICT_STREAM_ENCRYPTION, encode_u8, NULL, decode_u8, NULL), 
  TLV_DICT(DICT_STREAM_RX_QUEUE_LENGTH, encode_u8, NULL, decode_u8, NULL), 
  TLV_DICT(DICT_STREAM_FEC_LEVEL, encode_u8, NULL, decode_u8, NULL), 
  TLV_DICT(DICT_STREAM_MSS, encode_u16, NULL, decode_u16, NULL), 
  TLV_DICT(DICT_STREAM_TIMEBASE_NUM, encode_u16, NULL, decode_u16, NULL), 
  TLV_DICT(DICT_STREAM_TIMEBASE_DEN, encode_u16, NULL, decode_u16, NULL), 
  TLV_DICT(DICT_STREAM_PROFILE, encode_strz, NULL, decode_strz, NULL), 
  TLV_DICT(DICT_STREAM_LEVEL, encode_strz, NULL, decode_strz, NULL), 
);

static
int encode_stream(va_list *ap, uint8_t *dst, void *user_ctx) {
  struct navi_stream_ctx_s *stream=va_arg(*ap, struct navi_stream_ctx_s *);
  switch (stream->desc.stream_type) {
    case NAVI_STREAM_VIDEO:
      return tlv_encode(
        user_ctx, 
        dst, 
        stream_data_dict, 
        NULL,
        DICT_STREAM_STREAM_ID, stream->stream_id,
        DICT_STREAM_TYPE, stream->desc.stream_type,
        DICT_STREAM_CODEC, stream->desc.codec,
        DICT_STREAM_BITRATE, stream->desc.bitrate,
        DICT_STREAM_VIDEO_WIDTH, stream->desc.video.width,
        DICT_STREAM_VIDEO_HEIGHT, stream->desc.video.height,
        DICT_STREAM_VIDEO_FPS_NUM, stream->desc.video.fps.num,
        DICT_STREAM_VIDEO_FPS_DEN, stream->desc.video.fps.den,
        DICT_STREAM_DESCRIPTION, stream->desc.description,
        DICT_STREAM_ENCRYPTION, stream->desc.encryption,
        DICT_STREAM_RX_QUEUE_LENGTH, stream->desc.rx_queue_length,
        DICT_STREAM_FEC_LEVEL, stream->desc.fec_level,
        DICT_STREAM_MSS, stream->desc.stream_mss,
        DICT_STREAM_TIMEBASE_NUM, stream->desc.timebase.num,
        DICT_STREAM_TIMEBASE_DEN, stream->desc.timebase.den,
        DICT_STREAM_PROFILE, stream->desc.profile,
        DICT_STREAM_LEVEL, stream->desc.level,
        TLV_END
      );
    case NAVI_STREAM_AUDIO:
      return tlv_encode(
        user_ctx, 
        dst, 
        stream_data_dict, 
        NULL,
        DICT_STREAM_STREAM_ID, stream->stream_id,
        DICT_STREAM_TYPE, stream->desc.stream_type,
        DICT_STREAM_CODEC, stream->desc.codec,
        DICT_STREAM_BITRATE, stream->desc.bitrate,
        DICT_STREAM_AUDIO_RATE, stream->desc.audio.rate,
        DICT_STREAM_AUDIO_CHANNELS, stream->desc.audio.channels,
        DICT_STREAM_DESCRIPTION, stream->desc.description,
        DICT_STREAM_ENCRYPTION, stream->desc.encryption,
        DICT_STREAM_RX_QUEUE_LENGTH, stream->desc.rx_queue_length,
        DICT_STREAM_FEC_LEVEL, stream->desc.fec_level,
        DICT_STREAM_MSS, stream->desc.stream_mss,
        DICT_STREAM_TIMEBASE_NUM, stream->desc.timebase.num,
        DICT_STREAM_TIMEBASE_DEN, stream->desc.timebase.den,
        DICT_STREAM_PROFILE, stream->desc.profile,
        DICT_STREAM_LEVEL, stream->desc.level,
        TLV_END
      );
      case NAVI_STREAM_NULL:
      case NAVI_STREAM_NETWORK_L2:
      case NAVI_STREAM_NETWORK_L3:
      case NAVI_STREAM_DATA:
        return -1;
  }
  return -1;  
}

static
int encode_stream_va(uint8_t *dst, void *user_ctx, ...) {
  va_list ap;
  va_start(ap, user_ctx);
  return encode_stream(&ap, dst, user_ctx);
}

static
int encode_stream_arr(void *ptr, const int idx, uint8_t *dst, void *user_ctx) {
  struct navi_stream_ctx_s **stream=(struct navi_stream_ctx_s **)ptr;
  return encode_stream_va(dst, user_ctx, stream[idx]);
}

static
struct navi_stream_ctx_s *get_stream_by_id_in_list(const uint32_t stream_id, struct navi_stream_ctx_s *list, const int list_length) {
  for (int i=0; i<list_length; ++i) {
    if (list[i].stream_id==stream_id) return &list[i];
  }
  return NULL;
}

static
struct navi_stream_ctx_s *get_stream_by_id_in_queue(const uint32_t stream_id, struct navi_stream_ctx_s *list) {
  while (list) {
    if (list->stream_id==stream_id) return list;
    list=list->next;
  }
  return NULL;
}

static void proced_rx_fragment(struct navi_protocol_ctx_s *navi_ctx, struct NaviProtocolFrameHeader *head, struct NaviProtocolDataFrameHeader *fragment_head, const uint32_t stream_id, struct navi_stream_ctx_s *stream_ctx, const bool mcast_src);

#if NAVI_WITH_MULTICAST==1
#include "transport_mcast.c"
#endif

static
int decode_stream(uint8_t *src, const int src_len, void *dst, void *user_ctx) {
  int res;
  struct navi_protocol_ctx_s *navi_ctx=(struct navi_protocol_ctx_s *)dst;
  struct navi_stream_ctx_s *stream=malloc(sizeof(struct navi_stream_ctx_s));
  memset(&stream->desc, 0, sizeof(stream->desc));
  res=tlv_decode(
    navi_ctx, 
    src, src_len, 
    stream_data_dict, 
    NULL, 
    DICT_STREAM_STREAM_ID, &stream->stream_id,
    DICT_STREAM_TYPE, &stream->desc.stream_type,
    DICT_STREAM_CODEC, &stream->desc.codec,
    DICT_STREAM_BITRATE, &stream->desc.bitrate,
    DICT_STREAM_VIDEO_WIDTH, &stream->desc.video.width,
    DICT_STREAM_VIDEO_HEIGHT, &stream->desc.video.height,
    DICT_STREAM_VIDEO_FPS_NUM, &stream->desc.video.fps.num,
    DICT_STREAM_VIDEO_FPS_DEN, &stream->desc.video.fps.den,
    DICT_STREAM_AUDIO_RATE, &stream->desc.audio.rate,
    DICT_STREAM_AUDIO_CHANNELS, &stream->desc.audio.channels,
    DICT_STREAM_DESCRIPTION, &stream->desc.description,
    DICT_STREAM_ENCRYPTION, &stream->desc.encryption,
    DICT_STREAM_RX_QUEUE_LENGTH, &stream->desc.rx_queue_length,
    DICT_STREAM_FEC_LEVEL, &stream->desc.fec_level,
    DICT_STREAM_MSS, &stream->desc.stream_mss,
    DICT_STREAM_TIMEBASE_NUM, &stream->desc.timebase.num,
    DICT_STREAM_TIMEBASE_DEN, &stream->desc.timebase.den,
    DICT_STREAM_PROFILE, &stream->desc.profile,
    DICT_STREAM_LEVEL, &stream->desc.level,
    TLV_END
  );

  if (res<0) {
    free(stream);
    DEBUG_FAILURE(navi_ctx, NULL, "Can't decode stream info\n");
    return -1;
  }

  pthread_spin_lock(&navi_ctx->rx_streams_lock);
  for (struct navi_stream_ctx_s *s=navi_ctx->rx_streams; s; s=s->next) {
    if (s->stream_id==stream->stream_id) {
      pthread_spin_unlock(&navi_ctx->rx_streams_lock);
      free(stream);
      return 0;
    }
  }
  pthread_spin_unlock(&navi_ctx->rx_streams_lock);

  stream->navi_ctx=navi_ctx;
  stream->packet_id=0;
  stream->rx_queue_head=0;
  stream->stream_api_id=0;

  stream->rx_queue=malloc(sizeof(struct navi_rx_packet_s *)*stream->desc.rx_queue_length);
  memset(stream->rx_queue, 0, sizeof(struct navi_rx_packet_s *)*stream->desc.rx_queue_length);

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

  pthread_spin_lock(&navi_ctx->rx_streams_lock);
  stream->next=navi_ctx->rx_streams;
  navi_ctx->rx_streams=stream;
  ++navi_ctx->rx_stream_count;
  pthread_spin_unlock(&navi_ctx->rx_streams_lock);

  return 0;
}

static
int decode_stream_desc(uint8_t *src, const int src_len, void *dst, void *user_ctx) {
  struct navi_protocol_stream_list_s *stream=(struct navi_protocol_stream_list_s *)malloc(sizeof(struct navi_protocol_stream_list_s));
  struct navi_protocol_stream_list_s **list_head=(struct navi_protocol_stream_list_s **)dst;
  int res;
  memset(stream, 0, sizeof(struct navi_protocol_stream_list_s));
  res=tlv_decode(
    NULL,  // no nontext here
    src, src_len, 
    stream_data_dict, 
    NULL, 
    DICT_STREAM_STREAM_ID, &stream->stream_id,
    DICT_STREAM_TYPE, &stream->desc.stream_type,
    DICT_STREAM_CODEC, &stream->desc.codec,
    DICT_STREAM_BITRATE, &stream->desc.bitrate,
    DICT_STREAM_VIDEO_WIDTH, &stream->desc.video.width,
    DICT_STREAM_VIDEO_HEIGHT, &stream->desc.video.height,
    DICT_STREAM_VIDEO_FPS_NUM, &stream->desc.video.fps.num,
    DICT_STREAM_VIDEO_FPS_DEN, &stream->desc.video.fps.den,
    DICT_STREAM_AUDIO_RATE, &stream->desc.audio.rate,
    DICT_STREAM_AUDIO_CHANNELS, &stream->desc.audio.channels,
    DICT_STREAM_DESCRIPTION, &stream->desc.description,
    DICT_STREAM_ENCRYPTION, &stream->desc.encryption,
    DICT_STREAM_RX_QUEUE_LENGTH, &stream->desc.rx_queue_length,
    DICT_STREAM_FEC_LEVEL, &stream->desc.fec_level,
    DICT_STREAM_MSS, &stream->desc.stream_mss,
    DICT_STREAM_TIMEBASE_NUM, &stream->desc.timebase.num,
    DICT_STREAM_TIMEBASE_DEN, &stream->desc.timebase.den,
    DICT_STREAM_PROFILE, &stream->desc.profile,
    DICT_STREAM_LEVEL, &stream->desc.level,
    TLV_END
  );
  if (res<0) {
    free(stream);
    return res;
  }

  stream->next=*list_head;
  *list_head=stream;

  return res;
}

static inline
bool ice_is_connected(juice_agent_t *agent, struct navi_protocol_ctx_s *navi_ctx) {
  const juice_state_t state=agent?juice_get_state(agent):navi_ctx->ice_agent_state;
  return state==JUICE_STATE_CONNECTED || state==JUICE_STATE_COMPLETED;
}

static
int create_signalling(struct navi_protocol_ctx_s *navi_ctx) {
  struct sockaddr_in A;
  int flags;

  if (navi_ctx->signalling_fd>0) return 0;

  A.sin_family=AF_INET;
  A.sin_port=htons(navi_ctx->config.signalling_port);
  if (inet_aton(navi_ctx->config.signalling_server, &A.sin_addr)==0) {
    DEBUG_FAILURE(navi_ctx, NULL, "bad signalling addr '%s'\n",navi_ctx->config.signalling_server);
    return -1;
  }

  navi_ctx->signalling_fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (navi_ctx->signalling_fd==-1) {
    DEBUG_FAILURE(navi_ctx, NULL, "can't create signalling socket: %s\n",strerror(errno));
    return -1;
  }

  if (connect(navi_ctx->signalling_fd, (struct sockaddr *)&A, sizeof(A))<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "can't connect signalling socket: %s\n",strerror(errno));
    close(navi_ctx->signalling_fd);
    navi_ctx->signalling_fd=-1;
    return -1;
  }

  flags=fcntl(navi_ctx->signalling_fd, F_GETFL);
  if (flags<0) {
    close(navi_ctx->signalling_fd);
    navi_ctx->signalling_fd=-1;
    return -1;
  }

  fcntl(navi_ctx->signalling_fd, F_SETFL, flags|O_NONBLOCK);

  return 0;
}

static
int signalling_send(struct navi_protocol_ctx_s *navi_ctx, const int command, void *payload, const int payload_len) {
  uint8_t cmd=command;
  uint16_t crc=0xFFFF;
  struct iovec iov[5];

  if (navi_ctx->signalling_fd<=0) return -1;

  iov[0].iov_base=&cmd;
  iov[0].iov_len=1;
  iov[1].iov_base=navi_ctx->domain_hash;
  iov[1].iov_len=sizeof(navi_ctx->domain_hash);
  iov[2].iov_base=&navi_ctx->client_hash;
  iov[2].iov_len=sizeof(navi_ctx->client_hash);
  iov[3].iov_base=payload;
  iov[3].iov_len=payload_len;
  iov[4].iov_base=&crc;
  iov[4].iov_len=sizeof(crc);

  for (int i=0; i<4; ++i) {
    crc=crc16(iov[i].iov_base, crc, iov[i].iov_len);
  }

  crc=htobe16(crc);

  return writev(navi_ctx->signalling_fd, iov, 5);
}

static
int signalling_check(struct navi_protocol_ctx_s *navi_ctx) {
  int res;
  uint8_t buffer[4096];
  uint16_t crc;
  uint8_t *decrypted_data=NULL;
  int decrypted_len;
  bool rx_ok=true; 
  
  if (navi_ctx->signalling_fd<=0) return -1;

  res=recv(navi_ctx->signalling_fd, buffer, sizeof(buffer), MSG_NOSIGNAL);
  if (res<=0) return 0;

  if (res<(sizeof(navi_ctx->domain_hash)+sizeof(navi_ctx->client_hash)+1+2)) {
    DEBUG_FAILURE(navi_ctx, NULL, "bad reply size %d\n",res);
    navi_inc_perfcounter(&navi_ctx->counters.signalling_rx_error);
    return -1;
  }

  crc=crc16(buffer, 0xffff, res-2);
  if (crc!=be16toh(*((uint16_t *)&buffer[res-2]))) {
    DEBUG_FAILURE(navi_ctx, NULL, "bad reply crc\n");
    navi_inc_perfcounter(&navi_ctx->counters.signalling_rx_error);
    return -1;
  }

//  DEBUG_printf(navi_ctx,NULL,"signalling RX\n");
//  DEBUG_hexdump(buffer, res);
 
  navi_ctx->signalling_rx_time=navi_current_time(navi_ctx);

  if ((buffer[0]&0x80)!=0x80) {
    DEBUG_FAILURE(navi_ctx, NULL, "bad reply code %02x\n",buffer[0]);
    navi_inc_perfcounter(&navi_ctx->counters.signalling_rx_error);
    return -1;
  }

  if (memcmp(&buffer[1], navi_ctx->domain_hash, sizeof(navi_ctx->domain_hash))) {
    DEBUG_FAILURE(navi_ctx, NULL, "bad reply domain\n");
    navi_inc_perfcounter(&navi_ctx->counters.signalling_rx_error);
    return -1;
  }

  switch (buffer[0]&0x7f) {
    case NS_GET_CLIENTS:
    case NS_UPDATE_STATE:
    case NS_UPDATE_OFFER:
      decrypted_data=navi_decrypt_with_secret(navi_ctx, &buffer[1+sizeof(navi_ctx->domain_hash)+sizeof(navi_ctx->client_hash)], res-1-2-sizeof(navi_ctx->domain_hash)-sizeof(navi_ctx->client_hash), &decrypted_len);
      if (!decrypted_data) {
        DEBUG_FAILURE(navi_ctx, NULL, "can't decrypt reply %d\n",buffer[0]&0x7f);
        navi_inc_perfcounter(&navi_ctx->counters.signalling_rx_error);
        return -1;
      }
      break;
    case NS_UPDATE_CANDIDATE:
      decrypted_data=navi_decrypt_with_secret(navi_ctx, &buffer[1+sizeof(navi_ctx->domain_hash)+sizeof(navi_ctx->client_hash)+2], res-1-2-sizeof(navi_ctx->domain_hash)-sizeof(navi_ctx->client_hash)-2, &decrypted_len);
      if (!decrypted_data) {
        DEBUG_FAILURE(navi_ctx, NULL, "can't decrypt reply %d\n",buffer[0]&0x7f);
        navi_inc_perfcounter(&navi_ctx->counters.signalling_rx_error);
        return -1;
      }
      break;
  }

/*
  if (decrypted_data) {
    DEBUG_printf(navi_ctx,NULL,"signalling RX decrypted %d\n",decrypted_len);
    DEBUG_hexdump(decrypted_data, decrypted_len);
  } else {
    DEBUG_printf(navi_ctx,NULL,"signalling RX decrypted NULL\n");
  }
*/

  switch (buffer[0]&0x7f) {
    case NS_GET_CLIENTS:
    case NS_UPDATE_STATE: 
      if (decrypted_data) {
        char *name=NULL;
        char *sdp=NULL;
        uint8_t state=0;
        if (tlv_decode(navi_ctx, decrypted_data, decrypted_len, signalling_data_dict, NULL, DICT_OFFER_CLIENT_NAME, &name, DICT_OFFER_SDP, &sdp, DICT_CLIENT_STATE, &state, TLV_END)>0) {
          if (navi_ctx->events.client_event) {
            navi_ctx->events.client_event(navi_ctx, *((uint32_t *)&buffer[1+sizeof(navi_ctx->domain_hash)]), navi_ctx->config.domain_name, name, sdp, state, 0, 0, NULL, navi_ctx->events.client_event_data);
          }
        } else {
          DEBUG_FAILURE(navi_ctx, NULL, "Can't decode offer\n");
          rx_ok=false;
        }
        free(name);
        free(sdp);
      }
      break;

    case NS_UPDATE_OFFER:
      if (decrypted_data) {
        char *name=NULL;
        char *sdp=NULL;
        if (tlv_decode(navi_ctx, decrypted_data, decrypted_len, signalling_data_dict, NULL, DICT_OFFER_CLIENT_NAME, &name, DICT_OFFER_SDP, &sdp, TLV_END)>0) {
          juice_agent_t *agent=navi_ctx->ice_agent;
          if (navi_ctx->events.answer_event) {
            if (navi_ctx->events.answer_event(navi_ctx, *((uint32_t *)&buffer[1+sizeof(navi_ctx->domain_hash)]), name, sdp, navi_ctx->events.answer_event_data)==-1) {
              DEBUG_FAILURE(navi_ctx, NULL, "'answer_event' hook reject answer\n");
              free(name);
              free(sdp);
              FREEP(decrypted_data);
              navi_inc_perfcounter(&navi_ctx->counters.signalling_rx_error);
              return -1;
            }
          }
          if (juice_get_state(agent)==JUICE_STATE_DISCONNECTED) {
            if (juice_set_remote_description(agent, sdp)) {
              DEBUG_FAILURE(navi_ctx, NULL, "can't set remote answer\n");
              free(name);
              free(sdp);
              FREEP(decrypted_data);
              navi_inc_perfcounter(&navi_ctx->counters.signalling_rx_error);
              return -1;
            }
            juice_gather_candidates(agent);
          }
        } else {
          DEBUG_FAILURE(navi_ctx, NULL, "Can't decode offer\n");
          rx_ok=false;
        }
        free(name);
        free(sdp);
      }
      break;

    case NS_UPDATE_CANDIDATE:
      if (decrypted_data) {
        uint16_t candidate_list_version=be16toh(*(uint16_t *)&buffer[1+sizeof(navi_ctx->domain_hash)+sizeof(navi_ctx->client_hash)]);
        if (!(navi_ctx->candidate_list_version&(1<<candidate_list_version))) {
          char *sdp=NULL;
          uint8_t gathering_done=0;
          if (tlv_decode(navi_ctx, decrypted_data, decrypted_len, signalling_data_dict, NULL, DICT_OFFER_SDP, &sdp, DICT_GATHERING_DONE, &gathering_done, TLV_END)>0) {
            juice_agent_t *agent=navi_ctx->ice_agent;
            DEBUG_printf(navi_ctx,NULL,"add remote candidate %d %s '%s'\n",candidate_list_version,gathering_done?"DONE":"",sdp?sdp:"NULL");
            if (sdp) {
              juice_add_remote_candidate(agent, sdp);
              DEBUG_printf(navi_ctx,NULL,"juice_add_remote_candidate\n");
              navi_ctx->candidate_list_version|=(1<<candidate_list_version);
            }
            if (gathering_done) {
              juice_set_remote_gathering_done(agent);
              DEBUG_printf(navi_ctx,NULL,"juice_set_remote_gathering_done\n");
            }
            DEBUG_printf(navi_ctx,NULL,"done add\n");
          } else {
            DEBUG_FAILURE(navi_ctx, NULL, "Can't decode offer\n");
            rx_ok=false;
          }
          free(sdp);
        }
      }
      break;
  }

  FREEP(decrypted_data);

  if (rx_ok) navi_inc_perfcounter(&navi_ctx->counters.signalling_rx);
  else navi_inc_perfcounter(&navi_ctx->counters.signalling_rx_error);

  return rx_ok?0:-1;
}

static
int navi_send_frame(struct navi_protocol_ctx_s *navi_ctx, const int frame_type, const uint32_t stream_id, const void *payload, const int payload_len) {
  if (!ice_is_connected(NULL, navi_ctx)) return 0;

  void *data;
  struct NaviProtocolFrameHeader *head;
  juice_agent_t *agent=navi_ctx->ice_agent;
  const int data_len=payload_len+sizeof(*head);

  data=alloca(data_len);
  head=(struct NaviProtocolFrameHeader *)data;
  head->frameType=frame_type;
  head->streamId=htobe32(stream_id);
  head->crc=0xffff;
  head->payloadLength=htobe16(payload_len);

  head->crc=htobe16(crc16(payload, crc16(head, head->crc, sizeof(struct NaviProtocolFrameHeader)), payload_len));
  memcpy(head->payload, payload, payload_len);

  //DEBUG_printf(navi_ctx,NULL,"-- send frame %04x len %d payload %d\n",be16toh(frame_type),data_len,payload_len);

  navi_add_perfcounter(&navi_ctx->counters.tx_rate, data_len);
  navi_add_perfcounter(&navi_ctx->counters.tx_bytes, data_len);
  navi_inc_perfcounter(&navi_ctx->counters.tx_packets);

  return juice_send(agent, data, data_len);
}

#if NAVI_WITH_MULTICAST==1
static
int navi_send_mcast_frame(struct navi_protocol_ctx_s *navi_ctx, const int frame_type, const uint32_t stream_id, const void *payload, const int payload_len) {
  if (!navi_mcast_available(navi_ctx)) return 0;
  
  void *data;
  struct NaviProtocolFrameHeader *head;
  const int data_len=payload_len+sizeof(*head);

  data=alloca(data_len);
  head=(struct NaviProtocolFrameHeader *)data;
  head->frameType=frame_type;
  head->streamId=htobe32(stream_id);
  head->crc=0xffff;
  head->payloadLength=htobe16(payload_len);

  head->crc=htobe16(crc16(payload, crc16(head, head->crc, sizeof(struct NaviProtocolFrameHeader)), payload_len));
  memcpy(head->payload, payload, payload_len);

//  DEBUG_printf(navi_ctx,NULL,"-- send mcast frame %04x len %d payload %d\n",be16toh(frame_type),data_len,payload_len);

  int res=send(navi_ctx->mcast.mcast_socket, data, data_len, MSG_NOSIGNAL);
  if (res>0) {
    navi_add_perfcounter(&navi_ctx->mcast.counters.tx_rate, data_len);
  }

  return res;
}
#endif

static
void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
  struct navi_protocol_ctx_s *navi_ctx=user_ptr;
  navi_ctx->ice_agent_state=state;
  DEBUG_printf(navi_ctx,NULL,"state changed %d %s\n",state,juice_state_to_string(state));
}

static 
void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
  struct navi_protocol_ctx_s *navi_ctx=user_ptr;
  int candidate_len;
  void *candidate_payload;
  void *encrypted_data;
  int encrypted_len;

  DEBUG_printf(navi_ctx,NULL,"candidate %s\n",sdp);

  candidate_len=tlv_encode(
    navi_ctx,
    NULL, signalling_data_dict, NULL, 
    DICT_OFFER_SDP, sdp,
    TLV_END
  );

  if (candidate_len<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't serialize candidate\n");
    return;
  }

  candidate_payload=alloca(candidate_len);

  candidate_len=tlv_encode(
    navi_ctx,
    candidate_payload, signalling_data_dict, NULL, 
    DICT_OFFER_SDP, sdp,
    TLV_END
  );

  if (candidate_len<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't serialize candidate\n");
    return;
  }

  encrypted_data=navi_encrypt_with_secret(navi_ctx, candidate_payload, candidate_len, &encrypted_len);
  if (!encrypted_data) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't encrypt candidate\n");
    return;
  }

  signalling_send(navi_ctx, NS_UPDATE_CANDIDATE, encrypted_data, encrypted_len);

  free(encrypted_data);

  signalling_check(navi_ctx);
}

static
void on_gathering_done(juice_agent_t *agent, void *user_ptr) {
  struct navi_protocol_ctx_s *navi_ctx=user_ptr;
  int candidate_len;
  void *candidate_payload;
  void *encrypted_data;
  int encrypted_len;

  DEBUG_printf(navi_ctx,NULL,"gathering done\n");

  signalling_check(navi_ctx);

  candidate_len=tlv_encode(
    navi_ctx,
    NULL, signalling_data_dict, NULL, 
    DICT_GATHERING_DONE, 1,
    TLV_END
  );

  if (candidate_len<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't serialize candidate\n");
    return;
  }

  candidate_payload=alloca(candidate_len);

  candidate_len=tlv_encode(
    navi_ctx,
    candidate_payload, signalling_data_dict, NULL, 
    DICT_GATHERING_DONE, 1,
    TLV_END
  );

  if (candidate_len<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't serialize candidate\n");
    return;
  }

  encrypted_data=navi_encrypt_with_secret(navi_ctx, candidate_payload, candidate_len, &encrypted_len);
  if (!encrypted_data) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't encrypt candidate\n");
    return;
  }

  signalling_send(navi_ctx, NS_UPDATE_CANDIDATE, encrypted_data, encrypted_len);

  free(encrypted_data);
}

static
void free_fragment_queue(struct navi_rx_packet_fragment_s **q) {
  struct navi_rx_packet_fragment_s *list;
  if (*q==NULL) return;
  list=*q;
  *q=NULL;
  while (list) {
    struct navi_rx_packet_fragment_s *next=list->next;
    if (list->decrypted_data) {
      FREEP(list->decrypted_data);
    }
    free(list);
    list=next;
  }
}

/**
 * обрабаотывает пакет в приемной очереди
 * вернет true если tx_packet надо освободить
*/
static
bool proced_rx_queue_packet(struct navi_protocol_ctx_s *navi_ctx, struct navi_stream_ctx_s *stream_ctx, const int final_check, struct navi_rx_packet_s *rx_packet) {
  bool free_packet_later=true;
  DEBUG_printf(navi_ctx,stream_ctx,"-- proced queue packet %p final %d\n",rx_packet,final_check);
  if (rx_packet->fragments) {
    int lost_packets=0;
    uint32_t packet_len=0;
   
    for (int i=0; i<rx_packet->fragment_count; ++i) {
      //DEBUG_printf(navi_ctx,stream_ctx,"fragments[%d]=%p %d\n",i,rx_packet->fragments[i],rx_packet->fragments[i]?rx_packet->fragments[i]->payload_len:-1);
      if (!rx_packet->fragments[i]) ++lost_packets;
      else packet_len+=rx_packet->fragments[i]->payload_len;
    }
    DEBUG_printf(navi_ctx,stream_ctx,"count lost packets %d of %d\n",lost_packets,rx_packet->fragment_count);

    if (lost_packets) {
      const int max_fec_id=(rx_packet->fragment_count/stream_ctx->desc.fec_level)+1;
      const int fec_id_divisor=stream_ctx->desc.fec_level+1; // to calculate fec group id
      DEBUG_printf(navi_ctx,stream_ctx,"lost packets %d final %d\n",lost_packets,final_check);
      if (!final_check) {
        return free_packet_later;
      }
      if (!stream_ctx->desc.fec_level) {
        DEBUG_printf(navi_ctx,stream_ctx,"fec not enabled for %08x\n",stream_ctx->stream_id);
        return free_packet_later;        
      }
      //DEBUG_printf(navi_ctx,stream_ctx,"try to recover fec\n");
      struct navi_rx_packet_fragment_s **fec_list=alloca(max_fec_id*sizeof(struct navi_rx_packet_fragment_s *));
      memset(fec_list, 0, max_fec_id*sizeof(struct navi_rx_packet_fragment_s *));
      for (struct navi_rx_packet_fragment_s *p=rx_packet->fec_packets; p; p=p->next) {
        const int fec_group_id=be16toh(p->head.frame_idx);
        if (fec_group_id>max_fec_id) continue;
        fec_list[fec_group_id]=p;
        DEBUG_printf(navi_ctx,stream_ctx,"fec list %d %p\n",fec_group_id,p);
      }
      for (int i=0; i<rx_packet->fragment_count; ++i) {
        if (!rx_packet->fragments[i]) {
          const int fec_group_id=i/fec_id_divisor;
          struct navi_rx_packet_fragment_s *fec_packet=fec_list[fec_group_id];
          struct navi_rx_packet_fragment_s *pkt_fragment; // new fragment 
          struct navi_rx_packet_fragment_s *src_fragment; // where to get head
          uint8_t *fec_bytes;
          uint8_t *recover_bytes;

          DEBUG_printf(navi_ctx,stream_ctx,"no fragment %d fec group %d fec data %p\n",i,fec_group_id,fec_packet);
          
          if (!fec_packet) {
            DEBUG_FAILURE(navi_ctx,stream_ctx,"no fec frame, group %d\n",fec_group_id);
            return free_packet_later;
          }
          ++(fec_packet->refs);
          if (fec_packet->refs>1) {
            DEBUG_FAILURE(navi_ctx,stream_ctx,"not enough fec data, group %d\n",fec_group_id);
            navi_inc_perfcounter(&stream_ctx->counters.rx_loss_count);
            navi_inc_perfcounter(&stream_ctx->counters.rx_loss_rate);
            stream_ctx->last_rx_id=rx_packet->packet_id;
            return free_packet_later;
          }
          src_fragment=rx_packet->fragments[0];
          if (!src_fragment) {
            src_fragment=rx_packet->fragments[1];
            if (!src_fragment) {
              DEBUG_FAILURE(navi_ctx,stream_ctx,"not enough fec data (no src), group %d\n",fec_group_id);
              navi_inc_perfcounter(&stream_ctx->counters.rx_loss_count);
              navi_inc_perfcounter(&stream_ctx->counters.rx_loss_rate);
              stream_ctx->last_rx_id=rx_packet->packet_id;
              return free_packet_later;
            }
          }
          navi_inc_perfcounter(&stream_ctx->counters.rx_recover_count);

          DEBUG_printf(navi_ctx,stream_ctx,"recover fragment %d fec group %d fec data %p\n",i,fec_group_id,fec_packet);

          pkt_fragment=malloc(sizeof(struct navi_rx_packet_fragment_s)+stream_ctx->desc.stream_mss+NAVI_AES_ENCRYPTED_LEN(sizeof(struct NaviProtocolDataFrameHeader),NAVI_AES128_TAIL_LEN));
          pkt_fragment->fec=fec_packet;
          pkt_fragment->head=src_fragment->head;
          pkt_fragment->head.flags&=~NAVI_DATA_FLAG_ENCRYPTED_DATA;
          pkt_fragment->decrypted_data=NULL;
          if (i<rx_packet->fragment_count-1) {
            pkt_fragment->payload_len=stream_ctx->desc.stream_mss;
          } else {
            pkt_fragment->payload_len=rx_packet->packet_size%stream_ctx->desc.stream_mss;
          }
          memset(pkt_fragment->data, 0, stream_ctx->desc.stream_mss+NAVI_AES_ENCRYPTED_LEN(sizeof(struct NaviProtocolDataFrameHeader),NAVI_AES128_TAIL_LEN));

          if (fec_packet->head.flags&NAVI_DATA_FLAG_ENCRYPTED_DATA) {
#if NAVI_WITH_MULTICAST==1
            if (rx_packet->mcast_src) {
              fec_packet->decrypted_data=navi_decrypt_with_mcast_secret(navi_ctx, fec_packet->data, fec_packet->data_len, &fec_packet->decrypted_data_len);
            } else
#endif
            {
              fec_packet->decrypted_data=navi_decrypt_with_dh_secret(navi_ctx, fec_packet->data, fec_packet->data_len, &fec_packet->decrypted_data_len);
            }
            if (!fec_packet->decrypted_data) {
              free(pkt_fragment);
              DEBUG_FAILURE(navi_ctx,stream_ctx,"Can't decrypt fec packet\n");
              navi_inc_perfcounter(&stream_ctx->counters.rx_loss_count);
              navi_inc_perfcounter(&stream_ctx->counters.rx_loss_rate);
              stream_ctx->last_rx_id=rx_packet->packet_id;
              return free_packet_later;
            }
            if (fec_packet->decrypted_data_len<(pkt_fragment->payload_len+sizeof(struct NaviProtocolDataFrameHeader))) {
              FREEP(fec_packet->decrypted_data);
              free(pkt_fragment);
              DEBUG_FAILURE(navi_ctx,stream_ctx,"Decrypted packet length aless than required\n");
              navi_inc_perfcounter(&stream_ctx->counters.rx_loss_count);
              navi_inc_perfcounter(&stream_ctx->counters.rx_loss_rate);
              stream_ctx->last_rx_id=rx_packet->packet_id;
              return free_packet_later;
            }
            fec_bytes=fec_packet->decrypted_data;
            fec_bytes+=sizeof(struct NaviProtocolDataFrameHeader);
          } else {
            fec_bytes=fec_packet->data;
            fec_bytes+=sizeof(struct NaviProtocolDataFrameHeader);
          }

          recover_bytes=pkt_fragment->data;
          if (stream_ctx->desc.encryption!=NAVI_ENCRYPT_NONE) {
            recover_bytes+=NAVI_AES_ENCRYPTED_LEN(sizeof(struct NaviProtocolDataFrameHeader),NAVI_AES128_TAIL_LEN);
          } else {
            recover_bytes+=sizeof(struct NaviProtocolDataFrameHeader);
          }

          /*
          DEBUG_printf(navi_ctx,stream_ctx,"recover len %d fec0 %02x\n",pkt_fragment->payload_len,fec_bytes[0]);
          DEBUG_hexdump(fec_bytes,16);
          */

          for (int ptr=0; ptr<pkt_fragment->payload_len; ++ptr) {
            recover_bytes[ptr]=fec_bytes[ptr];
            for (int nfragment=0; nfragment<rx_packet->fragment_count; ++nfragment) {
              struct navi_rx_packet_fragment_s *f=rx_packet->fragments[nfragment];
              if (f) {
                uint8_t *f_data;
                int f_payload_len;
                if (ptr==0 && f->head.flags&NAVI_DATA_FLAG_ENCRYPTED_DATA && !f->decrypted_data) {
#if NAVI_WITH_MULTICAST==1
                  if (rx_packet->mcast_src) {
                    f->decrypted_data=navi_decrypt_with_mcast_secret(navi_ctx, f->data, f->data_len, &f->decrypted_data_len);
                  } else
#endif
                  {
                    f->decrypted_data=navi_decrypt_with_dh_secret(navi_ctx, f->data, f->data_len, &f->decrypted_data_len);
                  }
                  if (!f->decrypted_data) {
                    free(pkt_fragment);
                    DEBUG_FAILURE(navi_ctx,stream_ctx,"Can't decrypt packet in fec process\n");
                    navi_inc_perfcounter(&stream_ctx->counters.rx_loss_count);
                    navi_inc_perfcounter(&stream_ctx->counters.rx_loss_rate);
                    stream_ctx->last_rx_id=rx_packet->packet_id;
                    return free_packet_later;
                  }
                }
                if (f->decrypted_data) {
                  f_data=f->decrypted_data;
                  f_payload_len=f->decrypted_data_len;
                } else {
                  f_data=f->data;
                  if (stream_ctx->desc.encryption!=NAVI_ENCRYPT_NONE) {
                    f_data+=NAVI_AES_ENCRYPTED_LEN(sizeof(struct NaviProtocolDataFrameHeader),NAVI_AES128_TAIL_LEN);
                    if (rx_packet->mcast_src) f_data+=sizeof(navi_ctx->mcast.local_iv);
                  } else {
                    f_data+=sizeof(struct NaviProtocolDataFrameHeader);
                  }
                  f_payload_len=f->payload_len;
                }
                /*
                if (ptr==0) {
                  DEBUG_printf(navi_ctx,stream_ctx,"fragment %d %p %02x",nfragment,f->decrypted_data,f->head.flags);
                  DEBUG_hexdump(&f_data[ptr], 16*3);
                }
                */
                if (f_payload_len<=sizeof(struct NaviProtocolDataFrameHeader)) continue;
                f_payload_len-=sizeof(struct NaviProtocolDataFrameHeader);
                if (ptr<f_payload_len) {
                  recover_bytes[ptr]^=f_data[ptr];
                }
              }
            }
          }
          /*
          DEBUG_hexdump(&pkt_fragment->data[sizeof(struct NaviProtocolDataFrameHeader)],pkt_fragment->payload_len);
          */
          navi_add_perfcounter(&stream_ctx->counters.rx_recover_rate, pkt_fragment->payload_len);
          rx_packet->fragments[i]=pkt_fragment;
          break;
        }
      }
      lost_packets=0;
    } 
    DEBUG_printf(navi_ctx,stream_ctx,"Lost packets %d\n",lost_packets);
    if (!lost_packets) {
      struct navi_received_frame_s *rx_frame=malloc(sizeof(struct navi_received_frame_s)+rx_packet->packet_size);
      uint8_t *rx_packet_data=rx_frame->data.data;
      uint32_t ptr=0;
      int decrypt_error=0;
      for (int i=0; i<rx_packet->fragment_count; ++i) {
        struct navi_rx_packet_fragment_s *pkt=rx_packet->fragments[i];
        if (!pkt) {
          DEBUG_FAILURE(navi_ctx,stream_ctx,"No packet fragment at %d\n",i);
          ++decrypt_error;
          break;
        }
        if (pkt->head.flags&NAVI_DATA_FLAG_ENCRYPTED_DATA) {
          int decrypted_len;
          uint8_t *decrypted_data=pkt->decrypted_data;

          if (!decrypted_data) {
#if NAVI_WITH_MULTICAST==1
            if (rx_packet->mcast_src) {
              decrypted_data=navi_decrypt_with_mcast_secret(navi_ctx, pkt->data, pkt->data_len, &decrypted_len);
            } else
#endif
            {
              decrypted_data=navi_decrypt_with_dh_secret(navi_ctx, pkt->data, pkt->data_len, &decrypted_len);
            }
          }
          else decrypted_len=pkt->decrypted_data_len;

          if (!decrypted_data) {
            DEBUG_FAILURE(navi_ctx,stream_ctx,"Can't decrypt fragment %d\n",i);
            ++decrypt_error;
            break;
          } else {
            memcpy(&rx_packet_data[ptr], &decrypted_data[sizeof(struct NaviProtocolDataFrameHeader)], decrypted_len-sizeof(struct NaviProtocolDataFrameHeader));
            ptr+=decrypted_len-sizeof(struct NaviProtocolDataFrameHeader);
            if (pkt->decrypted_data==decrypted_data) {
              pkt->decrypted_data=NULL;
            }
            free(decrypted_data);
          }
        } else {
          /*
          if (pkt->head.flags&NAVI_DATA_FLAG_DEBUG_DATA_PATH) {
            DEBUG_printf(navi_ctx,stream_ctx,"frag %d ptr %u\n",i,ptr);
            DEBUG_hexdump(&pkt->data[NAVI_AES_ENCRYPTED_LEN(sizeof(struct NaviProtocolDataFrameHeader),NAVI_AES128_TAIL_LEN)], MIN(32,pkt->payload_len));
          }
          */
          if (stream_ctx->desc.encryption==NAVI_ENCRYPT_NONE) {
            memcpy(&rx_packet_data[ptr], &pkt->data[sizeof(struct NaviProtocolDataFrameHeader)], pkt->payload_len);
            ptr+=pkt->payload_len;
          } else {
            const off_t mcast_ofs=rx_packet->mcast_src?sizeof(navi_ctx->mcast.local_iv):0;
            memcpy(&rx_packet_data[ptr], &pkt->data[NAVI_AES_ENCRYPTED_LEN(sizeof(struct NaviProtocolDataFrameHeader),NAVI_AES128_TAIL_LEN)+mcast_ofs], pkt->payload_len);
            ptr+=pkt->payload_len;
          }
        }
      }
      if (!decrypt_error) {
        DEBUG_printf(navi_ctx,stream_ctx,"******* rx packet %p size %d\n",rx_packet_data,rx_packet->packet_size);
        /*
        if (rx_packet->fragments[0]->head.flags&NAVI_DATA_FLAG_DEBUG_DATA_PATH) {
          DEBUG_hexdump(rx_packet_data, MIN(64,rx_packet->packet_size));
        }
        */
        rx_frame->data.data_len=rx_packet->packet_size;
        rx_frame->data.stream_id=stream_ctx->stream_id;
        rx_frame->data.stream_api_id=stream_ctx->stream_api_id;
        rx_frame->data.pts=be64toh(rx_packet->fragments[0]->head.pts);
        rx_frame->data.dts=be64toh(rx_packet->fragments[0]->head.dts);
        rx_frame->data.flags=rx_packet->fragments[0]->head.flags;
        rx_frame->data.packet_id=be32toh(rx_packet->fragments[0]->head.frame_id);
        rx_frame->data.this_buffer=rx_frame;
        pthread_mutex_lock(&stream_ctx->rx_mtx);
        if (stream_ctx->rx_done_queue) {
          for (struct navi_received_frame_s *rxf=stream_ctx->rx_done_queue; rxf; rxf=rxf->next) {
            const uint32_t next_id=rxf->next?rxf->next->data.packet_id:UINT32_MAX;
            if (rx_frame->data.packet_id>rxf->data.packet_id && rx_frame->data.packet_id<next_id) {
              rx_frame->next=rxf->next;
              rxf->next=rx_frame;
            }
          }
        } else {
          rx_frame->next=NULL;
          stream_ctx->rx_done_queue=rx_frame;
        }

        #ifdef DEBUG_DATA_PACKETS
        if (rx_packet->debug_data) {
          struct NaviProtocolStreamDebug *debug_data=(struct NaviProtocolStreamDebug *)rx_packet->debug_data;
          int dbg_data_len=be32toh(debug_data->data_len);
          uint32_t dbg_data_crc=be32toh(debug_data->data_crc);
          /*
          DEBUG_printf(navi_ctx,stream_ctx,"rx debug packet %p\n",rx_packet->debug_data);
          DEBUG_hexdump(rx_packet->debug_data, rx_packet->debug_data_len);
          DEBUG_printf(navi_ctx,stream_ctx,"rx data len %u crc %08x\n",dbg_data_len,dbg_data_crc);
          */
          if (dbg_data_len!=rx_frame->data.data_len) {
            DEBUG_printf(navi_ctx,stream_ctx,"rx frame length missmatch: rx %d dbg %d\n",rx_frame->data.data_len,dbg_data_len);
          } else {
            uint32_t rx_crc=crc32(rx_frame->data.data, 0xFFFFFFFF, dbg_data_len);
            if (rx_crc!=dbg_data_crc) {
              DEBUG_printf(navi_ctx,stream_ctx,"rx frame bad crc: calc %08x dbg %08x\n",rx_crc, dbg_data_crc);
            } else {
              //DEBUG_printf(navi_ctx,stream_ctx,"\nDBG stream %08x frame %d data len %d crc %08x\n",stream_ctx->stream_id,rx_packet->packet_id,rx_frame->data.data_len,rx_crc);
            }
          }
        }
        #endif

        pthread_cond_signal(&stream_ctx->rx_cond);
        pthread_mutex_unlock(&stream_ctx->rx_mtx);

        pthread_mutex_lock(&navi_ctx->rx_mtx);
        pthread_cond_signal(&navi_ctx->rx_cond);
        pthread_mutex_unlock(&navi_ctx->rx_mtx);

        navi_add_perfcounter(&stream_ctx->counters.rx_rate, rx_packet->packet_size);
        navi_add_perfcounter(&stream_ctx->counters.rx_bytes, rx_packet->packet_size);
        navi_inc_perfcounter(&stream_ctx->counters.rx_packets);

        if (stream_ctx->last_rx_id<rx_packet->packet_id) {
          navi_add_perfcounter(&stream_ctx->counters.rx_loss_count, rx_packet->packet_id-stream_ctx->last_rx_id);
          navi_add_perfcounter(&stream_ctx->counters.rx_loss_rate, rx_packet->packet_id-stream_ctx->last_rx_id);
        }
        stream_ctx->last_rx_id=rx_packet->packet_id;

        if (navi_ctx->events.rx_data_event) {
          navi_ctx->events.rx_data_event(navi_ctx, stream_ctx, rx_frame->data.pts, rx_frame->data.dts, rx_frame->data.flags, navi_ctx->events.rx_data_event_data);
        }
      } else {
        DEBUG_printf(navi_ctx,stream_ctx,"decrypt error in proced_rx_queue_packet\n");
        FREEP(rx_frame);
      }
      if (rx_packet->fragments) {
        for (int i=0; i<rx_packet->fragment_count; ++i) {
          if (!rx_packet->fragments[i]) continue;
          if (rx_packet->fragments[i]->decrypted_data) {
            FREEP(rx_packet->fragments[i]->decrypted_data);
          }
          FREEP(rx_packet->fragments[i]);
        }
        FREEP(rx_packet->fragments);
      }
      free_fragment_queue(&rx_packet->fec_packets);
      rx_packet->done++;
      //DEBUG_printf(navi_ctx,stream_ctx,"done packet %p %u\n",rx_packet,rx_packet->packet_id);
      if (rx_packet==stream_ctx->rx_queue[0]) {
        // remove first done packet
        //DEBUG_printf(navi_ctx,stream_ctx,"-- remove first packet %p\n",rx_packet);
        for (int i=1; i<stream_ctx->desc.rx_queue_length; ++i) {
          stream_ctx->rx_queue[i-1]=stream_ctx->rx_queue[i];
        }
        stream_ctx->rx_queue[stream_ctx->desc.rx_queue_length-1]=NULL;
        ++stream_ctx->rx_queue_head;
        DEBUG_printf(navi_ctx,stream_ctx,"-- head now %u (remove first)\n",stream_ctx->rx_queue_head);
        FREEP(rx_packet->debug_data);
        FREEP(rx_packet);
        free_packet_later=false;
        //DEBUG_printf(navi_ctx,stream_ctx,"-- now qhead %u\n",stream_ctx->rx_queue_head);
      }
    }
  }
  return free_packet_later;
}

static
void proced_rx_queue(struct navi_protocol_ctx_s *navi_ctx, struct navi_stream_ctx_s *stream_ctx, const int final_check) {
  DEBUG_printf(navi_ctx,stream_ctx,"-- proced_rx_queue stream %08x head %u\n",stream_ctx->stream_id,stream_ctx->rx_queue_head);
  for (int i=0; i<stream_ctx->desc.rx_queue_length; ++i) {
    struct navi_rx_packet_s *rx_packet=stream_ctx->rx_queue[i];
    if (!rx_packet) continue;

    DEBUG_printf(navi_ctx,stream_ctx,"-- proced rx queue %d %p id %u done %d\n",i,rx_packet,rx_packet->packet_id,rx_packet->done);

    if (rx_packet->done && final_check) {
      FREEP(rx_packet->debug_data);
      FREEP(rx_packet);
      stream_ctx->rx_queue[i]=NULL;
      continue;
    }

    if (!proced_rx_queue_packet(navi_ctx, stream_ctx, final_check, rx_packet)) {
      rx_packet=NULL;
    }

    if (final_check && rx_packet) {
      if (rx_packet->fragments) {
        for (int i=0; i<rx_packet->fragment_count; ++i) {
          if (!rx_packet->fragments[i]) continue;
          FREEP(rx_packet->fragments[i]->decrypted_data);
          FREEP(rx_packet->fragments[i]);
        }
        FREEP(rx_packet->fragments);
      }
      free_fragment_queue(&rx_packet->fec_packets);
      FREEP(rx_packet->debug_data);
      FREEP(rx_packet);
      stream_ctx->rx_queue[i]=NULL;
    }
  }
}

static
void proced_rx_fragment(struct navi_protocol_ctx_s *navi_ctx, struct NaviProtocolFrameHeader *head, struct NaviProtocolDataFrameHeader *fragment_head, const uint32_t stream_id, struct navi_stream_ctx_s *stream_ctx, const bool mcast_src) {
  struct navi_rx_packet_s *rx_packet;
  uint32_t rx_packet_id;
  const int payload_len=be16toh(head->payloadLength);
  struct navi_rx_packet_fragment_s *pkt_fragment;
  uint32_t fragment_idx;

  rx_packet_id=be32toh(fragment_head->frame_id);
  fragment_idx=be16toh(fragment_head->frame_idx);

  DEBUG_printf(navi_ctx,stream_ctx,
    "-- rx to stream %p %s id %u %08x frame idx %d/%d size %d frag size %d flags %x head %u\n",
    stream_ctx,
    stream_ctx->desc.description,
    rx_packet_id,
    rx_packet_id,
    fragment_idx,
    be16toh(fragment_head->frame_count),
    be32toh(fragment_head->frame_size),
    payload_len,
    fragment_head->flags,
    stream_ctx->rx_queue_head
  );

  //DEBUG_hexdump(fragment_head, sizeof(struct NaviProtocolDataFrameHeader));

  if (rx_packet_id<stream_ctx->rx_queue_head) {
    if ((stream_ctx->rx_queue_head-rx_packet_id)==1) {
      DEBUG_printf(navi_ctx,stream_ctx,"duplicate last: head %u rx %u\n",stream_ctx->rx_queue_head,rx_packet_id);
      return;
    }
    DEBUG_FAILURE(navi_ctx,stream_ctx, "rx packet id %08x less than head %08x\n",rx_packet_id,stream_ctx->rx_queue_head);
    return;
  }

  DEBUG_printf(navi_ctx,stream_ctx,"-- rx_packet_id %u rx_queue_head %u length %d flags %02x\n",rx_packet_id,stream_ctx->rx_queue_head,stream_ctx->desc.rx_queue_length,fragment_head->flags);

/*
  if (fragment_head->flags&NAVI_DATA_FLAG_DEBUG_DATA_PATH) {
    DEBUG_hexdump(head->payload,MIN(80,payload_len));
  }
*/

#ifndef DEBUG_DATA_PACKETS
  if (fragment_head->flags&=NAVI_DATA_FLAG_DEBUG_DATA) {
    // ignore debug packet
    return;
  }
#endif

  // frame out of order
  if (rx_packet_id>=(stream_ctx->rx_queue_head+stream_ctx->desc.rx_queue_length)) {
    proced_rx_queue(navi_ctx, stream_ctx, 1);
    DEBUG_printf(navi_ctx,stream_ctx,"-- outoforder packet %u head %u max %u\n",rx_packet_id,stream_ctx->rx_queue_head,stream_ctx->rx_queue_head+stream_ctx->desc.rx_queue_length);
    stream_ctx->rx_queue_head=rx_packet_id;
    DEBUG_printf(navi_ctx,stream_ctx,"-- head now %u\n",rx_packet_id);
  }
  DEBUG_printf(navi_ctx,stream_ctx,"-- get packet %d from qlist %p head %d idx %d flags %d\n",rx_packet_id,stream_ctx->rx_queue,stream_ctx->rx_queue_head,rx_packet_id-stream_ctx->rx_queue_head,fragment_head->flags);
  rx_packet=stream_ctx->rx_queue[rx_packet_id-stream_ctx->rx_queue_head];
  DEBUG_printf(navi_ctx,stream_ctx,"-- rx packet %p\n",rx_packet);
  if (!rx_packet) {
    rx_packet=(struct navi_rx_packet_s *)malloc(sizeof(struct navi_rx_packet_s));
    rx_packet->packet_id=rx_packet_id;
    rx_packet->done=0;
    #ifdef DEBUG_DATA_PACKETS
    if (!(fragment_head->flags&NAVI_DATA_FLAG_DEBUG_DATA)) {
      rx_packet->packet_size=be32toh(fragment_head->frame_size);
      rx_packet->fragment_count=be16toh(fragment_head->frame_count);
      rx_packet->fragments=malloc(sizeof(struct navi_rx_packet_fragment_s *)*rx_packet->fragment_count);
      memset(rx_packet->fragments, 0, sizeof(struct navi_rx_packet_fragment_s *)*rx_packet->fragment_count);
    } else {
      rx_packet->packet_size=0;
      rx_packet->fragment_count=0;
      rx_packet->fragments=NULL;
    }
    #else
    rx_packet->packet_size=be32toh(fragment_head->frame_size);
    rx_packet->fragment_count=be16toh(fragment_head->frame_count);
    rx_packet->fragments=malloc(sizeof(struct navi_rx_packet_fragment_s *)*rx_packet->fragment_count);
    memset(rx_packet->fragments, 0, sizeof(struct navi_rx_packet_fragment_s *)*rx_packet->fragment_count);
    #endif
    rx_packet->debug_data=NULL;
    rx_packet->debug_data_len=0;
    rx_packet->fec_packets=NULL;
    rx_packet->mcast_src=mcast_src;
    stream_ctx->rx_queue[rx_packet_id-stream_ctx->rx_queue_head]=rx_packet;
    DEBUG_printf(navi_ctx,stream_ctx,"-- new rx packet %p\n",rx_packet);
  } else {
    if (rx_packet->done) {
      return; // duplicate packet
    }
  }

#ifdef DEBUG_DATA_PACKETS
  if (fragment_head->flags&NAVI_DATA_FLAG_DEBUG_DATA) {
    DEBUG_printf(navi_ctx,stream_ctx,"** update debug info pkt %d\n",rx_packet_id);
    FREEP(rx_packet->debug_data);
    if (stream_ctx->desc.encryption==NAVI_ENCRYPT_NONE) {
      rx_packet->debug_data=malloc(payload_len);
      rx_packet->debug_data_len=payload_len;
      memcpy(rx_packet->debug_data, head->payload, payload_len);
    } else {
      rx_packet->debug_data=navi_decrypt_with_dh_secret(navi_ctx, head->payload, payload_len, &rx_packet->debug_data_len);
    }
    //DEBUG_hexdump(rx_packet->debug_data, rx_packet->debug_data_len);
    return;
  } else 
  if (rx_packet->packet_size==0 && rx_packet->fragment_count==0) {
    rx_packet->packet_size=be32toh(fragment_head->frame_size);
    rx_packet->fragment_count=be16toh(fragment_head->frame_count);
    rx_packet->fragments=malloc(sizeof(struct navi_rx_packet_fragment_s *)*rx_packet->fragment_count);
    memset(rx_packet->fragments, 0, sizeof(struct navi_rx_packet_fragment_s *)*rx_packet->fragment_count);
    DEBUG_printf(navi_ctx,stream_ctx,"-- update real packet info size %d frags %d\n",rx_packet->packet_size,rx_packet->fragment_count);
  }
#endif

  navi_add_perfcounter(&navi_ctx->counters.rx_rate, payload_len);

  pkt_fragment=malloc(sizeof(struct navi_rx_packet_fragment_s)+payload_len);
  DEBUG_printf(navi_ctx,stream_ctx,"*** fragment %p idx %d len %d\n",pkt_fragment,fragment_idx,payload_len); fflush(stdout);
  pkt_fragment->head=*fragment_head;
  pkt_fragment->data_len=payload_len;
  pkt_fragment->refs=0;
  pkt_fragment->fec=NULL;
  pkt_fragment->decrypted_data=NULL;
  memcpy(pkt_fragment->data, head->payload, payload_len);

  if (fragment_idx==rx_packet->fragment_count-1) {
    pkt_fragment->payload_len=rx_packet->packet_size%stream_ctx->desc.stream_mss;
  } else {
    pkt_fragment->payload_len=stream_ctx->desc.stream_mss;
  }

  if (fragment_head->flags&NAVI_DATA_FLAG_FEC_FRAME) {
    pkt_fragment->next=rx_packet->fec_packets;
    rx_packet->fec_packets=pkt_fragment;
    DEBUG_printf(navi_ctx,stream_ctx,"*** fragment %p enqueue as fec\n",pkt_fragment);
    pkt_fragment=NULL; // mark it enqueued
  } else {
    if (fragment_idx<rx_packet->fragment_count) {
      if (!rx_packet->fragments[fragment_idx]) {
        rx_packet->fragments[fragment_idx]=pkt_fragment;
      } else {
        // duplicate packet
        FREEP(pkt_fragment);
      }
      pkt_fragment=NULL; // mark it enqueued
    }
  }

  if (pkt_fragment) {
    FREEP(pkt_fragment);
    DEBUG_FAILURE(navi_ctx,stream_ctx,"fragment not processed\n");
  }

  if (rx_packet->packet_size) proced_rx_queue_packet(navi_ctx, stream_ctx, !!(fragment_head->flags&NAVI_DATA_FLAG_FEC_FRAME), rx_packet);
}

static inline
const char *frame_type_to_string(const uint16_t type) {
  if (type==NAVICMD_START) return (const char *)"START";
  else if (type==NAVICMD_STREAMS) return (const char *)"STREAMS";
  else if (type==NAVICMD_DATA) return (const char *)"DATA";
  else if (type==NAVICMD_STATS) return (const char *)"STATS";
  return (const char *)"Unknown";
}

static
void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
  struct navi_protocol_ctx_s *navi_ctx=user_ptr;
  struct NaviProtocolFrameHeader *head=(struct NaviProtocolFrameHeader *)data;
  struct NaviProtocolFrameHeader head_copy;
  uint16_t calculated_crc;
  int payload_len;

  if (NAVI_REQUIRE_PROTOCOL_STATE_EQ_Q(navi_ctx,NAVI_STATE_DISCONNECT)) {
    return;
  }

  DEBUG_printf(
    navi_ctx,NULL,
    "RX data %p %lu state %d agent %p %d head type %04x %s stream %08x\n",
    data,size,
    navi_get_protocol_state(navi_ctx),
    agent,juice_get_state(agent),
    be16toh(head->frameType),
    frame_type_to_string(head->frameType),
    be32toh(head->streamId)
  );
  //DEBUG_hexdump(data,size);

  if (!navi_check_rx_frame_size(size,head)) {
    DEBUG_FAILURE(navi_ctx, NULL,"Bad frame size %lu (need %d)\n",size,navi_protocol_frame_size(head));
    navi_inc_perfcounter(&navi_ctx->counters.rx_errors);
    return;
  }

  head_copy=*head;
  head_copy.crc=0xFFFF;
  
  payload_len=be16toh(head->payloadLength);

  calculated_crc=crc16(head->payload, crc16(&head_copy, head_copy.crc, sizeof(head_copy)),payload_len);

  if (be16toh(head->crc)!=calculated_crc) {
    DEBUG_FAILURE(navi_ctx, NULL, "bad crc %04x calc %04x\n",be16toh(head->crc),calculated_crc);
    navi_inc_perfcounter(&navi_ctx->counters.rx_errors);
    return;
  }

  if (head->frameType==NAVICMD_START) {
    if (NAVI_REQUIRE_PROTOCOL_STATE_LT(navi_ctx,NAVI_STATE_DH_SEND)) {
      struct NaviProtocolStartFrame *start=(struct NaviProtocolStartFrame *)head->payload;
      DEBUG_printf(navi_ctx,NULL,"start frame, state %d\n",navi_get_protocol_state(navi_ctx));
      //DEBUG_hexdump(start, payload_len);

      if (memcmp(start->domain, navi_ctx->domain_hash, sizeof(navi_ctx->domain_hash))) {
        DEBUG_FAILURE(navi_ctx, NULL,"bad domain\n");
        navi_inc_perfcounter(&navi_ctx->counters.rx_errors);
        return;
      }

      void *remote_start_pkey=malloc(payload_len);
      void *ptr_to_free;
      memcpy(remote_start_pkey, head->payload, payload_len);
      NAVI_LOCK_CTX(navi_ctx);
      ptr_to_free=navi_ctx->remote_start_pkey;
      navi_ctx->remote_start_pkey=remote_start_pkey;
      navi_ctx->remote_start_pkey_len=payload_len;
      NAVI_UNLOCK_CTX(navi_ctx);
      free(ptr_to_free);

      /*
      if (payload_len!=(sizeof(struct NaviProtocolStartFrame)+navi_ctx->local_pkey_len)) {
        DEBUG_FAILURE(navi_ctx, NULL,"bad start payload length %d!=%ld\n",payload_len,(sizeof(struct NaviProtocolStartFrame)+navi_ctx->local_pkey_len));
        return;
      }
      */
      // openssl can't work good in multithred environment 
      // so copy public key and proced it in main thread
      /*
      NAVI_LOCK_CTX(navi_ctx);
      memcpy(navi_ctx->remote_pkey_data, start->public_key, navi_ctx->local_pkey_len);
      navi_set_protocol_state(navi_ctx, NAVI_STATE_DH_RECEIVED, 0);
      NAVI_UNLOCK_CTX(navi_ctx);
      */
    }
  } else 
  if (head->frameType==NAVICMD_STREAMS) {
    DEBUG_printf(navi_ctx,NULL,"RX NAVICMD_STREAMS len %d\n",payload_len);
    if (navi_ctx->rx_streams_encrypted_len!=payload_len) {
      FREEP(navi_ctx->rx_streams_encrypted);
      navi_ctx->rx_streams_encrypted_len=0;
    }
    if (!navi_ctx->rx_streams_encrypted) {
      navi_ctx->rx_streams_encrypted=malloc(payload_len+1);
      navi_ctx->rx_streams_encrypted_len=payload_len;
    }
    if (payload_len>0) {
      memcpy(navi_ctx->rx_streams_encrypted,head->payload, payload_len);
    }
  } else
  if (head->frameType==NAVICMD_DATA) {
    DEBUG_printf(navi_ctx,NULL,"data frame stream %08x\n",head->streamId);
    if (payload_len>0) {
      int data_len;
      const uint32_t stream_id=be32toh(head->streamId);
      struct navi_stream_ctx_s *stream_ctx=get_stream_by_id_in_queue(stream_id, navi_ctx->rx_streams);
      DEBUG_printf(navi_ctx,stream_ctx,"RX stream ctx %p\n",stream_ctx);
      if (stream_ctx) {
        navi_add_perfcounter(&stream_ctx->counters.net_rx_rate, size);
        if (stream_ctx->desc.encryption==NAVI_ENCRYPT_NONE) {
          proced_rx_fragment(navi_ctx, head, (struct NaviProtocolDataFrameHeader*)head->payload, stream_id, stream_ctx, false);
        } else {
          void *decrypted_data=navi_decrypt_with_dh_secret(navi_ctx, head->payload, sizeof(struct NaviProtocolDataFrameHeader)+NAVI_AES128_TAIL_LEN, &data_len);
          if (decrypted_data && data_len>=sizeof(struct NaviProtocolDataFrameHeader)) {
            proced_rx_fragment(navi_ctx, head, (struct NaviProtocolDataFrameHeader*)decrypted_data, stream_id, stream_ctx, false);
          } else {
            DEBUG_FAILURE(navi_ctx, stream_ctx,"Can't decrypt frame fragment header %p %d\n",decrypted_data,data_len);
          }
          free(decrypted_data);
        }
      }
    }
  } else 
  if (head->frameType==NAVICMD_STATS) {
    //DEBUG_printf(navi_ctx,NULL,"stats frame stream %08x\n",head->streamId);
    if (payload_len>=sizeof(struct NaviProtocolStatisticElement)) {
      int data_len;
      const uint32_t stream_id=be32toh(head->streamId);
      struct navi_stream_ctx_s *stream_ctx=get_stream_by_id_in_queue(stream_id, navi_ctx->tx_streams);
      //DEBUG_printf(navi_ctx,NULL,"STATS stream ctx %p\n",stream_ctx);
      if (stream_ctx) {
        struct NaviProtocolStatisticElement *items=NULL;
        int nitems;
        if (stream_ctx->desc.encryption==NAVI_ENCRYPT_NONE) {
          if ((payload_len%(sizeof(struct NaviProtocolStatisticElement)))==0) {
            items=(struct NaviProtocolStatisticElement *)head->payload;
            nitems=payload_len/sizeof(struct NaviProtocolStatisticElement);
          }
        } else {
          int data_len;
          void *decrypted_data=navi_decrypt_with_dh_secret(navi_ctx, head->payload, payload_len, &data_len);
          if (decrypted_data && 
              data_len>=sizeof(struct NaviProtocolStatisticElement) && 
              (data_len%(sizeof(struct NaviProtocolStatisticElement)))==0) {
            items=(struct NaviProtocolStatisticElement *)decrypted_data;
            nitems=data_len/sizeof(struct NaviProtocolStatisticElement);
          } else {
            DEBUG_FAILURE(navi_ctx,stream_ctx,"Can't decrypt stats frame fragment header %p %d\n",decrypted_data,data_len);
          }
          if (!items) free(decrypted_data);
        }
        if (items) {
          //DEBUG_hexdump(items, nitems*sizeof(struct NaviProtocolStatisticElement));
          for (int i=0; i<nitems; ++i) {
            struct NaviProtocolStatisticElement *item=&items[i];
            const uint16_t hash=be16toh(item->hash);
            #define COPY_PC(name) { \
              if (stream_ctx->remote_counters.name.hash==hash) { \
                if (item->flags&NAVI_STAT_FLAG_GAUGE) { \
                  switch (item->flags&NAVI_STAT_FLAG_TYPE_MASK) { \
                    case NAVI_STAT_FLAG_DOUBLE: \
                      stream_ctx->remote_counters.name.counter=navi_perfcounter_read_double(&item->value); \
                      break; \
                    case NAVI_STAT_FLAG_INTEGER: \
                      stream_ctx->remote_counters.name.counter=navi_perfcounter_read_u64(&item->value); \
                      break; \
                  } \
                } else { \
                  switch (item->flags&NAVI_STAT_FLAG_TYPE_MASK) { \
                    case NAVI_STAT_FLAG_DOUBLE: \
                      stream_ctx->remote_counters.name.rate=navi_perfcounter_read_double(&item->value); \
                      break; \
                    case NAVI_STAT_FLAG_INTEGER: \
                      stream_ctx->remote_counters.name.rate=navi_perfcounter_read_u64(&item->value); \
                      break; \
                  } \
                } \
                break; \
              } \
            }
            do {
              COPY_PC(rx_rate);
              COPY_PC(tx_rate);
              COPY_PC(rx_bytes);
              COPY_PC(tx_bytes);
              COPY_PC(rx_packets);
              COPY_PC(tx_packets);
              COPY_PC(tx_frames);
              COPY_PC(rx_loss_rate);
              COPY_PC(rx_loss_count);
              COPY_PC(rx_recover_rate);
              COPY_PC(rx_recover_count);
              COPY_PC(tx_codec_rate);
              COPY_PC(net_rx_rate);
              COPY_PC(net_tx_rate);
            } while (0);
            #undef COPY_PC  
          }
          navi_ctx->last_stats_dt=stream_ctx->remote_counters_time=navi_current_time(navi_ctx);
          if ((void *)items!=(void *)head->payload) {
            free(items);
          }
        }
      }
    }
  }

  navi_add_perfcounter(&navi_ctx->counters.rx_rate, size);
}

int navi_transport_create(struct navi_protocol_ctx_s *navi_ctx) {
  juice_config_t config;
  juice_agent_t *agent;
  int res=-1;

  if (!navi_ctx->config.unicast_enable) return 0;

  if (navi_ctx->ice_agent) return 0;

  if (create_signalling(navi_ctx)<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't create signaling connection\n");
    return -1;
  }

#ifdef NAVI_WITH_DEBUG
  juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);
#endif

  memset(&config, 0, sizeof(config));
  config.stun_server_host=navi_ctx->config.stun_server_host;
  config.stun_server_port=navi_ctx->config.stun_server_port;

  for(char *turn_server=navi_ctx->config.turn_servers; turn_server[0];) {
    char *login=NULL,*password=NULL,*host=NULL;
    int port,len;
    juice_turn_server_t turn;
    juice_turn_server_t *turn_list;

    DEBUG_printf(navi_ctx,NULL,"turn '%s'\n",turn_server);
    if (sscanf(turn_server, "%m[^:]:%m[^@]@%m[^:]:%d%n",&login,&password,&host,&port,&len)!=4) break;
    DEBUG_printf(navi_ctx,NULL,"'%s' '%s' '%s' %d %d\n",login,password,host,port,len);

    memset(&turn, 0, sizeof(juice_turn_server_t));
    turn.host=host;
    turn.port=port;
    turn.username=login;
    turn.password=password;
    turn_list=realloc(config.turn_servers, (config.turn_servers_count+1)*sizeof(juice_turn_server_t));
    if (!turn_list) {
      FREEP(config.turn_servers);
      goto out;
    }
    config.turn_servers=turn_list;
    config.turn_servers[config.turn_servers_count]=turn;
    ++config.turn_servers_count;

    turn_server+=len;
    if (turn_server[0]!=',' && turn_server[0]!=' ') break;
    ++turn_server;
  }

  config.cb_state_changed = on_state_changed;
	config.cb_candidate = on_candidate;
	config.cb_gathering_done = on_gathering_done;
	config.cb_recv = on_recv;
	config.user_ptr = navi_ctx;

  agent=juice_create(&config);

  if (agent) {
    navi_ctx->ice_agent=agent;
    res=0;
  }

out:
  for (int i=0; i<config.turn_servers_count; ++i) {
    free((void*)(config.turn_servers[i].host));
    free((void*)(config.turn_servers[i].username));
    free((void*)(config.turn_servers[i].password));
  }
  free(config.turn_servers);

  return res;
}

int navi_transport_send_offer(struct navi_protocol_ctx_s *navi_ctx) {
  juice_agent_t *agent=navi_ctx->ice_agent;
  int offer_len;
  void *offer_payload;
  char sdp[JUICE_MAX_SDP_STRING_LEN];

  if (!navi_ctx->config.unicast_enable) return 0;

  if (!agent) {
    DEBUG_FAILURE(navi_ctx, NULL, "no agent\n");
    return -1;
  }

  if (!NAVI_REQUIRE_PROTOCOL_STATE_LT(navi_ctx,NAVI_STATE_DH_GENERATE)) return -1;

  if (navi_ctx->offer_data) {
    navi_ctx->offer_time=navi_current_time(navi_ctx);
    return signalling_send(navi_ctx, NS_UPDATE_OFFER, navi_ctx->offer_data, navi_ctx->offer_data_len);
  }

	juice_get_local_description(agent, sdp, JUICE_MAX_SDP_STRING_LEN);

  DEBUG_printf(navi_ctx,NULL,"send offer sdp '%s'\n",sdp);

  offer_len=tlv_encode(
    navi_ctx,
    NULL, signalling_data_dict, NULL, 
    DICT_OFFER_CLIENT_NAME, navi_ctx->config.client_name,
    DICT_OFFER_SDP, sdp,
    TLV_END
  );

  if (offer_len<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't serialize offer\n");
    return -1;
  }

  offer_payload=alloca(offer_len);

  offer_len=tlv_encode(
    navi_ctx,
    offer_payload, signalling_data_dict, NULL, 
    DICT_OFFER_CLIENT_NAME, navi_ctx->config.client_name,
    DICT_OFFER_SDP, sdp,
    TLV_END
  );

  if (offer_len<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't serialize offer\n");
    return -1;
  }

  navi_ctx->offer_data=navi_encrypt_with_secret(navi_ctx, offer_payload, offer_len, &navi_ctx->offer_data_len);
  if (!navi_ctx->offer_data) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't encrypt offer\n");
    return -1;
  }

  navi_set_protocol_state(navi_ctx, NAVI_STATE_ICE, 1);

  navi_ctx->offer_time=navi_current_time(navi_ctx);

  return signalling_send(navi_ctx, NS_UPDATE_OFFER, navi_ctx->offer_data, navi_ctx->offer_data_len);
}

static
int navi_signalling_update_state(struct navi_protocol_ctx_s *navi_ctx, const uint8_t state) {
  int state_len;
  void *state_payload;
  void *state_data;
  int state_data_len;
  int res;
  
  state_len=tlv_encode(
    navi_ctx,
    NULL, signalling_data_dict, NULL, 
    DICT_OFFER_CLIENT_NAME, navi_ctx->config.client_name,
    DICT_CLIENT_STATE, state,
    TLV_END
  );

  if (state_len<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't serialize state\n");
    return -1;
  }

  state_payload=alloca(state_len);

  state_len=tlv_encode(
    navi_ctx,
    state_payload, signalling_data_dict, NULL, 
    DICT_OFFER_CLIENT_NAME, navi_ctx->config.client_name,
    DICT_CLIENT_STATE, state,
    TLV_END
  );

  if (state_len<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't serialize state\n");
    return -1;
  }

  state_data=navi_encrypt_with_secret(navi_ctx, state_payload, state_len, &state_data_len);
  if (!state_data) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't encrypt state\n");
    return -1;
  }
  res=signalling_send(navi_ctx, NS_UPDATE_STATE, state_data, state_data_len);

  free(state_data);

  return res;
}

int navi_transport_get_clients(struct navi_protocol_ctx_s *navi_ctx) {
  int res;

  if (!navi_ctx->config.unicast_enable) return 0;

  if (!NAVI_REQUIRE_PROTOCOL_STATE_EQ(navi_ctx,NAVI_STATE_INIT)) return -1;

  res=signalling_send(navi_ctx, NS_GET_CLIENTS, "", 0);
  if (res<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't send request\n");
    return -1;
  }

  sleep(1);

  signalling_check(navi_ctx);

  return 0;
}

int navi_transport_connect_client(struct navi_protocol_ctx_s *navi_ctx, const char *name, const char *sdp) {
  juice_agent_t *agent=navi_ctx->ice_agent;
  juice_state_t state;
  int answer_len;
  void *answer_payload;
  void *encrypted_data;
  int encrypted_len;
  int res;
  char answer_sdp[JUICE_MAX_SDP_STRING_LEN];

  if (navi_ctx->mcast.enable && !sdp) {
    free(navi_ctx->mcast.connect_to_client);
    navi_ctx->mcast.connect_to_client=strdup(name);
    return 0;
  }

  if (!navi_ctx->config.unicast_enable) return 0;

  if (!agent) return -1;

  state=juice_get_state(agent);

  if (state!=JUICE_STATE_DISCONNECTED) {
    DEBUG_FAILURE(navi_ctx, NULL, "bad ice transport state %d\n",state);
    return -1;
  }

  juice_get_local_description(agent, answer_sdp, JUICE_MAX_SDP_STRING_LEN);

  navi_ctx->client_hash=crc32(name, 0xFFFFFFFF, strlen(navi_ctx->config.client_name));

  answer_len=tlv_encode(
    navi_ctx,
    NULL, signalling_data_dict, NULL, 
    DICT_OFFER_CLIENT_NAME, navi_ctx->config.client_name,
    DICT_OFFER_SDP, answer_sdp,
    TLV_END
  );

  if (answer_len<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't serialize answer\n");
    return -1;
  }

  answer_payload=alloca(answer_len);

  answer_len=tlv_encode(
    navi_ctx,
    answer_payload, signalling_data_dict, NULL, 
    DICT_OFFER_CLIENT_NAME, navi_ctx->config.client_name,
    DICT_OFFER_SDP, answer_sdp,
    TLV_END
  );

  if (answer_len<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't serialize answer\n");
    return -1;
  }

  DEBUG_printf(navi_ctx,NULL,"\nsend offer\n");
  DEBUG_hexdump(answer_payload, answer_len);

  encrypted_data=navi_encrypt_with_secret(navi_ctx, answer_payload, answer_len, &encrypted_len);
  if (!encrypted_data) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't encrypt offer\n");
    return -1;
  }

  res=signalling_send(navi_ctx, NS_UPDATE_ANSWER, encrypted_data, encrypted_len);

  free(encrypted_data);

  if (res<0) return -1;

  if (juice_set_remote_description(agent, sdp)) {
    DEBUG_FAILURE(navi_ctx, NULL, "can't set remote description\nSDP:\n%s\n\n",sdp);
    return -1;
  }

  juice_gather_candidates(agent);

  navi_set_protocol_state(navi_ctx, NAVI_STATE_ICE, 1);

  return 0;
}

static
void navi_send_stream_stats(struct navi_protocol_ctx_s *navi_ctx, struct navi_stream_ctx_s *stream_ctx, const uint64_t dt_ms) {
  //DEBUG_printf(navi_ctx,stream_ctx,"===== send stats stream %08x\n",stream_ctx->stream_id);

  struct NaviProtocolStatisticElement items[sizeof(stream_ctx->counters)/sizeof(navi_perfcounter)];
  int ptr=0;
#define COPY_PC(name) do { \
  if (ptr>=(sizeof(stream_ctx->counters)/sizeof(navi_perfcounter))) { \
    DEBUG_printf(navi_ctx,stream_ctx,"COPY_PC: items overflow\n"); \
    return; \
  } \
  items[ptr].hash=htobe16(stream_ctx->counters.name.hash); \
  if (stream_ctx->counters.name.gauge) { \
    items[ptr].flags=NAVI_STAT_FLAG_GAUGE|NAVI_STAT_FLAG_INTEGER; \
    navi_perfcounter_write_u64(navi_read_perfcounter_counter(&stream_ctx->counters.name),&items[ptr].value); \
  } else { \
    items[ptr].flags=NAVI_STAT_FLAG_DOUBLE; \
    navi_perfcounter_write_double(navi_read_perfcounter(&stream_ctx->counters.name,dt_ms),&items[ptr].value); \
  } \
  ++ptr; \
} while (0)
  
  COPY_PC(rx_rate);
  COPY_PC(tx_rate);
  COPY_PC(rx_bytes);
  COPY_PC(tx_bytes);
  COPY_PC(rx_packets);
  COPY_PC(tx_packets);
  COPY_PC(tx_frames);
  COPY_PC(rx_loss_rate);
  COPY_PC(rx_loss_count);
  COPY_PC(rx_recover_rate);
  COPY_PC(rx_recover_count);
  COPY_PC(tx_codec_rate);
  COPY_PC(net_rx_rate);
  COPY_PC(net_tx_rate);

#undef COPY_PC

  if (stream_ctx->desc.encryption==NAVI_ENCRYPT_NONE) {
    if (navi_send_frame(navi_ctx, NAVICMD_STATS, stream_ctx->stream_id, &items, sizeof(items))<0) {
      DEBUG_FAILURE(navi_ctx,stream_ctx,"Can't send stats frame\n");
    }
  } else {
    uint8_t *encrypted_data=alloca(navi_ctx->mss+32);
    int encrypted_len;

    if (!navi_encrypt_with_dh_secret(navi_ctx, &items, sizeof(items), &encrypted_len, encrypted_data)) {
      DEBUG_FAILURE(navi_ctx,stream_ctx,"Can't encrypt stats frame, stream %p\n",stream_ctx);
      return;
    }

    //DEBUG_printf(navi_ctx,stream_ctx,"===== send encrypted stats %p %d %lu stream %08x\n",encrypted_data, encrypted_len, sizeof(items), stream_ctx->stream_id);

    if (navi_send_frame(navi_ctx, NAVICMD_STATS, stream_ctx->stream_id, encrypted_data, encrypted_len)<0) {
      DEBUG_FAILURE(navi_ctx,stream_ctx,"Can't send stats frame\n");
    }
  }
}

static
void navi_check_stream_quality(struct navi_protocol_ctx_s *navi_ctx, struct navi_stream_ctx_s *stream_ctx, const uint64_t dt_ms) {
  if (dt_ms-stream_ctx->remote_counters_time>(NAVI_STATS_PERIOD*2)) {
    DEBUG_printf(navi_ctx,stream_ctx,"stream %08x: Can't check quality - remote data too old\n",stream_ctx->stream_id);
    return;
  }

  

}

static 
int navi_transport_work_ICE(struct navi_protocol_ctx_s *navi_ctx, const uint64_t now_dt) {
  juice_agent_t *agent=navi_ctx->ice_agent;

//  DEBUG_printf(navi_ctx,NULL,"navi_transport_work_ICE: ice_agent_state (start) %d\n",navi_ctx->ice_agent_state);

  signalling_check(navi_ctx);

  if (now_dt<navi_ctx->offer_time) navi_ctx->offer_time=0;

  if (navi_ctx->ice_agent_state==JUICE_STATE_DISCONNECTED && (now_dt-navi_ctx->offer_time)>NAVI_OFFER_RESEND) {
    navi_transport_send_offer(navi_ctx);
  }

//  DEBUG_printf(navi_ctx,NULL,"navi_transport_work_ICE: ice_agent_state (check) %d\n",navi_ctx->ice_agent_state);

  if (navi_ctx->ice_agent_state==JUICE_STATE_CONNECTED || navi_ctx->ice_agent_state==JUICE_STATE_COMPLETED) {
    navi_set_protocol_state(navi_ctx, NAVI_STATE_DH_GENERATE, 1);
  }
  return 0;
}

static 
int navi_transport_work_DH_SEND(struct navi_protocol_ctx_s *navi_ctx) {
  struct NaviProtocolStartFrame *start;
  const int start_len=sizeof(struct NaviProtocolStartFrame)+navi_ctx->local_pkey_len;
  start=alloca(start_len);
  memcpy(start->domain, navi_ctx->domain_hash, sizeof(navi_ctx->domain_hash));
  memcpy(start->public_key, navi_ctx->local_pkey_data, navi_ctx->local_pkey_len);
  DEBUG_printf(navi_ctx,NULL,"--- send DH\n");
  int res=navi_send_frame(navi_ctx, NAVICMD_START, NAVI_INFO_STREAM, start, start_len);
  
  void *remote_start_pkey;
  int remote_start_pkey_len;
  
  NAVI_LOCK_CTX(navi_ctx);
  remote_start_pkey=navi_ctx->remote_start_pkey;
  remote_start_pkey_len=navi_ctx->remote_start_pkey_len;
  navi_ctx->remote_start_pkey=NULL;
  NAVI_UNLOCK_CTX(navi_ctx);

  if (!remote_start_pkey) return res;

  if (remote_start_pkey_len!=(sizeof(struct NaviProtocolStartFrame)+navi_ctx->local_pkey_len)) {
    DEBUG_FAILURE(navi_ctx, NULL,"bad start payload length %d!=%ld\n",remote_start_pkey_len,(sizeof(struct NaviProtocolStartFrame)+navi_ctx->local_pkey_len));
  } else {
    struct NaviProtocolStartFrame *start=(struct NaviProtocolStartFrame *)remote_start_pkey;
    memcpy(navi_ctx->remote_pkey_data, start->public_key, navi_ctx->local_pkey_len);
    navi_set_protocol_state(navi_ctx, NAVI_STATE_DH_RECEIVED, 0);
  }

  free(remote_start_pkey);  

  return res;
}

static 
int navi_transport_work_DH_GENERATE(struct navi_protocol_ctx_s *navi_ctx) {
  DEBUG_printf(navi_ctx,NULL,"--- generate keys\n");
  if (navi_generate_keys(navi_ctx)<0) return -1;
  navi_set_protocol_state(navi_ctx, NAVI_STATE_DH_SEND, 1);
  // send DH right after creating, not in next loop
  return navi_transport_work_DH_SEND(navi_ctx);
}

static 
int navi_transport_work_DH_RECEIVED(struct navi_protocol_ctx_s *navi_ctx) {
  if (navi_generate_secret(navi_ctx)<0) {
    DEBUG_FAILURE(navi_ctx, NULL,"Can't create secret\n");
    return -1;
  }
  navi_set_protocol_state(navi_ctx, NAVI_STATE_WAIT_START, 1);
  return 0;
}

static 
int navi_transport_work_WAIT_START(struct navi_protocol_ctx_s *navi_ctx) {
  int data_len;
  int ptr;
  struct navi_stream_ctx_s **streams;
  void *streams_data;
  void *data;

  if (navi_ctx->rx_streams_encrypted) {
    DEBUG_printf(navi_ctx,NULL,"WAIT START streams frame\n");
    //DEBUG_hexdump(navi_ctx->rx_streams_encrypted, navi_ctx->rx_streams_encrypted_len);
    if (navi_ctx->rx_streams_encrypted_len>0) {
      int data_len;
      void *data=navi_decrypt_with_dh_secret(navi_ctx, navi_ctx->rx_streams_encrypted, navi_ctx->rx_streams_encrypted_len, &data_len);
      if (data) {
        int res;
        int stream_count;
        //DEBUG_hexdump(data, data_len);
        res=tlv_decode(
          navi_ctx, 
          data, data_len, 
          protocol_data_dict, 
          NULL, 
          DICT_ANOUNCE_STREAM_COUNT, &stream_count, 
          DICT_ANOUNCE_STREAM, navi_ctx, // stream decoder also create list of streams
          TLV_END
        );
        free(data);
        if (res>=0) navi_set_protocol_state(navi_ctx, NAVI_STATE_PROCED_STREAMS, 1);
      }
    } else {
      // no streams
      navi_set_protocol_state(navi_ctx, NAVI_STATE_PROCED_STREAMS, 1);
    }
  }

  // in this state send DH frame, login frame, wait for login frame
  if (navi_transport_work_DH_SEND(navi_ctx)<0) return -1;

  if (!navi_ctx->tx_streams) {
    if (!navi_ctx->rx_streams_encrypted) return 0;
    return navi_send_frame(navi_ctx, NAVICMD_STREAMS, NAVI_INFO_STREAM, "", 0);
  }

  if (navi_ctx->tx_streams_enc_data) {
    return navi_send_frame(navi_ctx, NAVICMD_STREAMS, NAVI_INFO_STREAM, navi_ctx->tx_streams_enc_data, navi_ctx->tx_streams_enc_len);
  }

  streams=(struct navi_stream_ctx_s **)alloca(sizeof(struct navi_stream_ctx_s *)*navi_ctx->tx_stream_count);
  ptr=0;
  for (struct navi_stream_ctx_s *s=navi_ctx->tx_streams; s; s=s->next) {
    streams[ptr++]=s;
  }

  data_len=tlv_encode(
    navi_ctx, 
    NULL, 
    protocol_data_dict, 
    navi_ctx, 
    DICT_ANOUNCE_STREAM_COUNT, ptr,
    TLV_ARRAY_OF(DICT_ANOUNCE_STREAM, ptr), streams, 
    TLV_END
  );
  if (data_len<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "can't seralize tx streams\n");
    return -1;
  }

  streams_data=malloc(data_len);
  data_len=tlv_encode(
    navi_ctx, 
    streams_data, 
    protocol_data_dict, 
    navi_ctx, 
    DICT_ANOUNCE_STREAM_COUNT, ptr,
    TLV_ARRAY_OF(DICT_ANOUNCE_STREAM, ptr), streams, 
    TLV_END
  );
  if (data_len<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "can't seralize tx streams\n");
    free(streams_data);
    return -1;
  }

  DEBUG_printf(navi_ctx,NULL,"-- send streams %d %d\n",data_len,ptr);
  //DEBUG_hexdump(streams_data, data_len);

  data=navi_encrypt_with_dh_secret(navi_ctx, streams_data, data_len, &data_len, NULL);
  free(streams_data);
  if (!data) {
    DEBUG_FAILURE(navi_ctx, NULL, "can't encrypt tx streams\n");
    return -1;
  }

  navi_ctx->tx_streams_enc_data=data;
  navi_ctx->tx_streams_enc_len=data_len;

  return navi_send_frame(navi_ctx, NAVICMD_STREAMS, NAVI_INFO_STREAM, data, data_len);
}

static
int navi_transport_work_PROCED_STREAMS(struct navi_protocol_ctx_s *navi_ctx) {
  if (navi_ctx->events.rx_stream_event) {
    for (struct navi_stream_ctx_s *s=navi_ctx->rx_streams; s; s=s->next) {
      navi_ctx->events.rx_stream_event(navi_ctx, s, s->stream_id, &s->desc, navi_ctx->events.rx_stream_event_data);
    }
    navi_ctx->events.rx_stream_event(navi_ctx, NULL, 0, NULL, navi_ctx->events.rx_stream_event_data);
  }
  navi_set_protocol_state(navi_ctx, NAVI_STATE_ONLINE, 1);
  navi_signalling_update_state(navi_ctx, NAVI_SIGNALLING_STATE_BUSY);
  return 0;
}

static 
int navi_transport_work_ONLINE(struct navi_protocol_ctx_s *navi_ctx) {
  const uint64_t now_dt=navi_current_time(navi_ctx);
  if (now_dt) {
    for (struct navi_stream_ctx_s *s=navi_get_rx_streams(navi_ctx); s; s=s->next) {
      if (!navi_get_rx_streams(navi_ctx)) break;
      if (now_dt<s->last_stats_time) {
        s->last_stats_time=0;
        continue;
      }
      if (now_dt-s->last_stats_time>NAVI_STATS_PERIOD) {
        s->last_stats_time=now_dt;
        navi_send_stream_stats(navi_ctx, s,now_dt);
      }

      if (navi_ctx->events.quality_event) {
        if (now_dt<s->last_quality_time) {
          s->last_quality_time=0;
          continue;
        }
        if (now_dt-s->last_quality_time>NAVI_QUALITY_PERIOD) {
          s->last_quality_time=now_dt;
          navi_check_stream_quality(navi_ctx, s, now_dt);
        }
      }
    }
  }

  if (navi_ctx->last_stats_dt && now_dt && now_dt>navi_ctx->last_stats_dt) {
    if ((now_dt-navi_ctx->last_stats_dt)>NAVI_STATS_PERIOD*5) {
      // remote side not responding
      DEBUG_printf(navi_ctx,NULL,"client stats timeout\n");
      navi_set_protocol_state(navi_ctx, NAVI_STATE_DISCONNECT, 1);
      navi_signalling_update_state(navi_ctx, NAVI_SIGNALLING_STATE_RECONNECT);
    }
  }

  return 0;
}

static 
int navi_transport_work_DISCONNECT(struct navi_protocol_ctx_s *navi_ctx) {
  struct navi_stream_ctx_s *rx_streams;
  juice_agent_t *agent=navi_ctx->ice_agent;

  if (agent) {
    juice_destroy(agent);
    navi_ctx->ice_agent=NULL;
  }

  FREEP(navi_ctx->offer_data);
  navi_ctx->offer_data_len=0;
  FREEP(navi_ctx->remote_pkey_data);
  FREEP(navi_ctx->remote_start_pkey);
  navi_ctx->remote_start_pkey_len=0;
  FREEP(navi_ctx->tx_streams_enc_data);
  navi_ctx->tx_streams_enc_len=0;

  navi_ctx->candidate_list_version=0;
  navi_ctx->last_stats_dt=0;

  navi_reset_perfcounter(&navi_ctx->counters.signalling_tx);
  navi_reset_perfcounter(&navi_ctx->counters.signalling_rx);
  navi_reset_perfcounter(&navi_ctx->counters.signalling_rx_error);
  navi_reset_perfcounter(&navi_ctx->counters.rx_rate);
  navi_reset_perfcounter(&navi_ctx->counters.rx_errors);
  navi_reset_perfcounter(&navi_ctx->counters.tx_rate);
  navi_reset_perfcounter(&navi_ctx->counters.tx_bytes);
  navi_reset_perfcounter(&navi_ctx->counters.rx_bytes);
  navi_reset_perfcounter(&navi_ctx->counters.tx_packets);
  navi_reset_perfcounter(&navi_ctx->counters.rx_packets);
  navi_reset_perfcounter(&navi_ctx->mcast.counters.rx_rate);
  navi_reset_perfcounter(&navi_ctx->mcast.counters.tx_rate);

#define RESET_PC(stream,name) do { \
  navi_reset_perfcounter(&stream->counters.name); \
  navi_reset_perfcounter(&stream->remote_counters.name); \
} while (0)

  for (struct navi_stream_ctx_s *s=navi_ctx->tx_streams; s; s=s->next) {
    RESET_PC(s,rx_rate);
    RESET_PC(s,tx_rate);
    RESET_PC(s,rx_bytes);
    RESET_PC(s,tx_bytes);
    RESET_PC(s,rx_packets);
    RESET_PC(s,tx_packets);
    RESET_PC(s,tx_frames);
    RESET_PC(s,rx_loss_rate);
    RESET_PC(s,rx_loss_count);
    RESET_PC(s,rx_recover_rate);
    RESET_PC(s,rx_recover_count);
    RESET_PC(s,tx_codec_rate);
    RESET_PC(s,net_rx_rate);
    RESET_PC(s,net_tx_rate);
    navi_reset_perfcounter(&s->mcast.counters.net_tx_rate);
  }
#undef RESET_PC

  pthread_spin_lock(&navi_ctx->rx_streams_lock);
  rx_streams=navi_ctx->rx_streams;
  navi_ctx->rx_streams=NULL;
  pthread_spin_unlock(&navi_ctx->rx_streams_lock);

  for (struct navi_stream_ctx_s *stream=rx_streams; stream; stream=stream->next) {
    while (stream->rx_done_queue) {
      struct navi_received_frame_s *frame=stream->rx_done_queue;
      stream->rx_done_queue=stream->rx_done_queue->next;
      free(frame);
    }

    if (stream->rx_queue) {
      for (int rxn=0; rxn<stream->desc.rx_queue_length; ++rxn) {
        struct navi_rx_packet_s *rx_packet=stream->rx_queue[rxn];
        if (!rx_packet) continue;
        stream->rx_queue[rxn]=NULL;

        if (rx_packet->fragments) {
          for (int i=0; i<rx_packet->fragment_count; ++i) {
            if (!rx_packet->fragments[i]) continue;
            FREEP(rx_packet->fragments[i]->decrypted_data);
            FREEP(rx_packet->fragments[i]);
          }
          FREEP(rx_packet->fragments);
        }
        free_fragment_queue(&rx_packet->fec_packets);
        FREEP(rx_packet->debug_data);
        FREEP(rx_packet);
      }
    }
  }  

  navi_ctx->delayed_state_change=NAVI_STATE_RECONNECT;
  navi_ctx->delayed_state_change_time=NAVI_RECONNECT_DELAY+navi_current_time(navi_ctx);

  return 0;
}

static 
int navi_transport_work_RECONNECT(struct navi_protocol_ctx_s *navi_ctx) {
  navi_set_protocol_state(navi_ctx, NAVI_STATE_INIT, 1);
  
  DEBUG_printf(navi_ctx,NULL,"transport create\n");
  
  if (navi_transport_create(navi_ctx)<0) {
    DEBUG_FAILURE(navi_ctx, NULL,"Can't create transport when reconnect\n");
    return -1;
  }

  DEBUG_printf(navi_ctx,NULL,"send offer\n");

  if (navi_transport_send_offer(navi_ctx)<0) {
    DEBUG_FAILURE(navi_ctx, NULL,"Can't send offer when reconnect\n");
    return -1;
  }

  return 0;
}

int navi_transport_work(struct navi_protocol_ctx_s *navi_ctx) {
  for(;;) {
    enum navi_protocol_state_e state1;
    enum navi_protocol_state_e state0=navi_get_protocol_state(navi_ctx);
    int res=-1;
    const uint64_t now_dt=navi_current_time(navi_ctx);

    #if NAVI_WITH_MULTICAST==1
    if (navi_ctx->mcast.enable) {
      if (!navi_ctx->mcast.secret_valid) {
        navi_generate_mcast_secret(navi_ctx);
      }
      navi_check_mcast_discovery(navi_ctx, now_dt);
      if (navi_ctx->tx_streams) navi_send_mcast_announce(navi_ctx, now_dt);

      if (navi_mcast_available(navi_ctx) && now_dt) {
        if (navi_ctx->mcast.send_reports && navi_ctx->rx_stream_count>0) {
          navi_send_mcast_report(navi_ctx, now_dt);
        }
        if (navi_ctx->mcast.receive_reports && navi_ctx->tx_stream_count>0) {
          navi_mcast_check_report(navi_ctx, now_dt);
        }
        if (navi_ctx->mcast.ondemand_enable) {
          for (struct navi_stream_ctx_s *s=navi_ctx->tx_streams; s; s=s->next) {
            s->mcast.report_rx_timeout=(now_dt-s->mcast.remote_report.report_time)>(NAVI_MCAST_REPORT_PERIOD*2);
          }
        } else {
          for (struct navi_stream_ctx_s *s=navi_ctx->tx_streams; s; s=s->next) {
            s->mcast.report_rx_timeout=false;
          }
        }
      }
    }
    #endif

    if (!navi_ctx->config.unicast_enable) {
      return 0;
    }

    if (navi_ctx->events.state_event && navi_ctx->report_state_change!=NAVI_STATE_NOREPORT) {
      navi_ctx->events.state_event(navi_ctx, navi_ctx->events.state_event_data);
      navi_ctx->report_state_change=NAVI_STATE_NOREPORT;
    }
    if (navi_ctx->delayed_state_change_time && navi_ctx->delayed_state_change!=NAVI_STATE_NOREPORT) {
      if (now_dt<navi_ctx->delayed_state_change_time) {
        DEBUG_printf(navi_ctx,NULL,"wait for state %d for %lu ms\n",navi_ctx->delayed_state_change,navi_ctx->delayed_state_change_time-now_dt);
        return 0;
      }
      navi_ctx->delayed_state_change_time=0;
      navi_set_protocol_state(navi_ctx, navi_ctx->delayed_state_change, 1);
      navi_ctx->delayed_state_change=NAVI_STATE_NOREPORT;
    }
    //DEBUG_printf(navi_ctx,NULL,"********** work state %d\n",state0);
    switch (navi_get_protocol_state(navi_ctx)) {
      case NAVI_STATE_NOREPORT:
      case NAVI_STATE_INIT: return 0;
      case NAVI_STATE_ICE: res=navi_transport_work_ICE(navi_ctx, now_dt); break;
      case NAVI_STATE_DH_GENERATE: res=navi_transport_work_DH_GENERATE(navi_ctx); break;
      case NAVI_STATE_DH_SEND: res=navi_transport_work_DH_SEND(navi_ctx); break;
      case NAVI_STATE_DH_RECEIVED: res=navi_transport_work_DH_RECEIVED(navi_ctx); break;
      case NAVI_STATE_WAIT_START: res=navi_transport_work_WAIT_START(navi_ctx); break;
      case NAVI_STATE_PROCED_STREAMS: res=navi_transport_work_PROCED_STREAMS(navi_ctx); break;
      case NAVI_STATE_ONLINE: res=navi_transport_work_ONLINE(navi_ctx); break;
      case NAVI_STATE_DISCONNECT: res=navi_transport_work_DISCONNECT(navi_ctx); break;
      case NAVI_STATE_RECONNECT: res=navi_transport_work_RECONNECT(navi_ctx); break;
    }
    state1=navi_get_protocol_state(navi_ctx);
    //DEBUG_printf(navi_ctx,NULL,"********** end work state %d res %d\n",state1, res);
    if (res<0) return res;
    if (state1==state0) return res;
    DEBUG_printf(navi_ctx,NULL,"work again\n");
  }
  return -1;
}

int navi_transport_multicast_ready(struct navi_protocol_ctx_s *navi_ctx) {
#if NAVI_WITH_MULTICAST==1  
  return navi_mcast_available(navi_ctx) && navi_ctx->mcast.rx_active>0;
#else
  return 0;
#endif
}

int navi_send_packet(struct navi_stream_ctx_s *stream_ctx, const int64_t pts, const int64_t dts, const int flags, const void *packet_data, int packet_size) {
  struct navi_protocol_ctx_s *navi_ctx=stream_ctx->navi_ctx;
  struct NaviProtocolDataFrameHeader *head;
  uint8_t *data=alloca(navi_ctx->mss+32); // buffer for data
  uint8_t *fec_data; // buffer for data
  struct NaviProtocolDataFrameHeader *fec_head;
  uint8_t *encrypted_data=alloca(navi_ctx->mss+32); // buffer for encrypted data
  uint8_t *payload;
  const int send_count=(stream_ctx->desc.fec_level && packet_size<=navi_ctx->mss)+1;
  int fec_packet_counter=0;
  uint16_t frame_idx=0;
  uint16_t fec_id_divisor=stream_ctx->desc.fec_level+1;
  const uint8_t *data_ptr=(const uint8_t *)packet_data;
  int res_mcast=0;
  int res_ucast=0;
  int net_send_bytes=0;
  int net_send_bytes_mcast=0;
  const bool send_via_unicast=navi_get_protocol_state(navi_ctx)==NAVI_STATE_ONLINE;
#if NAVI_WITH_MULTICAST==1
  const bool send_via_mcast=navi_mcast_available(navi_ctx) && navi_mcast_can_send_stream(navi_ctx, stream_ctx);
#else
  const bool send_via_mcast=false;
#endif

  if (packet_size<0 || !packet_data) return -1;

  if (!send_via_unicast && !send_via_mcast) return 0;

  navi_add_perfcounter(&stream_ctx->counters.tx_codec_rate, packet_size);

  head=(struct NaviProtocolDataFrameHeader *)data;

  //DEBUG_printf(navi_ctx,stream_ctx,"\n\n***** send packet to %08x size %d pts %ld dts %ld id %u crc %04x\n\n",stream_ctx->stream_id,packet_size,pts,dts,stream_ctx->packet_id+1,crc16(packet_data, 0xFFFF, packet_size));
  //DEBUG_hexdump(packet_data, 32);

  /*
  if (flags&NAVI_DATA_FLAG_DEBUG_DATA_PATH) {
    DEBUG_printf(navi_ctx,stream_ctx,"\ndebug TX packet to %08x size %d pts %ld dts %ld id %u crc %08x\n",stream_ctx->stream_id,packet_size,pts,dts,stream_ctx->packet_id+1,crc32(packet_data,0xFFFFFFFF,packet_size));
    DEBUG_hexdump(packet_data,MIN(packet_size,64));
  }
  */

  head->dts=htobe64(dts);
  head->pts=htobe64(pts);
  head->check=0x5A;
  head->flags=flags&0x0F; // clear internal bits
  head->frame_id=htobe32(++stream_ctx->packet_id);
  head->frame_size=htobe32(packet_size);
  head->frame_idx=0;
  head->frame_count=htobe16((packet_size/navi_ctx->mss)+((packet_size%navi_ctx->mss)>0));

  payload=data+sizeof(struct NaviProtocolDataFrameHeader);

#ifdef DEBUG_DATA_PACKETS
  if (send_via_unicast) {
    struct NaviProtocolStreamDebug debug_packet;
    void *debug_data=NULL;
    int debug_data_len;
    memcpy(&debug_packet.head, head, sizeof(struct NaviProtocolDataFrameHeader));
    debug_packet.head.flags=NAVI_DATA_FLAG_DEBUG_DATA;
    debug_packet.head.frame_size=htobe32(sizeof(struct NaviProtocolStreamDebug)-sizeof(struct NaviProtocolDataFrameHeader));
    debug_packet.data_len=htobe32(packet_size);
    debug_packet.data_crc=htobe32(crc32(packet_data, 0xFFFFFFFF, packet_size));
    //DEBUG_printf(navi_ctx,stream_ctx,"\nDBG stream %08x frame %d data len %d crc %08x\n",stream_ctx->stream_id,stream_ctx->packet_id,packet_size,be32toh(debug_packet.data_crc));
    if (stream_ctx->desc.encryption==NAVI_ENCRYPT_NONE) {
      debug_data=&debug_packet;
      debug_data_len=sizeof(debug_packet);
    } else {
      debug_packet.head.flags|=NAVI_DATA_FLAG_ENCRYPTED_DATA;
      if (!navi_encrypt_with_dh_secret(navi_ctx, &debug_packet, sizeof(struct NaviProtocolStreamDebug), &debug_data_len, encrypted_data)) {
        DEBUG_FAILURE(navi_ctx,stream_ctx,"Can't encrypt debug data stream %p\n",stream_ctx);
        return -1;
      }
      debug_data=encrypted_data;
    }
    if (!debug_data) {
      DEBUG_FAILURE(navi_ctx,stream_ctx,"Can't make debug data stream %p\n",stream_ctx);
       return -1;
    }
    //DEBUG_printf(navi_ctx,stream_ctx,"** debug packet flags %02x\n",debug_packet.head.flags);
    if (navi_send_frame(navi_ctx, NAVICMD_DATA, stream_ctx->stream_id, debug_data, debug_data_len)<0) {
      DEBUG_FAILURE(navi_ctx,stream_ctx, "Can't send data debug frame\n");
      return -1;
    } else {
      /*
      DEBUG_printf(navi_ctx,stream_ctx,"** send debug packet\n");
      DEBUG_hexdump(&debug_packet, sizeof(debug_packet));
      */
    }
  }
#endif

  if (stream_ctx->desc.fec_level && packet_size>navi_ctx->mss) {
    fec_data=alloca(navi_ctx->mss+32);
    memset(fec_data, 0, navi_ctx->mss+32);
    fec_head=(struct NaviProtocolDataFrameHeader *)fec_data;
    fec_data+=sizeof(struct NaviProtocolDataFrameHeader);
    *fec_head=*head;
    fec_head->flags=NAVI_DATA_FLAG_FEC_FRAME;
    if (stream_ctx->desc.encryption!=NAVI_ENCRYPT_NONE) {
      fec_head->flags|=NAVI_DATA_FLAG_ENCRYPTED_DATA;
    }
  } else {
    fec_data=NULL;
    fec_head=NULL;
  }

  while (packet_size>0) {
    int subframe_len=MIN(navi_ctx->mss, packet_size);
    int frame_encryption=stream_ctx->desc.encryption;
    int encrypted_len;

    head->frame_idx=htobe16(frame_idx);
    head->flags&=~NAVI_DATA_FLAG_ENCRYPTED_DATA;

    if (stream_ctx->desc.encryption==NAVI_ENCRYPT_KEYFRAME && (flags&NAVI_DATA_FLAG_KEYFRAME)) frame_encryption=NAVI_ENCRYPT_ALL;

    //DEBUG_printf(navi_ctx,stream_ctx,"-- send frame part %d/%d len %d enc %d:\n",be16toh(head->frame_idx),be16toh(head->frame_count),subframe_len,frame_encryption);
    //DEBUG_hexdump(head,sizeof(struct NaviProtocolDataFrameHeader));

    /*
    if (flags&NAVI_DATA_FLAG_DEBUG_DATA_PATH) {
      DEBUG_printf(navi_ctx,stream_ctx,"frag %d ptr %lu\n",frame_idx,data_ptr-((uint8_t*)packet_data));
      DEBUG_hexdump(data_ptr, MIN(32,subframe_len));
    }
    */

    navi_add_perfcounter(&stream_ctx->counters.tx_rate, subframe_len);
    navi_add_perfcounter(&stream_ctx->counters.tx_bytes, subframe_len);
    navi_inc_perfcounter(&stream_ctx->counters.tx_packets);

    switch (frame_encryption) {
      case NAVI_ENCRYPT_NONE:
        memcpy(payload, data_ptr, subframe_len);

/*
        DEBUG_hexdump(data, MIN(96, subframe_len+sizeof(struct NaviProtocolDataFrameHeader)));
*/
        for (int t=0; t<send_count; ++t) {
          DEBUG_code(0) {
            if (subframe_len<navi_ctx->mss) {
              DEBUG_printf(navi_ctx,stream_ctx,"skip sending len %d\n",subframe_len);
              continue;
            }
          }
          if (send_via_unicast) {
            if (navi_send_frame(navi_ctx, NAVICMD_DATA, stream_ctx->stream_id, data, subframe_len+sizeof(struct NaviProtocolDataFrameHeader))<0) {
              DEBUG_FAILURE(navi_ctx,stream_ctx, "Can't send data frame\n");
              res_ucast=-1;
            } else {
              net_send_bytes+=subframe_len+sizeof(struct NaviProtocolDataFrameHeader)+sizeof(struct NaviProtocolFrameHeader);
            }
          }
          #if NAVI_WITH_MULTICAST==1
          if (send_via_mcast) {
            if (navi_send_mcast_frame(navi_ctx, NAVICMD_DATA, stream_ctx->stream_id, data, subframe_len+sizeof(struct NaviProtocolDataFrameHeader))<0) {
              DEBUG_FAILURE(navi_ctx,stream_ctx, "Can't send data frame\n");
              res_mcast=-1;
            } else {
              net_send_bytes_mcast+=subframe_len+sizeof(struct NaviProtocolDataFrameHeader)+sizeof(struct NaviProtocolFrameHeader);
            }
          }
          #endif
        }
        break;
      case NAVI_ENCRYPT_KEYFRAME:
      case NAVI_ENCRYPT_DATAHEADER:
        if (send_via_unicast) {
          if (!navi_encrypt_with_dh_secret(navi_ctx, head, sizeof(struct NaviProtocolDataFrameHeader), &encrypted_len, encrypted_data)) {
            DEBUG_FAILURE(navi_ctx,stream_ctx,"Can't encrypt data header stream %p\n",stream_ctx);
            return -1;
          }
          memcpy(encrypted_data+encrypted_len, data_ptr, subframe_len);

          if (flags&NAVI_DATA_FLAG_DEBUG_DATA_PATH) {
            DEBUG_hexdump(encrypted_data,MIN(subframe_len+encrypted_len,64));
          }

          for (int t=0; t<send_count; ++t) {
            DEBUG_code(0) {
              if (subframe_len<navi_ctx->mss) {
                DEBUG_printf(navi_ctx,stream_ctx,"skip sending len %d\n",subframe_len);
                continue;
              }
            }
            if (navi_send_frame(navi_ctx, NAVICMD_DATA, stream_ctx->stream_id, encrypted_data, subframe_len+encrypted_len)<0) {
              DEBUG_FAILURE(navi_ctx,stream_ctx, "Can't send data frame\n");
              return -1;
            } else {
              net_send_bytes+=subframe_len+encrypted_len+sizeof(struct NaviProtocolDataFrameHeader)+sizeof(struct NaviProtocolFrameHeader);
            }
          }
        }
        #if NAVI_WITH_MULTICAST==1
        if (send_via_mcast) {
          if (!navi_encrypt_with_mcast_secret(navi_ctx, head, sizeof(struct NaviProtocolDataFrameHeader), &encrypted_len, encrypted_data)) {
            DEBUG_FAILURE(navi_ctx,stream_ctx,"Can't encrypt data header stream %p\n",stream_ctx);
            return -1;
          }
          memcpy(encrypted_data+encrypted_len, data_ptr, subframe_len);

          if (flags&NAVI_DATA_FLAG_DEBUG_DATA_PATH) {
            DEBUG_hexdump(encrypted_data,MIN(subframe_len+encrypted_len,64));
          }

          for (int t=0; t<send_count; ++t) {
            DEBUG_code(0) {
              if (subframe_len<navi_ctx->mss) {
                DEBUG_printf(navi_ctx,stream_ctx,"skip sending len %d\n",subframe_len);
                continue;
              }
            }
            if (navi_send_mcast_frame(navi_ctx, NAVICMD_DATA, stream_ctx->stream_id, encrypted_data, subframe_len+encrypted_len)<0) {
              DEBUG_FAILURE(navi_ctx,stream_ctx, "Can't send data frame\n");
              return -1;
            } else {
              net_send_bytes_mcast+=subframe_len+encrypted_len+sizeof(struct NaviProtocolDataFrameHeader)+sizeof(struct NaviProtocolFrameHeader);
            }
          }
        }
        #endif
        break;
      case NAVI_ENCRYPT_ALL:
        memcpy(payload, data_ptr, subframe_len);
        head->flags|=NAVI_DATA_FLAG_ENCRYPTED_DATA;

        if (send_via_unicast) {
          if (!navi_encrypt_with_dh_secret(navi_ctx, head, sizeof(struct NaviProtocolDataFrameHeader)+subframe_len, &encrypted_len, encrypted_data)) {
            DEBUG_FAILURE(navi_ctx,stream_ctx,"Can't encrypt data and header, stream %p\n",stream_ctx);
            return -1;
          }

          DEBUG_printf(navi_ctx,stream_ctx,"-- NAVI_ENCRYPT_ALL subframe_len %d head %lu encrypted_len %d\n",subframe_len,sizeof(struct NaviProtocolDataFrameHeader),encrypted_len);

          for (int t=0; t<send_count; ++t) {
            DEBUG_code(0) {
              if (subframe_len<navi_ctx->mss) {
                DEBUG_printf(navi_ctx,stream_ctx,"skip sending len %d\n",subframe_len);
                continue;
              }
            }
            if (navi_send_frame(navi_ctx, NAVICMD_DATA, stream_ctx->stream_id, encrypted_data, encrypted_len)<0) {
              DEBUG_FAILURE(navi_ctx,stream_ctx, "Can't send data frame\n");
              return -1;
            } else {
              net_send_bytes+=encrypted_len+sizeof(struct NaviProtocolDataFrameHeader)+sizeof(struct NaviProtocolFrameHeader);
            }
          }
        }
        #if NAVI_WITH_MULTICAST==1
        if (send_via_mcast) {
          if (!navi_encrypt_with_mcast_secret(navi_ctx, head, sizeof(struct NaviProtocolDataFrameHeader)+subframe_len, &encrypted_len, encrypted_data)) {
            DEBUG_FAILURE(navi_ctx,stream_ctx,"Can't encrypt data and header, stream %p\n",stream_ctx);
            return -1;
          }

          DEBUG_printf(navi_ctx,stream_ctx,"-- NAVI_ENCRYPT_ALL subframe_len %d head %lu encrypted_len %d\n",subframe_len,sizeof(struct NaviProtocolDataFrameHeader),encrypted_len);

          for (int t=0; t<send_count; ++t) {
            DEBUG_code(0) {
              if (subframe_len<navi_ctx->mss) {
                DEBUG_printf(navi_ctx,stream_ctx,"skip sending len %d\n",subframe_len);
                continue;
              }
            }
            if (navi_send_mcast_frame(navi_ctx, NAVICMD_DATA, stream_ctx->stream_id, encrypted_data, encrypted_len)<0) {
              DEBUG_FAILURE(navi_ctx,stream_ctx, "Can't send data frame\n");
              return -1;
            } else {
              net_send_bytes_mcast+=encrypted_len+sizeof(struct NaviProtocolDataFrameHeader)+sizeof(struct NaviProtocolFrameHeader);
            }
          }
        }
        #endif
        break;
    }

    if (fec_data) {
      const int fec_group_id=(frame_idx/fec_id_divisor)-1; // группа считается с 0, а тут frame_idx уже "следующий"
      for (int i=0; i<subframe_len; ++i) {
        fec_data[i]^=data_ptr[i];
      }
      if (((frame_idx%fec_id_divisor==0) && (frame_idx>0)) || packet_size==subframe_len) {
        fec_head->frame_idx=htobe16(fec_group_id);
        switch (frame_encryption) {
          case NAVI_ENCRYPT_NONE:
            if (navi_send_frame(navi_ctx, NAVICMD_DATA, stream_ctx->stream_id, fec_head, navi_ctx->mss)<0) {
              DEBUG_FAILURE(navi_ctx,stream_ctx, "Can't send fec frame\n");
              return -1;
            } else {
              net_send_bytes+=navi_ctx->mss+sizeof(struct NaviProtocolFrameHeader);
            }
            break;
          // fec always encrypted
          case NAVI_ENCRYPT_KEYFRAME:
          case NAVI_ENCRYPT_DATAHEADER:
          case NAVI_ENCRYPT_ALL:
            if (send_via_unicast) {
              if (!navi_encrypt_with_dh_secret(navi_ctx, fec_head, navi_ctx->mss, &encrypted_len, encrypted_data)) {
                DEBUG_FAILURE(navi_ctx,stream_ctx,"Can't encrypt data header stream %p\n",stream_ctx);
                return -1;
              }

              if (navi_send_frame(navi_ctx, NAVICMD_DATA, stream_ctx->stream_id, encrypted_data, encrypted_len)<0) {
                DEBUG_FAILURE(navi_ctx,stream_ctx, "Can't send data frame\n");
                return -1;
              } else {
                net_send_bytes+=encrypted_len+sizeof(struct NaviProtocolFrameHeader);
              }
            }

#if NAVI_WITH_MULTICAST==1
            if (send_via_mcast) {
              if (!navi_encrypt_with_mcast_secret(navi_ctx, fec_head, navi_ctx->mss, &encrypted_len, encrypted_data)) {
                DEBUG_FAILURE(navi_ctx,stream_ctx,"Can't encrypt data header stream %p\n",stream_ctx);
                return -1;
              }

              if (navi_send_frame(navi_ctx, NAVICMD_DATA, stream_ctx->stream_id, encrypted_data, encrypted_len)<0) {
                DEBUG_FAILURE(navi_ctx,stream_ctx, "Can't send data frame\n");
                return -1;
              } else {
                net_send_bytes+=encrypted_len+sizeof(struct NaviProtocolFrameHeader);
              }
            }
#endif
            break;
        }
      }
      ++frame_idx;
    }

    data_ptr+=subframe_len;
    packet_size-=subframe_len;
  }

  if (res_mcast==-1 || res_ucast==-1) return -1;

  navi_inc_perfcounter(&stream_ctx->counters.tx_frames);
  navi_add_perfcounter(&stream_ctx->counters.net_tx_rate, net_send_bytes);
  navi_add_perfcounter(&stream_ctx->mcast.counters.net_tx_rate, net_send_bytes_mcast);

  return 0;
}
