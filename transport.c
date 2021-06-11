#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <alloca.h>
#include <errno.h>
#include <endian.h>
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

enum {
  NS_ZERO = 0,
  NS_UPDATE_OFFER,
  NS_GET_CLIENTS,
  NS_UPDATE_ANSWER,
  NS_UPDATE_CANDIDATE,
};

enum {
  DICT_OFFER_CLIENT_NAME=1,
  DICT_OFFER_SDP,
  DICT_GATHERING_DONE,
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
};

TLV_MAKE_DICT(signalling_data_dict, 
  TLV_DICT(DICT_OFFER_CLIENT_NAME, encode_strz, NULL, decode_strz, NULL), // client name
  TLV_DICT(DICT_OFFER_SDP, encode_strz, NULL, decode_strz, NULL),  // offer string
  TLV_DICT(DICT_GATHERING_DONE, encode_u8, NULL, decode_u8, NULL)  // gathering done flag
);

static int encode_stream(va_list ap, uint8_t *dst, void *user_ctx);
static int encode_stream_arr(void *ptr, const int idx, uint8_t *dst, void *user_ctx);
static int decode_stream(uint8_t *src, const int src_len, void *dst, void *user_ctx);

TLV_MAKE_DICT(protocol_data_dict,
  TLV_DICT(DICT_ANOUNCE_STREAM_COUNT, encode_u8, NULL, decode_u8, NULL), // stream count
  TLV_DICT(DICT_ANOUNCE_STREAM, encode_stream, encode_stream_arr, decode_stream, NULL), // stream data
);

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
);

static
int encode_stream(va_list ap, uint8_t *dst, void *user_ctx) {
  struct navi_stream_ctx_s *stream=va_arg(ap, struct navi_stream_ctx_s *);
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
        DICT_STREAM_VIDEO_FPS_NUM, stream->desc.video.fps_num,
        DICT_STREAM_VIDEO_FPS_DEN, stream->desc.video.fps_den,
        DICT_STREAM_DESCRIPTION, stream->desc.description,
        DICT_STREAM_ENCRYPTION, stream->desc.encryption,
        DICT_STREAM_RX_QUEUE_LENGTH, stream->desc.rx_queue_length,
        DICT_STREAM_FEC_LEVEL, stream->desc.fec_level,
        DICT_STREAM_MSS, stream->desc.stream_mss,
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
        TLV_END
      );
    case NAVI_STREAM_DATA:
      return -1;
  }
  return -1;  
}

static
int encode_stream_va(uint8_t *dst, void *user_ctx, ...) {
  va_list ap;
  va_start(ap, user_ctx);
  return encode_stream(ap, dst, user_ctx);
}

static
int encode_stream_arr(void *ptr, const int idx, uint8_t *dst, void *user_ctx) {
  struct navi_stream_ctx_s **stream=(struct navi_stream_ctx_s **)ptr;
  return encode_stream_va(dst, user_ctx, stream[idx]);
}

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
    DICT_STREAM_VIDEO_FPS_NUM, &stream->desc.video.fps_num,
    DICT_STREAM_VIDEO_FPS_DEN, &stream->desc.video.fps_den,
    DICT_STREAM_AUDIO_RATE, &stream->desc.audio.rate,
    DICT_STREAM_AUDIO_CHANNELS, &stream->desc.audio.channels,
    DICT_STREAM_DESCRIPTION, &stream->desc.description,
    DICT_STREAM_ENCRYPTION, &stream->desc.encryption,
    DICT_STREAM_RX_QUEUE_LENGTH, &stream->desc.rx_queue_length,
    DICT_STREAM_FEC_LEVEL, &stream->desc.fec_level,
    DICT_STREAM_MSS, &stream->desc.stream_mss,
    TLV_END
  );

  if (res<0) {
    free(stream);
    DEBUG_FAILURE(navi_ctx,"Can't decode stream info\n");
    return -1;
  }

  for (struct navi_stream_ctx_s *s=navi_ctx->rx_streams; s; s=s->next) {
    if (s->stream_id==stream->stream_id) {
      free(stream);
      return 0;
    }
  }

  stream->navi_ctx=navi_ctx;
  stream->packet_id=0;
  stream->rx_queue_head=0;
  stream->stream_api_id=0;

  stream->rx_queue=malloc(sizeof(struct navi_rx_packet_s *)*stream->desc.rx_queue_length);
  memset(stream->rx_queue, 0, sizeof(struct navi_rx_packet_s *)*stream->desc.rx_queue_length);

  stream->rx_done_queue=NULL;

  pthread_mutex_init(&stream->rx_mtx, NULL);
  pthread_cond_init(&stream->rx_cond, NULL);

  stream->next=navi_ctx->rx_streams;
  navi_ctx->rx_streams=stream;
  ++navi_ctx->rx_stream_count;

  return 0;
}

static
int create_signalling(struct navi_protocol_ctx_s *navi_ctx) {
  struct sockaddr_in A;
  int flags;

  if (navi_ctx->signalling_fd>0) return 0;

  A.sin_family=AF_INET;
  A.sin_port=htons(navi_ctx->config.signalling_port);
  if (inet_aton(navi_ctx->config.signalling_server, &A.sin_addr)==0) {
    DEBUG_FAILURE(navi_ctx, "bad signalling addr '%s'\n",navi_ctx->config.signalling_server);
    return -1;
  }

  navi_ctx->signalling_fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (navi_ctx->signalling_fd==-1) {
    DEBUG_FAILURE(navi_ctx, "can't create signalling socket: %s\n",strerror(errno));
    return -1;
  }

  if (connect(navi_ctx->signalling_fd, (struct sockaddr *)&A, sizeof(A))<0) {
    DEBUG_FAILURE(navi_ctx, "can't connect signalling socket: %s\n",strerror(errno));
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
  
  if (navi_ctx->signalling_fd<=0) return -1;

  res=recv(navi_ctx->signalling_fd, buffer, sizeof(buffer), MSG_NOSIGNAL);
  if (res<=0) return 0;

  if (res<(sizeof(navi_ctx->domain_hash)+sizeof(navi_ctx->client_hash)+1+2)) {
    DEBUG_FAILURE(navi_ctx, "bad reply size %d\n",res);
    return -1;
  }

  crc=crc16(buffer, 0xffff, res-2);
  if (crc!=be16toh(*((uint16_t *)&buffer[res-2]))) {
    DEBUG_FAILURE(navi_ctx, "bad reply crc\n");
    return -1;
  }

  //DEBUG_hexdump(buffer, res);

  if ((buffer[0]&0x80)!=0x80) {
    DEBUG_FAILURE(navi_ctx, "bad reply code %02x\n",buffer[0]);
    return -1;
  }

  if (memcmp(&buffer[1], navi_ctx->domain_hash, sizeof(navi_ctx->domain_hash))) {
    DEBUG_FAILURE(navi_ctx, "bad reply domain\n");
    return -1;
  }

  switch (buffer[0]&0x7f) {
    case NS_GET_CLIENTS:
    case NS_UPDATE_OFFER:
      decrypted_data=navi_decrypt_with_secret(navi_ctx, &buffer[1+sizeof(navi_ctx->domain_hash)+sizeof(navi_ctx->client_hash)], res-1-2-sizeof(navi_ctx->domain_hash)-sizeof(navi_ctx->client_hash), &decrypted_len);
      if (!decrypted_data) {
        DEBUG_FAILURE(navi_ctx, "can't decrypt reply %d\n",buffer[0]&0x7f);
        return -1;
      }
      break;
    case NS_UPDATE_CANDIDATE:
      decrypted_data=navi_decrypt_with_secret(navi_ctx, &buffer[1+sizeof(navi_ctx->domain_hash)+sizeof(navi_ctx->client_hash)+2], res-1-2-sizeof(navi_ctx->domain_hash)-sizeof(navi_ctx->client_hash)-2, &decrypted_len);
      if (!decrypted_data) {
        DEBUG_FAILURE(navi_ctx, "can't decrypt reply %d\n",buffer[0]&0x7f);
        return -1;
      }
      break;
  }

  switch (buffer[0]&0x7f) {
    case NS_GET_CLIENTS: 
      if (decrypted_data) {
        char *name=NULL;
        char *sdp=NULL;
        if (tlv_decode(navi_ctx, decrypted_data, decrypted_len, signalling_data_dict, NULL, DICT_OFFER_CLIENT_NAME, &name, DICT_OFFER_SDP, &sdp, TLV_END)>0) {
          if (navi_ctx->events.client_event) {
            navi_ctx->events.client_event(navi_ctx, *((uint32_t *)&buffer[1+sizeof(navi_ctx->domain_hash)]), name, sdp, navi_ctx->events.client_event_data);
          }
        } else {
          DEBUG_FAILURE(navi_ctx, "Can't decode offer\n");
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
              DEBUG_FAILURE(navi_ctx, "'answer_event' hook reject answer\n");
              free(name);
              free(sdp);
              return -1;
            }
          }
          if (juice_get_state(agent)==JUICE_STATE_DISCONNECTED) {
            if (juice_set_remote_description(agent, sdp)) {
              DEBUG_FAILURE(navi_ctx, "can't set remote answer\n");
              free(name);
              free(sdp);
              return -1;
            }
            juice_gather_candidates(agent);
          }
        } else {
          DEBUG_FAILURE(navi_ctx, "Can't decode offer\n");
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
            DEBUG_printf("%p: add remote candidate %d %s '%s'\n",navi_ctx,candidate_list_version,gathering_done?"DONE":"",sdp?sdp:"NULL");
            if (sdp) {
              juice_add_remote_candidate(agent, sdp);
              navi_ctx->candidate_list_version|=(1<<candidate_list_version);
            }
            if (gathering_done) {
              juice_set_remote_gathering_done(agent);
            }
          } else {
            DEBUG_FAILURE(navi_ctx, "Can't decode offer\n");
          }
          free(sdp);
        }
      }
      break;
  }

  return 0;
}

static
int navi_send_frame(struct navi_protocol_ctx_s *navi_ctx, const int frame_type, const uint32_t stream_id, const void *payload, const int payload_len) {
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

  DEBUG_printf("%p: -- send frame %04x len %d payload %d\n",navi_ctx,be16toh(frame_type),data_len,payload_len);

  return juice_send(agent, data, data_len);
}

static
void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
  struct navi_protocol_ctx_s *navi_ctx=user_ptr;
  navi_ctx->ice_agent_state=state;
  DEBUG_printf("%p: state changed %d %s\n",navi_ctx,state,juice_state_to_string(state));
}

static 
void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
  struct navi_protocol_ctx_s *navi_ctx=user_ptr;
  int candidate_len;
  void *candidate_payload;
  void *encrypted_data;
  int encrypted_len;

  DEBUG_printf("%p: candidate %s\n",navi_ctx,sdp);

  candidate_len=tlv_encode(
    navi_ctx,
    NULL, signalling_data_dict, NULL, 
    DICT_OFFER_SDP, sdp,
    TLV_END
  );

  if (candidate_len<0) {
    DEBUG_FAILURE(navi_ctx, "Can't serialize candidate\n");
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
    DEBUG_FAILURE(navi_ctx, "Can't serialize candidate\n");
    return;
  }

  encrypted_data=navi_encrypt_with_secret(navi_ctx, candidate_payload, candidate_len, &encrypted_len);
  if (!encrypted_data) {
    DEBUG_FAILURE(navi_ctx, "Can't encrypt candidate\n");
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

  DEBUG_printf("%p: gathering done\n",navi_ctx);

  signalling_check(navi_ctx);

  candidate_len=tlv_encode(
    navi_ctx,
    NULL, signalling_data_dict, NULL, 
    DICT_GATHERING_DONE, 1,
    TLV_END
  );

  if (candidate_len<0) {
    DEBUG_FAILURE(navi_ctx, "Can't serialize candidate\n");
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
    DEBUG_FAILURE(navi_ctx, "Can't serialize candidate\n");
    return;
  }

  encrypted_data=navi_encrypt_with_secret(navi_ctx, candidate_payload, candidate_len, &encrypted_len);
  if (!encrypted_data) {
    DEBUG_FAILURE(navi_ctx, "Can't encrypt candidate\n");
    return;
  }

  signalling_send(navi_ctx, NS_UPDATE_CANDIDATE, encrypted_data, encrypted_len);

  free(encrypted_data);
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

static
void free_fragment_queue(struct navi_rx_packet_fragment_s **q) {
  struct navi_rx_packet_fragment_s *list;
  if (*q==NULL) return;
  list=*q;
  *q=NULL;
  while (list) {
    struct navi_rx_packet_fragment_s *next=list->next;
    free(list);
    list=next;
  }
}

static
void proced_rx_queue_packet(struct navi_protocol_ctx_s *navi_ctx, struct navi_stream_ctx_s *stream_ctx, const int final_check, struct navi_rx_packet_s *rx_packet) {
  DEBUG_printf("-- proced queue packet %p\n",rx_packet);
  if (rx_packet->fragments) {
    int lost_packets=0;
    uint32_t packet_len=0;
   
    for (int i=0; i<rx_packet->fragment_count; ++i) {
      //DEBUG_printf("fragments[%d]=%p %d\n",i,rx_packet->fragments[i],rx_packet->fragments[i]?rx_packet->fragments[i]->payload_len:-1);
      if (!rx_packet->fragments[i]) ++lost_packets;
      else packet_len+=rx_packet->fragments[i]->payload_len;
    }

    if (lost_packets) {
      const int max_fec_id=(rx_packet->fragment_count/stream_ctx->desc.fec_level)+1;
      const int fec_id_divisor=stream_ctx->desc.fec_level+1; // to calculate fec group id
      DEBUG_printf("lost packets %d\n",lost_packets);
      if (!final_check) {
        return;
      }
      if (!stream_ctx->desc.fec_level) {
        DEBUG_printf("fec not enabled for %08x\n",stream_ctx->stream_id);
        return;        
      }
      DEBUG_printf("try to recover fec\n");
      struct navi_rx_packet_fragment_s **fec_list=alloca(max_fec_id*sizeof(struct navi_rx_packet_fragment_s *));
      memset(fec_list, 0, max_fec_id*sizeof(struct navi_rx_packet_fragment_s *));
      for (struct navi_rx_packet_fragment_s *p=rx_packet->fec_packets; p; p=p->next) {
        const int fec_group_id=be16toh(p->head.frame_idx);
        if (fec_group_id>max_fec_id) continue;
        fec_list[fec_group_id]=p;
      }
      for (int i=0; i<rx_packet->fragment_count; ++i) {
        if (!rx_packet->fragments[i]) {
          const int fec_group_id=i/fec_id_divisor;
          struct navi_rx_packet_fragment_s *fec_packet=fec_list[fec_group_id];
          struct navi_rx_packet_fragment_s *pkt_fragment; // new fragment 
          struct navi_rx_packet_fragment_s *src_fragment; // where to get head
          if (!fec_packet) {
            DEBUG_FAILURE(navi_ctx,"no fec frame, group %d\n",fec_group_id);
            return;
          }
          ++(fec_packet->refs);
          if (fec_packet->refs>1) {
            DEBUG_FAILURE(navi_ctx,"not enough fec data, group %d\n",fec_group_id);
            return;
          }
          src_fragment=rx_packet->fragments[0];
          if (!src_fragment) {
            src_fragment=rx_packet->fragments[1];
            if (!src_fragment) {
              DEBUG_FAILURE(navi_ctx,"not enough fec data (no src), group %d\n",fec_group_id);
              return;
            }
          }
          pkt_fragment=malloc(sizeof(struct navi_rx_packet_fragment_s)+stream_ctx->desc.stream_mss);
          pkt_fragment->fec=fec_packet;
          pkt_fragment->head=src_fragment->head;
          if (i<rx_packet->fragment_count-1) {
            pkt_fragment->payload_len=stream_ctx->desc.stream_mss;
          } else {
            pkt_fragment->payload_len=rx_packet->packet_size%stream_ctx->desc.stream_mss;
          }
        }
      }
      // try to recover from fec
    } else {
      struct navi_received_frame_s *rx_frame=malloc(sizeof(struct navi_received_frame_s)+rx_packet->packet_size);
      uint8_t *rx_packet_data=rx_frame->data.data;
      uint32_t ptr=0;
      int decrypt_error=0;
      for (int i=0; i<rx_packet->fragment_count; ++i) {
        struct navi_rx_packet_fragment_s *pkt=rx_packet->fragments[i];
        if (pkt->head.flags&NAVI_DATA_FLAG_ENCRYPTED_DATA) {
          int decrypted_len;
          uint8_t *decrypted_data=navi_decrypt_with_dh_secret(navi_ctx, pkt->data, pkt->data_len, &decrypted_len);
          if (!decrypted_data) {
            DEBUG_FAILURE(navi_ctx,"Can't decrypt fragment %d\n",i);
            ++decrypt_error;
            break;
          } else {
            memcpy(&rx_packet_data[ptr], &decrypted_data[sizeof(struct NaviProtocolDataFrameHeader)], decrypted_len-sizeof(struct NaviProtocolDataFrameHeader));
            ptr+=decrypted_len-sizeof(struct NaviProtocolDataFrameHeader);
            free(decrypted_data);
          }
        } else {
          if (pkt->head.flags&NAVI_DATA_FLAG_DEBUG_DATA_PATH) {
            DEBUG_hexdump(&pkt->data[NAVI_AES_ENCRYPTED_LEN(sizeof(struct NaviProtocolDataFrameHeader),NAVI_AES128_TAIL_LEN)], MIN(32,pkt->payload_len));
          }
          memcpy(&rx_packet_data[ptr], &pkt->data[NAVI_AES_ENCRYPTED_LEN(sizeof(struct NaviProtocolDataFrameHeader),NAVI_AES128_TAIL_LEN)], pkt->payload_len);
          ptr+=pkt->payload_len;
        }
      }
      if (!decrypt_error) {
        DEBUG_printf("******* rx packet %p size %d\n",rx_packet_data,rx_packet->packet_size);
        if (rx_packet->fragments[0]->head.flags&NAVI_DATA_FLAG_DEBUG_DATA_PATH) {
          DEBUG_hexdump(rx_packet_data, MIN(64,rx_packet->packet_size));
        }
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
        pthread_cond_signal(&stream_ctx->rx_cond);
        pthread_mutex_unlock(&stream_ctx->rx_mtx);

        pthread_mutex_lock(&navi_ctx->rx_mtx);
        pthread_cond_signal(&navi_ctx->rx_cond);
        pthread_mutex_unlock(&navi_ctx->rx_mtx);

        if (navi_ctx->events.rx_data_event) {
          navi_ctx->events.rx_data_event(navi_ctx, stream_ctx, rx_frame->data.pts, rx_frame->data.dts, rx_frame->data.flags, navi_ctx->events.rx_data_event_data);
        }
      } else {
        DEBUG_printf("decrypt error\n");
        free(rx_frame);
      }
      for (int i=0; i<rx_packet->fragment_count; ++i) {
        free(rx_packet->fragments[i]);
      }
      free(rx_packet->fragments);
      free_fragment_queue(&rx_packet->fec_packets);
      rx_packet->done++;
      DEBUG_printf("done packet %p %u\n",rx_packet,rx_packet->packet_id);
      if (rx_packet==stream_ctx->rx_queue[0]) {
        // remove first done packet
        DEBUG_printf("-- remove first packet %p\n",rx_packet);
        for (int i=1; i<stream_ctx->desc.rx_queue_length; ++i) {
          stream_ctx->rx_queue[i-1]=stream_ctx->rx_queue[i];
        }
        stream_ctx->rx_queue[stream_ctx->desc.rx_queue_length-1]=NULL;
        ++stream_ctx->rx_queue_head;
        free(rx_packet);
        DEBUG_printf("-- now qhead %u\n",stream_ctx->rx_queue_head);
      }
    }
  }
}

static
void proced_rx_queue(struct navi_protocol_ctx_s *navi_ctx, struct navi_stream_ctx_s *stream_ctx, const int final_check) {
  DEBUG_printf("-- proced_rx_queue stream %08x head %u\n",stream_ctx->stream_id,stream_ctx->rx_queue_head);
  for (int i=0; i<stream_ctx->desc.rx_queue_length; ++i) {
    struct navi_rx_packet_s *rx_packet=stream_ctx->rx_queue[i];
    if (!rx_packet) continue;

    DEBUG_printf("-- proced rx queue %d %p id %u done %d\n",i,rx_packet,rx_packet->packet_id,rx_packet->done);

    if (rx_packet->done && final_check) {
      free(rx_packet);
      stream_ctx->rx_queue[i]=NULL;
      continue;
    }

    proced_rx_queue_packet(navi_ctx, stream_ctx, final_check, rx_packet);

    if (final_check) {
      for (int i=0; i<rx_packet->fragment_count; ++i) {
        free(rx_packet->fragments[i]);
      }
      free(rx_packet->fragments);
      free_fragment_queue(&rx_packet->fec_packets);
      free(rx_packet);
      stream_ctx->rx_queue[i]=NULL;
    }
  }
}

static
void proced_rx_fragment(struct navi_protocol_ctx_s *navi_ctx, struct NaviProtocolFrameHeader *head, struct NaviProtocolDataFrameHeader *fragment_head) {
  struct navi_stream_ctx_s *stream_ctx;
  const uint32_t stream_id=be32toh(head->streamId);
  struct navi_rx_packet_s *rx_packet;
  uint32_t rx_packet_id;
  const int payload_len=be16toh(head->payloadLength);
  struct navi_rx_packet_fragment_s *pkt_fragment;
  uint32_t fragment_idx;

  stream_ctx=get_stream_by_id_in_queue(stream_id, navi_ctx->rx_streams);
  if (!stream_ctx) {
    DEBUG_FAILURE(navi_ctx,"no rx stream found %08x\n",stream_id);
    return;
  }

  rx_packet_id=be32toh(fragment_head->frame_id);
  fragment_idx=be16toh(fragment_head->frame_idx);

  DEBUG_printf("-- rx to stream %p id %u frame idx %d/%d size %d frag size %d flags %d\n",stream_ctx,rx_packet_id,fragment_idx,be16toh(fragment_head->frame_count),be32toh(fragment_head->frame_size),payload_len,fragment_head->flags);

  if (rx_packet_id<stream_ctx->rx_queue_head) {
    DEBUG_FAILURE(navi_ctx, "rx packet id %08x less than head %08x\n",rx_packet_id,stream_ctx->rx_queue_head);
    return;
  }

  DEBUG_printf("-- rx_packet_id %u rx_queue_head %u length %d\n",rx_packet_id,stream_ctx->rx_queue_head,stream_ctx->desc.rx_queue_length);

  if (fragment_head->flags&NAVI_DATA_FLAG_DEBUG_DATA_PATH) {
    DEBUG_hexdump(head->payload,MIN(80,payload_len));
  }

  // frame out of order
  if (rx_packet_id>=(stream_ctx->rx_queue_head+stream_ctx->desc.rx_queue_length)) {
    proced_rx_queue(navi_ctx, stream_ctx, 1);
    DEBUG_printf("-- outoforder packet %u head %u max %u\n",rx_packet_id,stream_ctx->rx_queue_head,stream_ctx->rx_queue_head+stream_ctx->desc.rx_queue_length);
    stream_ctx->rx_queue_head=rx_packet_id;
  }
  DEBUG_printf("-- get packet %d from qlist %p head %d idx %d flags %d\n",rx_packet_id,stream_ctx->rx_queue,stream_ctx->rx_queue_head,rx_packet_id-stream_ctx->rx_queue_head,fragment_head->flags);
  rx_packet=stream_ctx->rx_queue[rx_packet_id-stream_ctx->rx_queue_head];
  DEBUG_printf("-- rx packet %p\n",rx_packet);
  if (!rx_packet) {
    rx_packet=(struct navi_rx_packet_s *)malloc(sizeof(struct navi_rx_packet_s));
    rx_packet->packet_id=rx_packet_id;
    rx_packet->done=0;
    rx_packet->packet_size=be32toh(fragment_head->frame_size);
    rx_packet->fragment_count=be16toh(fragment_head->frame_count);
    rx_packet->fragments=malloc(sizeof(struct navi_rx_packet_fragment_s *)*rx_packet->fragment_count);
    memset(rx_packet->fragments, 0, sizeof(struct navi_rx_packet_fragment_s *)*rx_packet->fragment_count);
    rx_packet->fec_packets=NULL;
    stream_ctx->rx_queue[rx_packet_id-stream_ctx->rx_queue_head]=rx_packet;
    DEBUG_printf("-- new rx packet %p\n",rx_packet);
  } else {
    if (rx_packet->done) {
      return; // duplicate packet
    }
  }

  pkt_fragment=malloc(sizeof(struct navi_rx_packet_fragment_s)+payload_len);
  DEBUG_printf("*** fragment %p idx %d len %d\n",pkt_fragment,fragment_idx,payload_len); fflush(stdout);
  pkt_fragment->head=*fragment_head;
  pkt_fragment->data_len=payload_len;
  pkt_fragment->refs=0;
  pkt_fragment->fec=NULL;
  memcpy(pkt_fragment->data, head->payload, payload_len);

  if (fragment_idx==rx_packet->fragment_count-1) {
    pkt_fragment->payload_len=rx_packet->packet_size%stream_ctx->desc.stream_mss;
  } else {
    pkt_fragment->payload_len=stream_ctx->desc.stream_mss;
  }

  if (fragment_head->flags&NAVI_DATA_FLAG_FEC_FRAME) {
    pkt_fragment->next=rx_packet->fec_packets;
    rx_packet->fec_packets=pkt_fragment;
    pkt_fragment=NULL; // mark it enqueued
  } else {
    if (fragment_idx<rx_packet->fragment_count) {
      if (!rx_packet->fragments[fragment_idx]) {
        rx_packet->fragments[fragment_idx]=pkt_fragment;
      } else {
        // duplicate packet
        free(pkt_fragment);
      }
      pkt_fragment=NULL; // mark it enqueued
    }
  }

  if (pkt_fragment) {
    free(pkt_fragment);
    DEBUG_FAILURE(navi_ctx,"fragment not processed\n");
  }

  proced_rx_queue_packet(navi_ctx, stream_ctx, 0, rx_packet);
}

static
void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
  struct navi_protocol_ctx_s *navi_ctx=user_ptr;
  struct NaviProtocolFrameHeader *head=(struct NaviProtocolFrameHeader *)data;
  struct NaviProtocolFrameHeader head_copy;
  uint16_t calculated_crc;
  int payload_len;
  
  DEBUG_printf("%p: RX data %p %lu state %d agent %p %d head type %04x stream %08x\n",navi_ctx,data,size,navi_get_protocol_state(navi_ctx),agent,juice_get_state(agent),be16toh(head->frameType),be32toh(head->streamId));
  //DEBUG_hexdump(data,size);

  if (!navi_check_rx_frame_size(size,head)) {
    DEBUG_FAILURE(navi_ctx,"Bad frame size %lu (need %d)\n",size,navi_protocol_frame_size(head));
    return;
  }

  head_copy=*head;
  head_copy.crc=0xFFFF;
  
  payload_len=be16toh(head->payloadLength);

  calculated_crc=crc16(head->payload, crc16(&head_copy, head_copy.crc, sizeof(head_copy)),payload_len);

  if (be16toh(head->crc)!=calculated_crc) {
    DEBUG_FAILURE(navi_ctx, "bad crc %04x calc %04x\n",be16toh(head->crc),calculated_crc);
    return;
  }

  if (head->frameType==NAVICMD_START) {
    if (NAVI_REQUIRE_PROTOCOL_STATE_LT(navi_ctx,NAVI_STATE_DH_SEND)) {
      struct NaviProtocolStartFrame *start=(struct NaviProtocolStartFrame *)head->payload;
      DEBUG_printf("%p: start frame, state %d\n",navi_ctx,navi_get_protocol_state(navi_ctx));
      //DEBUG_hexdump(start, payload_len);

      if (!navi_wait_for_state(navi_ctx, NAVI_STATE_DH_SEND, 1500)) {
        DEBUG_FAILURE(navi_ctx,"bad state for START frame\n");
        return;
      }

      if (payload_len!=(sizeof(struct NaviProtocolStartFrame)+navi_ctx->local_pkey_len)) {
        DEBUG_FAILURE(navi_ctx,"bad start payload length %d!=%ld\n",payload_len,(sizeof(struct NaviProtocolStartFrame)+navi_ctx->local_pkey_len));
        return;
      }
      if (memcmp(start->domain, navi_ctx->domain_hash, sizeof(navi_ctx->domain_hash))) {
        DEBUG_FAILURE(navi_ctx,"bad domain\n");
        return;
      }
      // openssl can't work good in multithred environment 
      // so copy public key and proced it in main thread
      NAVI_LOCK_CTX(navi_ctx);
      memcpy(navi_ctx->remote_pkey_data, start->public_key, navi_ctx->local_pkey_len);
      navi_set_protocol_state(navi_ctx, NAVI_STATE_DH_RECEIVED, 0);
      NAVI_UNLOCK_CTX(navi_ctx);
    }
  } else 
  if (head->frameType==NAVICMD_STREAMS) {
    if (navi_ctx->rx_streams_encrypted_len!=payload_len) {
      free(navi_ctx->rx_streams_encrypted);
      navi_ctx->rx_streams_encrypted=NULL;
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
    DEBUG_printf("data frame stream %08x\n",head->streamId);
    if (payload_len>0) {
      int data_len;
      void *data=navi_decrypt_with_dh_secret(navi_ctx, head->payload, sizeof(struct NaviProtocolDataFrameHeader)+NAVI_AES128_TAIL_LEN, &data_len);
      if (data && data_len>=sizeof(struct NaviProtocolDataFrameHeader)) {
        proced_rx_fragment(navi_ctx, head, (struct NaviProtocolDataFrameHeader*)data);
      } else {
        DEBUG_FAILURE(navi_ctx,"Can't decrypt frame fragment header %p %d\n",data,data_len);
      }
      free(data);
    }
  }
}

int navi_transport_create(struct navi_protocol_ctx_s *navi_ctx) {
  juice_config_t config;
  juice_agent_t *agent;
  int res=-1;

  if (navi_ctx->ice_agent) return 0;

  if (create_signalling(navi_ctx)<0) {
    DEBUG_FAILURE(navi_ctx, "Can't create signaling connection\n");
    return -1;
  }

#ifdef WITH_DEBUG
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

    DEBUG_printf("turn '%s'\n",turn_server);
    if (sscanf(turn_server, "%m[^:]:%m[^@]@%m[^:]:%d%n",&login,&password,&host,&port,&len)!=4) break;
    DEBUG_printf("'%s' '%s' '%s' %d %d\n",login,password,host,port,len);

    memset(&turn, 0, sizeof(juice_turn_server_t));
    turn.host=host;
    turn.port=port;
    turn.username=login;
    turn.password=password;
    turn_list=realloc(config.turn_servers, (config.turn_servers_count+1)*sizeof(juice_turn_server_t));
    if (!turn_list) {
      free(config.turn_servers);
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

  if (!agent) return -1;

  if (!NAVI_REQUIRE_PROTOCOL_STATE_LT(navi_ctx,NAVI_STATE_DH_GENERATE)) return -1;

  if (navi_ctx->offer_data) {
    return signalling_send(navi_ctx, NS_UPDATE_OFFER, navi_ctx->offer_data, navi_ctx->offer_data_len);
  }

	juice_get_local_description(agent, sdp, JUICE_MAX_SDP_STRING_LEN);

  DEBUG_printf("send offer sdp '%s'\n",sdp);

  offer_len=tlv_encode(
    navi_ctx,
    NULL, signalling_data_dict, NULL, 
    DICT_OFFER_CLIENT_NAME, navi_ctx->config.client_name,
    DICT_OFFER_SDP, sdp,
    TLV_END
  );

  if (offer_len<0) {
    DEBUG_FAILURE(navi_ctx, "Can't serialize offer\n");
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
    DEBUG_FAILURE(navi_ctx, "Can't serialize offer\n");
    return -1;
  }

  navi_ctx->offer_data=navi_encrypt_with_secret(navi_ctx, offer_payload, offer_len, &navi_ctx->offer_data_len);
  if (!navi_ctx->offer_data) {
    DEBUG_FAILURE(navi_ctx, "Can't encrypt offer\n");
    return -1;
  }

  navi_set_protocol_state(navi_ctx, NAVI_STATE_ICE, 1);

  return signalling_send(navi_ctx, NS_UPDATE_OFFER, navi_ctx->offer_data, navi_ctx->offer_data_len);
}

int navi_transport_get_clients(struct navi_protocol_ctx_s *navi_ctx) {
  int res;

  if (!NAVI_REQUIRE_PROTOCOL_STATE_EQ(navi_ctx,NAVI_STATE_INIT)) return -1;

  res=signalling_send(navi_ctx, NS_GET_CLIENTS, "", 0);
  if (res<0) {
    DEBUG_FAILURE(navi_ctx, "Can't send request\n");
    return -1;
  }

  sleep(1);

  signalling_check(navi_ctx);
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

  if (!agent) return -1;

  state=juice_get_state(agent);

  if (state!=JUICE_STATE_DISCONNECTED) {
    DEBUG_FAILURE(navi_ctx, "bad ice transport state %d\n",state);
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
    DEBUG_FAILURE(navi_ctx, "Can't serialize answer\n");
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
    DEBUG_FAILURE(navi_ctx, "Can't serialize answer\n");
    return -1;
  }

  encrypted_data=navi_encrypt_with_secret(navi_ctx, answer_payload, answer_len, &encrypted_len);
  if (!encrypted_data) {
    DEBUG_FAILURE(navi_ctx, "Can't encrypt offer\n");
    return -1;
  }

  res=signalling_send(navi_ctx, NS_UPDATE_ANSWER, encrypted_data, encrypted_len);

  free(encrypted_data);

  if (res<0) return -1;

  if (juice_set_remote_description(agent, sdp)) {
    DEBUG_FAILURE(navi_ctx, "can't set remote description\n");
    return -1;
  }

  juice_gather_candidates(agent);

  navi_set_protocol_state(navi_ctx, NAVI_STATE_ICE, 1);

  return 0;
}

static 
int navi_transport_work_ICE(struct navi_protocol_ctx_s *navi_ctx) {
  juice_agent_t *agent=navi_ctx->ice_agent;

  signalling_check(navi_ctx);

  if (navi_ctx->ice_agent_state>=JUICE_STATE_CONNECTED) {
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
  DEBUG_printf("%p: --- send DH\n",navi_ctx);
  return navi_send_frame(navi_ctx, NAVICMD_START, NAVI_INFO_STREAM, start, start_len);
}

static 
int navi_transport_work_DH_GENERATE(struct navi_protocol_ctx_s *navi_ctx) {
  DEBUG_printf("%p: --- generate keys\n",navi_ctx);
  if (navi_generate_keys(navi_ctx)<0) return -1;
  navi_set_protocol_state(navi_ctx, NAVI_STATE_DH_SEND, 1);
  // send DH right after creating, not in next loop
  return navi_transport_work_DH_SEND(navi_ctx);
}

static 
int navi_transport_work_DH_RECEIVED(struct navi_protocol_ctx_s *navi_ctx) {
  if (navi_generate_secret(navi_ctx)<0) {
    DEBUG_FAILURE(navi_ctx,"Can't create secret\n");
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
    DEBUG_printf("%p: WAIT START streams frame\n",navi_ctx);
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
    DEBUG_FAILURE(navi_ctx, "can't seralize tx streams\n");
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
    DEBUG_FAILURE(navi_ctx, "can't seralize tx streams\n");
    free(streams_data);
    return -1;
  }

  DEBUG_printf("-- send streams %d %d\n",data_len,ptr);
  //DEBUG_hexdump(streams_data, data_len);

  data=navi_encrypt_with_dh_secret(navi_ctx, streams_data, data_len, &data_len, NULL);
  free(streams_data);
  if (!data) {
    DEBUG_FAILURE(navi_ctx, "can't encrypt tx streams\n");
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
  return 0;
}

static 
int navi_transport_work_ONLINE(struct navi_protocol_ctx_s *navi_ctx) {
  return 0;
}

int navi_transport_work(struct navi_protocol_ctx_s *navi_ctx) {
  for(;;) {
    enum navi_protocol_state_e state1;
    enum navi_protocol_state_e state0=navi_get_protocol_state(navi_ctx);
    int res=-1;
    DEBUG_printf("%p: ********** work state %d\n",navi_ctx, state0);
    switch (navi_get_protocol_state(navi_ctx)) {
      case NAVI_STATE_INIT: return 0;
      case NAVI_STATE_ICE: res=navi_transport_work_ICE(navi_ctx); break;
      case NAVI_STATE_DH_GENERATE: res=navi_transport_work_DH_GENERATE(navi_ctx); break;
      case NAVI_STATE_DH_SEND: res=navi_transport_work_DH_SEND(navi_ctx); break;
      case NAVI_STATE_DH_RECEIVED: res=navi_transport_work_DH_RECEIVED(navi_ctx); break;
      case NAVI_STATE_WAIT_START: res=navi_transport_work_WAIT_START(navi_ctx); break;
      case NAVI_STATE_PROCED_STREAMS: res=navi_transport_work_PROCED_STREAMS(navi_ctx); break;
      case NAVI_STATE_ONLINE: res=navi_transport_work_ONLINE(navi_ctx); break;
    }
    state1=navi_get_protocol_state(navi_ctx);
    DEBUG_printf("%p: ********** end work state %d res %d\n",navi_ctx, state1, res);
    if (res<0) return res;
    if (state1==state0) return res;
    DEBUG_printf("%p: work again\n",navi_ctx);
  }
  return -1;
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
  head=(struct NaviProtocolDataFrameHeader *)data;

  DEBUG_printf("\n\n***** send packet to %08x size %d pts %ld dts %ld id %u\n\n",stream_ctx->stream_id,packet_size,pts,dts,stream_ctx->packet_id+1);
  //DEBUG_hexdump(packet_data, packet_size);
  if (flags&NAVI_DATA_FLAG_DEBUG_DATA_PATH) {
    DEBUG_printf("\ndebug TX packet to %08x size %d pts %ld dts %ld id %u crc %08x\n",stream_ctx->stream_id,packet_size,pts,dts,stream_ctx->packet_id+1,crc32(packet_data,0xFFFFFFFF,packet_size));
    DEBUG_hexdump(packet_data,MIN(packet_size,64));
  }

  head->dts=htobe64(dts);
  head->pts=htobe64(pts);
  head->check=0x5A;
  head->flags=flags&0x0F; // clear internal bits
  head->frame_id=htobe32(++stream_ctx->packet_id);
  head->frame_size=htobe32(packet_size);
  head->frame_idx=0;
  head->frame_count=htobe16((packet_size/navi_ctx->mss)+((packet_size%navi_ctx->mss)>0));

  payload=data+sizeof(struct NaviProtocolDataFrameHeader);

  if (stream_ctx->desc.fec_level && packet_size>navi_ctx->mss) {
    fec_data=alloca(navi_ctx->mss+32);
    memset(fec_data, 0, navi_ctx->mss+32);
    fec_head=(struct NaviProtocolDataFrameHeader *)fec_data;
    fec_data+=sizeof(struct NaviProtocolDataFrameHeader);
    *fec_head=*head;
    fec_head->flags=NAVI_DATA_FLAG_FEC_FRAME;
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

    DEBUG_printf("-- send frame part %d/%d len %d enc %d:\n",be16toh(head->frame_idx),be16toh(head->frame_count),subframe_len,frame_encryption);
    //DEBUG_hexdump(head,sizeof(struct NaviProtocolDataFrameHeader));

    switch (frame_encryption) {
      case NAVI_ENCRYPT_NONE:
        memcpy(payload, data_ptr, subframe_len);

        for (int t=0; t<send_count; ++t) {
          if (navi_send_frame(navi_ctx, NAVICMD_DATA, stream_ctx->stream_id, data, subframe_len+sizeof(struct NaviProtocolDataFrameHeader))<0) {
            DEBUG_FAILURE(navi_ctx, "Can't send data frame\n");
            return -1;
          }
        }
        break;
      case NAVI_ENCRYPT_KEYFRAME:
      case NAVI_ENCRYPT_DATAHEADER:
        if (!navi_encrypt_with_dh_secret(navi_ctx, head, sizeof(struct NaviProtocolDataFrameHeader), &encrypted_len, encrypted_data)) {
          DEBUG_FAILURE(navi_ctx,"Can't encrypt data header stream %p\n",stream_ctx);
          return -1;
        }
        memcpy(encrypted_data+encrypted_len, data_ptr, subframe_len);
        DEBUG_printf("------ len %d %lu\n",encrypted_len,sizeof(struct NaviProtocolDataFrameHeader));
        if (flags&NAVI_DATA_FLAG_DEBUG_DATA_PATH) {
          DEBUG_hexdump(encrypted_data,MIN(subframe_len+encrypted_len,64));
        }

        for (int t=0; t<send_count; ++t) {
          if (navi_send_frame(navi_ctx, NAVICMD_DATA, stream_ctx->stream_id, encrypted_data, subframe_len+encrypted_len)<0) {
            DEBUG_FAILURE(navi_ctx, "Can't send data frame\n");
            return -1;
          }
        }
        break;
      case NAVI_ENCRYPT_ALL:
        memcpy(payload, data_ptr, subframe_len);
        head->flags|=NAVI_DATA_FLAG_ENCRYPTED_DATA;

        if (!navi_encrypt_with_dh_secret(navi_ctx, head, sizeof(struct NaviProtocolDataFrameHeader)+subframe_len, &encrypted_len, encrypted_data)) {
          DEBUG_FAILURE(navi_ctx,"Can't encrypt data and header, stream %p\n",stream_ctx);
          return -1;
        }

        DEBUG_printf("-- NAVI_ENCRYPT_ALL subframe_len %d head %lu encrypted_len %d\n",subframe_len,sizeof(struct NaviProtocolDataFrameHeader),encrypted_len);

        for (int t=0; t<send_count; ++t) {
          if (navi_send_frame(navi_ctx, NAVICMD_DATA, stream_ctx->stream_id, encrypted_data, encrypted_len)<0) {
            DEBUG_FAILURE(navi_ctx, "Can't send data frame\n");
            return -1;
          }
        }
        break;
    }

    if (fec_data) {
      const int fec_group_id=frame_idx/fec_id_divisor;
      for (int i=0; i<subframe_len; ++i) {
        fec_data[i]^=data_ptr[i];
      }
      if (((frame_idx%fec_id_divisor==0) && (frame_idx>0)) || packet_size==subframe_len) {
        fec_head->frame_idx=htobe16(fec_group_id);
        DEBUG_printf("-- send fec packet %d\n",fec_group_id);
        switch (frame_encryption) {
          case NAVI_ENCRYPT_NONE:
            if (navi_send_frame(navi_ctx, NAVICMD_DATA, stream_ctx->stream_id, fec_head, navi_ctx->mss)<0) {
              DEBUG_FAILURE(navi_ctx, "Can't send fec frame\n");
              return -1;
            }
            break;
          case NAVI_ENCRYPT_KEYFRAME:
          case NAVI_ENCRYPT_DATAHEADER:
            if (!navi_encrypt_with_dh_secret(navi_ctx, fec_head, sizeof(struct NaviProtocolDataFrameHeader), &encrypted_len, encrypted_data)) {
              DEBUG_FAILURE(navi_ctx,"Can't encrypt fec header stream %p\n",stream_ctx);
              return -1;
            }
            memcpy(encrypted_data+encrypted_len, fec_data, navi_ctx->mss-sizeof(struct NaviProtocolDataFrameHeader));

            if (navi_send_frame(navi_ctx, NAVICMD_DATA, stream_ctx->stream_id, encrypted_data, navi_ctx->mss-sizeof(struct NaviProtocolDataFrameHeader)+encrypted_len)<0) {
              DEBUG_FAILURE(navi_ctx, "Can't send fec frame\n");
              return -1;
            }
            break;
          case NAVI_ENCRYPT_ALL:
            if (!navi_encrypt_with_dh_secret(navi_ctx, fec_head, navi_ctx->mss, &encrypted_len, encrypted_data)) {
              DEBUG_FAILURE(navi_ctx,"Can't encrypt data header stream %p\n",stream_ctx);
              return -1;
            }

            if (navi_send_frame(navi_ctx, NAVICMD_DATA, stream_ctx->stream_id, encrypted_data, encrypted_len)<0) {
              DEBUG_FAILURE(navi_ctx, "Can't send data frame\n");
              return -1;
            }
            break;
        }
      }
      ++frame_idx;
    }

    data_ptr+=subframe_len;
    packet_size-=subframe_len;
  }

  return 0;
}
