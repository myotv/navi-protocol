static char *discovery_group_addr="224.1.0.1";
static char *report_group_addr="224.1.0.1";
static bool discovery_group_addr_set=false;
static bool report_group_addr_set=false;
static int mcast_discovery_fd=0;
static int mcast_report_send_fd=0;
static struct sockaddr_in mcast_announce_addr;
static struct sockaddr_in mcast_report_addr;

#define NAVI_MCAST_BUFFER_SIZE 1500
#define NAVI_MCAST_MEMBERSHIP_TIMEOUT 2000

static void navi_start_mcast_receive(struct navi_protocol_ctx_s *navi_ctx, const struct in_addr group_addr, const int udp_port, struct navi_protocol_stream_list_s *streams);
static void navi_send_mcast_report(struct navi_protocol_ctx_s *navi_ctx, const uint64_t now_dt);

static inline
bool navi_mcast_available(struct navi_protocol_ctx_s *navi_ctx) {
  return navi_ctx->mcast.enable && navi_ctx->mcast.mcast_socket;
}

void navi_transport_set_discovery_group(const char *group_addr) {
  if (discovery_group_addr && group_addr && !strcmp(discovery_group_addr,group_addr)) return;
  
  if (discovery_group_addr_set) free(discovery_group_addr);
  discovery_group_addr_set=true;

  if (group_addr) discovery_group_addr=strdup(group_addr);
  else discovery_group_addr=NULL;

  if (mcast_discovery_fd && !discovery_group_addr) {
    close(mcast_discovery_fd);
    mcast_discovery_fd=0;
  }
}

void navi_transport_set_report_group(const char *group_addr) {
  if (report_group_addr && group_addr && !strcmp(report_group_addr,group_addr)) return;
  
  if (report_group_addr_set) free(report_group_addr);
  report_group_addr_set=true;

  if (group_addr) report_group_addr=strdup(group_addr);
  else report_group_addr=NULL;

  if (mcast_report_send_fd && !report_group_addr) {
    close(mcast_report_send_fd);
    mcast_report_send_fd=0;
  }
}

int navi_transport_set_multicast_discovery(const int enable) {
  struct ip_mreqn mreq;

  if (mcast_discovery_fd) {
    close(mcast_discovery_fd);
    mcast_discovery_fd=0;
  }

  if (!enable) return 0;

  mcast_discovery_fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (mcast_discovery_fd<0) {
    mcast_discovery_fd=0;
    DEBUG_FAILURE_A("Can't create multicast socket, error %s",strerror(errno));
    return -1;
  }

  static const int yes=1;
  if (setsockopt(mcast_discovery_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))<0) {
    DEBUG_FAILURE_A("Can't set SO_REUSEADDR, error %s",strerror(errno));
    close(mcast_discovery_fd);
    mcast_discovery_fd=0;
    return -1;
  }

  static const int multicastTTL=20;
  if (setsockopt(mcast_discovery_fd, IPPROTO_IP, IP_MULTICAST_TTL, &multicastTTL, sizeof(multicastTTL))<0) {
    DEBUG_FAILURE_A("Can't set IP_MULTICAST_TTL, error %s",strerror(errno));
    close(mcast_discovery_fd);
    mcast_discovery_fd=0;
    return -1;
  }

/*
  if (setsockopt(mcast_discovery_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &yes, sizeof (yes))<0) {
    DEBUG_FAILURE_A("Can't set IP_MULTICAST_LOOP, error %s",strerror(errno));
    close(mcast_discovery_fd);
    mcast_discovery_fd=0;
    return -1;
  }
*/

  mcast_announce_addr.sin_family=AF_INET;
  mcast_announce_addr.sin_port=htons(NAVI_MULTICAST_DISCOVERY_PORT);
  mcast_announce_addr.sin_addr.s_addr=inet_addr(discovery_group_addr);

  if (bind(mcast_discovery_fd, (struct sockaddr *)&mcast_announce_addr, sizeof(mcast_announce_addr))<0) {
    DEBUG_FAILURE_A("Can't bind discovery addr, error %s",strerror(errno));
    close(mcast_discovery_fd);
    mcast_discovery_fd=0;
    return -1;
  }

  mreq.imr_multiaddr=mcast_announce_addr.sin_addr;
  mreq.imr_address.s_addr=htonl(INADDR_ANY);
  mreq.imr_ifindex=0;

  // ignore result
  setsockopt(mcast_discovery_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

  DEBUG_printf_a("multicast announce/discovery fd %d\n",mcast_discovery_fd);

  return 0;
}

static
void navi_check_mcast_discovery(struct navi_protocol_ctx_s *navi_ctx, const uint64_t now_dt) {
  uint8_t buffer[NAVI_MCAST_BUFFER_SIZE];

  if (!mcast_discovery_fd) return;

  if (navi_ctx->mcast.membership_check>now_dt) navi_ctx->mcast.membership_check=0;

  if (now_dt-navi_ctx->mcast.membership_check>NAVI_MCAST_MEMBERSHIP_TIMEOUT) {
    struct ip_mreq mreq;
    navi_ctx->mcast.membership_check=now_dt;

    mreq.imr_multiaddr=mcast_announce_addr.sin_addr;
    mreq.imr_interface.s_addr=htonl(INADDR_ANY);

    // don't care about result
    setsockopt(mcast_discovery_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
  
    if (navi_ctx->mcast.mcast_socket) {
      mreq.imr_multiaddr=navi_ctx->mcast.group_addr.sin_addr;
      setsockopt(mcast_discovery_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    }
  }

  for(;;) {
    ssize_t res;
    struct sockaddr_in pkt_addr;
    socklen_t pkt_addr_len=sizeof(pkt_addr);
    uint8_t *decrypted_data;
    int decrypted_len;
    uint16_t *crc_ptr;
    uint16_t rx_crc;
    char *domain=NULL;
    char *client_name=NULL;
    uint8_t stream_count;
    struct in_addr group_addr;
    uint16_t udp_port;
    struct navi_protocol_stream_list_s *streams=NULL;

    res=recvfrom(mcast_discovery_fd, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&pkt_addr, &pkt_addr_len);
    if (res<(ssize_t)sizeof(navi_ctx->mcast.local_iv)) return;

    // loopback check
    if (memcmp(buffer, navi_ctx->mcast.local_iv, sizeof(navi_ctx->mcast.local_iv))==0) {
      return;
    }

    decrypted_data=(uint8_t*)navi_decrypt_with_mcast_secret(navi_ctx, buffer, res, &decrypted_len);
    if (!decrypted_data) return;
    if (decrypted_len<8) {
      NAVI_free((void *)decrypted_data);
      return;
    }

    //DEBUG_hexdump(decrypted_data, decrypted_len);

    crc_ptr=(uint16_t *)(decrypted_data+decrypted_len-sizeof(uint16_t));
    rx_crc=htobe16(crc16(decrypted_data, 0xFFFF, decrypted_len-sizeof(uint16_t)));
    if (*crc_ptr!=rx_crc) {
      DEBUG_FAILURE(navi_ctx, NULL, "bad mcast announce crc\n");
      NAVI_free((void *)decrypted_data);
      continue;
    }

    res=tlv_decode(
      navi_ctx,
      decrypted_data,
      decrypted_len-sizeof(uint16_t),
      multicast_announce_dict,
      navi_ctx,
      DICT_MCAST_DOMAIN, &domain,
      DICT_MCAST_CLIENT_NAME, &client_name,
      DICT_MCAST_STREAM_COUNT, &stream_count,
      DICT_MCAST_GROUP, &group_addr.s_addr,
      DICT_MCAST_PORT, &udp_port,
      DICT_MCAST_STREAMS, &streams,
      TLV_END
    );

    if (!navi_ctx->mcast.mcast_socket) {
      DEBUG_printf(navi_ctx,NULL,"mcast announce: res %ld name %s domain %s streams %d\n",res,client_name,domain,stream_count);
    }
    if (navi_ctx->events.client_event) {
      char *sdp_data;
      char *udp_addr=inet_ntoa(group_addr);
      if (asprintf(&sdp_data,"v=0\r\no=%s@%s\r\nu=udp://@%s:%d\r\nc=IN IP4 %s:%d\r\n",client_name,domain,udp_addr,ntohs(udp_port),udp_addr,ntohs(udp_port))<0) {
        sdp_data=NULL;
      }
  
      navi_ctx->events.client_event(navi_ctx, 0, domain, client_name, sdp_data, 0x00, 1, stream_count, streams, navi_ctx->events.client_event_data);
      NAVI_free(sdp_data);
    }

    if (navi_get_protocol_state(navi_ctx)<NAVI_STATE_DH_RECEIVED) {
      if (navi_ctx->mcast.connect_to_client && 
          client_name && strcmp(client_name, navi_ctx->mcast.connect_to_client)==0 && 
          domain && strcmp(domain, navi_ctx->config.domain_name)==0) {
        // TODO: if connected via unicast - disconnect, switch to multicast
        if (!navi_ctx->mcast.mcast_socket || navi_ctx->mcast.group_addr.sin_addr.s_addr!=group_addr.s_addr || navi_ctx->mcast.group_addr.sin_port!=udp_port) {
          DEBUG_printf(navi_ctx,NULL,"start receive mcast from %s on %s:%d\n",client_name,inet_ntoa(group_addr),ntohs(udp_port));
          navi_start_mcast_receive(navi_ctx, group_addr, udp_port, streams);
        }
      }
    }

    while (streams) {
      struct navi_protocol_stream_list_s *next=streams->next;
      NAVI_free(streams);
      streams=next;
    }

    NAVI_free(client_name);
    NAVI_free(domain);

    NAVI_free((void *)decrypted_data);
  }
}

static
void navi_send_mcast_announce(struct navi_protocol_ctx_s *navi_ctx, const uint64_t now_dt) {
  int res;
  if (!mcast_discovery_fd) return;

  if (navi_ctx->mcast.announce_time>now_dt) {
    navi_ctx->mcast.announce_time=0;
  }

  if ((now_dt-navi_ctx->mcast.announce_time)<NAVI_MCAST_ANNOUNCE_PERIOD) return;
  navi_ctx->mcast.announce_time=now_dt;

  if (navi_ctx->mcast.group_addr.sin_addr.s_addr==0 || navi_ctx->mcast.group_addr.sin_port==0 || !navi_ctx->mcast.enable) {
    if (navi_ctx->mcast.announce_packet) {
      NAVI_free(navi_ctx->mcast.announce_packet);
      navi_ctx->mcast.announce_packet=NULL;
    }
    return;
  }

  if (!navi_ctx->mcast.announce_packet) {
    uint8_t *buffer;
    int data_len;
    struct navi_stream_ctx_s **streams;
    int ptr;
    uint16_t *crc_ptr;

    streams=(struct navi_stream_ctx_s **)alloca(sizeof(struct navi_stream_ctx_s *)*navi_ctx->tx_stream_count);
    ptr=0;
    for (struct navi_stream_ctx_s *s=navi_ctx->tx_streams; s; s=s->next) {
      streams[ptr++]=s;
    }

    data_len=tlv_encode(
      navi_ctx, 
      NULL, 
      multicast_announce_dict, 
      navi_ctx,
      DICT_MCAST_DOMAIN, navi_ctx->config.domain_name,
      DICT_MCAST_CLIENT_NAME, navi_ctx->config.client_name,
      DICT_MCAST_STREAM_COUNT, ptr,
      DICT_MCAST_GROUP, navi_ctx->mcast.group_addr.sin_addr.s_addr,
      DICT_MCAST_PORT, navi_ctx->mcast.group_addr.sin_port,
      TLV_ARRAY_OF(DICT_MCAST_STREAMS, ptr), streams, 
      TLV_END
    );
    if (data_len<0) {
      DEBUG_FAILURE(navi_ctx, NULL, "can't seralize tx streams\n");
      return;
    }

    buffer=alloca(data_len+16);
    data_len=tlv_encode(
      navi_ctx, 
      buffer, 
      multicast_announce_dict, 
      navi_ctx,
      DICT_MCAST_DOMAIN, navi_ctx->config.domain_name,
      DICT_MCAST_CLIENT_NAME, navi_ctx->config.client_name,
      DICT_MCAST_STREAM_COUNT, ptr,
      DICT_MCAST_GROUP, navi_ctx->mcast.group_addr.sin_addr.s_addr,
      DICT_MCAST_PORT, navi_ctx->mcast.group_addr.sin_port,
      TLV_ARRAY_OF(DICT_MCAST_STREAMS, ptr), streams, 
      TLV_END
    );
    if (data_len<0) {
      DEBUG_FAILURE(navi_ctx, NULL, "can't seralize tx streams\n");
      return;
    }
  
    crc_ptr=(uint16_t *)(buffer+data_len);
    *crc_ptr=htobe16(crc16(buffer, 0xFFFF, data_len));
    data_len+=sizeof(uint16_t);

    navi_ctx->mcast.announce_packet=navi_encrypt_with_mcast_secret(navi_ctx, buffer, data_len, &navi_ctx->mcast.announce_packet_len, NULL);
    if (!navi_ctx->mcast.announce_packet) {
      DEBUG_FAILURE(navi_ctx, NULL, "can't encrypt mcast announce\n");
      navi_ctx->mcast.announce_packet_len=0;
      return;
    }
  }

  if (!navi_ctx->mcast.announce_packet) return;

  res=sendto(mcast_discovery_fd, navi_ctx->mcast.announce_packet, navi_ctx->mcast.announce_packet_len, MSG_DONTWAIT|MSG_NOSIGNAL, (struct sockaddr *)&mcast_announce_addr, sizeof(mcast_announce_addr));

  DEBUG_printf(navi_ctx,NULL,"send mcast discovery %d name '%s'\n",res,navi_ctx->config.client_name);

  if (res<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "can't send mcast announce, error %s\n",strerror(errno));
  } else
  if (res<navi_ctx->mcast.announce_packet_len) {
    DEBUG_FAILURE(navi_ctx, NULL, "mcast announce: short send %d\n",res);
  }
}

static 
void *navi_transport_mcast_rx_thread(void *arg) {
  struct navi_protocol_ctx_s *navi_ctx=arg;
  uint8_t buffer[NAVI_MCAST_BUFFER_SIZE];
  struct NaviProtocolFrameHeader *head=(struct NaviProtocolFrameHeader *)buffer;
  struct NaviProtocolFrameHeader head_copy;

  if (!navi_ctx->mcast.enable) return NULL;
  if (!navi_ctx->mcast.mcast_socket) return NULL;

  DEBUG_printf(navi_ctx,NULL,"start mcast rx thread fd %d\n",navi_ctx->mcast.mcast_socket);

  navi_ctx->mcast.rx_active=0;

  while(navi_ctx->mcast.mcast_socket) {
    int res;
    struct sockaddr_in rx_addr;
    socklen_t rx_addr_len=sizeof(rx_addr);
    uint16_t calculated_crc;
    int payload_len;

    pthread_testcancel();
    
    res=recvfrom(navi_ctx->mcast.mcast_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&rx_addr, &rx_addr_len);
    if (res<0) {
      if (errno==EAGAIN) {
        usleep(1000);
        continue;
      }
      DEBUG_FAILURE(navi_ctx, NULL, "Can't read from mcast data socket, error %s\n",strerror(errno));
      return NULL;
    }

    if (!navi_check_rx_frame_size(res,head)) {
      DEBUG_FAILURE(navi_ctx, NULL, "Bad frame size %d (need %d)\n",res,navi_protocol_frame_size(head));
      navi_inc_perfcounter(&navi_ctx->counters.rx_errors);
      continue;
    }

    head_copy=*head;
    head_copy.crc=0xFFFF;
    
    payload_len=be16toh(head->payloadLength);

    calculated_crc=crc16(head->payload, crc16(&head_copy, head_copy.crc, sizeof(head_copy)),payload_len);

    if (be16toh(head->crc)!=calculated_crc) {
      DEBUG_FAILURE(navi_ctx, NULL, "bad crc %04x calc %04x\n",be16toh(head->crc),calculated_crc);
      navi_inc_perfcounter(&navi_ctx->counters.rx_errors);
      continue;
    }

    if (head->frameType==NAVICMD_DATA) {
      DEBUG_printf(navi_ctx,NULL,"data frame stream %08x\n",head->streamId);
      if (payload_len>0) {
        int data_len;
        const uint32_t stream_id=be32toh(head->streamId);
        struct navi_stream_ctx_s *stream_ctx=get_stream_by_id_in_queue(stream_id, navi_ctx->rx_streams);
        DEBUG_printf(navi_ctx,NULL,"RX stream ctx %p\n",stream_ctx);
        if (stream_ctx) {
          ++navi_ctx->mcast.rx_active;
          navi_add_perfcounter(&stream_ctx->counters.net_rx_rate, res);
          if (stream_ctx->desc.encryption==NAVI_ENCRYPT_NONE) {
            proced_rx_fragment(navi_ctx, head, (struct NaviProtocolDataFrameHeader*)head->payload, stream_id, stream_ctx, true);
          } else {
            void *decrypted_data=navi_decrypt_with_mcast_secret(navi_ctx, head->payload, sizeof(struct NaviProtocolDataFrameHeader)+NAVI_AES128_TAIL_LEN+sizeof(navi_ctx->mcast.local_iv), &data_len);
            if (decrypted_data && data_len>=sizeof(struct NaviProtocolDataFrameHeader)) {
              proced_rx_fragment(navi_ctx, head, (struct NaviProtocolDataFrameHeader*)decrypted_data, stream_id, stream_ctx, true);
            } else {
              DEBUG_FAILURE(navi_ctx, NULL, "Can't decrypt frame fragment header %p %d\n",decrypted_data,data_len);
            }
            NAVI_free(decrypted_data);
          }
        }
      }
    }
  }
  return NULL;
}

static
int navi_transport_start_multicast_on_addr(struct navi_protocol_ctx_s *navi_ctx, struct sockaddr_in *group_addr, const bool for_tx) {
  struct ip_mreqn mreq;
  char *addr_str=NULL;
  int port=5001;

  if (!navi_ctx->mcast.enable) return 0;
  if (navi_ctx->mcast.mcast_socket) return 0;
  if (!group_addr && !navi_ctx->config.multicast_tx_group) return -1;

  if (!group_addr) {
    switch (sscanf(navi_ctx->config.multicast_tx_group,"%m[0-9.]:%d",&addr_str,&port)) {
      case 1:
        port=5001;
        break;

      case 2:
        if (port<1 || port>65535) {
          free(addr_str);
          DEBUG_FAILURE(navi_ctx, NULL, "Bad port number %d\n",port);
          return -1;
        }
        break;

      default:
        DEBUG_FAILURE(navi_ctx, NULL, "Can't parse multicast_tx_group\n");
        return -1;
        break;
    }
  }

  navi_ctx->mcast.mcast_socket=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (navi_ctx->mcast.mcast_socket<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't create mcast data socket, error %s\n",strerror(errno));
    navi_ctx->mcast.mcast_socket=0;
    return -1;
  }

  static const int no=0;
  if (setsockopt(navi_ctx->mcast.mcast_socket, SOL_SOCKET, SO_REUSEADDR, &no, sizeof(no))<0) {
    DEBUG_FAILURE_A("Can't unset SO_REUSEADDR, error %s",strerror(errno));
    close(navi_ctx->mcast.mcast_socket);
    navi_ctx->mcast.mcast_socket=0;
    return -1;
  }

  if (setsockopt(navi_ctx->mcast.mcast_socket, IPPROTO_IP, IP_MULTICAST_LOOP, &no, sizeof (no))<0) {
    DEBUG_FAILURE_A("Can't unset IP_MULTICAST_LOOP, error %s",strerror(errno));
    close(navi_ctx->mcast.mcast_socket);
    navi_ctx->mcast.mcast_socket=0;
    return -1;
  }

  static const int multicastTTL=20;
  if (setsockopt(navi_ctx->mcast.mcast_socket, IPPROTO_IP, IP_MULTICAST_TTL, &multicastTTL, sizeof(multicastTTL))<0) {
    DEBUG_FAILURE_A("Can't set IP_MULTICAST_TTL, error %s",strerror(errno));
    close(navi_ctx->mcast.mcast_socket);
    navi_ctx->mcast.mcast_socket=0;
    return -1;
  }

  navi_ctx->mcast.group_addr.sin_family=AF_INET;

  if (!group_addr) {
    navi_ctx->mcast.group_addr.sin_port=htons(port);
  } else {
    navi_ctx->mcast.group_addr.sin_port=group_addr->sin_port;
  }

  if (for_tx) {
    navi_ctx->mcast.group_addr.sin_addr.s_addr=0;
    navi_ctx->mcast.group_addr.sin_port=0;
  } else {
    if (!group_addr) {
      navi_ctx->mcast.group_addr.sin_addr.s_addr=inet_addr(addr_str);
    } else {
      navi_ctx->mcast.group_addr.sin_addr=group_addr->sin_addr;
    }
  }

  DEBUG_printf(navi_ctx,NULL,"bind mcast tx to %s:%d\n",inet_ntoa(navi_ctx->mcast.group_addr.sin_addr),ntohs(navi_ctx->mcast.group_addr.sin_port));

  if (bind(navi_ctx->mcast.mcast_socket, (struct sockaddr *)&navi_ctx->mcast.group_addr, sizeof(navi_ctx->mcast.group_addr))<0) {
    DEBUG_FAILURE_A("Can't bind mcast data socket, error %s\n",strerror(errno));
    close(navi_ctx->mcast.mcast_socket);
    navi_ctx->mcast.mcast_socket=0;
    return -1;
  }

  if (for_tx) {
    if (!group_addr) {
      navi_ctx->mcast.group_addr.sin_addr.s_addr=inet_addr(addr_str);
    } else {
      navi_ctx->mcast.group_addr.sin_addr=group_addr->sin_addr;
    }

    if (connect(navi_ctx->mcast.mcast_socket, (struct sockaddr *)&navi_ctx->mcast.group_addr, sizeof(navi_ctx->mcast.group_addr))<0) {
      DEBUG_FAILURE_A("Can't connect mcast data socket, error %s\n",strerror(errno));
      close(navi_ctx->mcast.mcast_socket);
      navi_ctx->mcast.mcast_socket=0;
      return -1;
    }
  }

  mreq.imr_multiaddr=navi_ctx->mcast.group_addr.sin_addr;
  mreq.imr_address.s_addr=htonl(INADDR_ANY);
  mreq.imr_ifindex=0;

  if (setsockopt(navi_ctx->mcast.mcast_socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))<0) {
    DEBUG_FAILURE_A("Can't join data group, error %s\n",strerror(errno));
    close(navi_ctx->mcast.mcast_socket);
    navi_ctx->mcast.mcast_socket=0;
    return -1;
  }

  if (pthread_create(&navi_ctx->mcast.rx_thread, NULL, navi_transport_mcast_rx_thread, navi_ctx)) {
    DEBUG_FAILURE_A("Can't create mcast rx thread, error %s\n",strerror(errno));
    close(navi_ctx->mcast.mcast_socket);
    navi_ctx->mcast.mcast_socket=0;
    navi_ctx->mcast.rx_thread=0;
    return -1;
  }

  return 0;
}

int navi_transport_start_multicast(struct navi_protocol_ctx_s *navi_ctx) {
  return navi_transport_start_multicast_on_addr(navi_ctx, NULL, true);
}

int navi_transport_stop_multicast(struct navi_protocol_ctx_s *navi_ctx) {
  struct ip_mreq mreq;

  if (!navi_ctx->mcast.enable) return 0;
  if (!navi_ctx->mcast.mcast_socket) return -1;

  mreq.imr_multiaddr=navi_ctx->mcast.group_addr.sin_addr;
  mreq.imr_interface.s_addr=htonl(INADDR_ANY);

  // don't care about result, just drop membership
  setsockopt(navi_ctx->mcast.mcast_socket, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));

  pthread_cancel(navi_ctx->mcast.rx_thread);

  close(navi_ctx->mcast.mcast_socket);
  navi_ctx->mcast.mcast_socket=0;

  pthread_join(navi_ctx->mcast.rx_thread, NULL);
  navi_ctx->mcast.rx_thread=0;

  return 0;
}

static 
void navi_start_mcast_receive(struct navi_protocol_ctx_s *navi_ctx, const struct in_addr group_addr, const int udp_port, struct navi_protocol_stream_list_s *streams) {
  struct sockaddr_in A;
  A.sin_family=AF_INET;
  A.sin_addr=group_addr;
  A.sin_port=udp_port;

  for (struct navi_protocol_stream_list_s *sd=streams; sd; sd=sd->next) {
    bool found_duplicate=false;    
    
    pthread_spin_lock(&navi_ctx->rx_streams_lock);
    for (struct navi_stream_ctx_s *s=navi_ctx->rx_streams; s; s=s->next) {
      if (s->stream_id==sd->stream_id) {
        found_duplicate=true;
        break;
      }
    }
    pthread_spin_unlock(&navi_ctx->rx_streams_lock);

    if (found_duplicate) continue;
    
    struct navi_stream_ctx_s *stream=NAVI_malloc(sizeof(struct navi_stream_ctx_s));
    stream->desc=sd->desc;
    stream->stream_id=sd->stream_id;

    stream->navi_ctx=navi_ctx;
    stream->packet_id=0;
    stream->rx_queue_head=0;
    stream->stream_api_id=0;

    stream->rx_queue=NAVI_malloc(sizeof(struct navi_rx_packet_s *)*stream->desc.rx_queue_length);
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
  }

  navi_transport_stop_multicast(navi_ctx);
  navi_transport_start_multicast_on_addr(navi_ctx, &A, false);

  if (navi_ctx->events.rx_stream_event) {
    for (struct navi_stream_ctx_s *s=navi_ctx->rx_streams; s; s=s->next) {
      navi_ctx->events.rx_stream_event(navi_ctx, s, s->stream_id, &s->desc, navi_ctx->events.rx_stream_event_data);
    }
    navi_ctx->events.rx_stream_event(navi_ctx, NULL, 0, NULL, navi_ctx->events.rx_stream_event_data);
  }
}

int navi_start_mcast_report_sending(void) {
  struct ip_mreqn mreq;
  
  if (mcast_report_send_fd) return 0;

  mcast_report_send_fd=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (mcast_report_send_fd<0) {
    mcast_report_send_fd=0;
    DEBUG_FAILURE_A("Can't create multicast socket, error %s",strerror(errno));
    return -1;
  }

  static const int yes=1;
  if (setsockopt(mcast_report_send_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))<0) {
    DEBUG_FAILURE_A("Can't set SO_REUSEADDR, error %s",strerror(errno));
    close(mcast_report_send_fd);
    mcast_report_send_fd=0;
    return -1;
  }

  static const int multicastTTL=20;
  if (setsockopt(mcast_report_send_fd, IPPROTO_IP, IP_MULTICAST_TTL, &multicastTTL, sizeof(multicastTTL))<0) {
    DEBUG_FAILURE_A("Can't set IP_MULTICAST_TTL, error %s",strerror(errno));
    close(mcast_report_send_fd);
    mcast_report_send_fd=0;
    return -1;
  }

  mcast_report_addr.sin_family=AF_INET;
  mcast_report_addr.sin_port=htons(NAVI_MULTICAST_REPORT_PORT);
  mcast_report_addr.sin_addr.s_addr=inet_addr(report_group_addr);

  if (bind(mcast_report_send_fd, (struct sockaddr *)&mcast_report_addr, sizeof(mcast_report_addr))<0) {
    DEBUG_FAILURE_A("Can't bind report addr, error %s",strerror(errno));
    close(mcast_report_send_fd);
    mcast_report_send_fd=0;
    return -1;
  }

  mreq.imr_multiaddr=mcast_report_addr.sin_addr;
  mreq.imr_address.s_addr=htonl(INADDR_ANY);
  mreq.imr_ifindex=0;

  // ignore result
  setsockopt(mcast_report_send_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

  DEBUG_printf_a("multicast report fd %d\n",mcast_report_send_fd);

  return 0;
}

static
void navi_send_mcast_report(struct navi_protocol_ctx_s *navi_ctx, const uint64_t now_dt) {
  uint8_t *buffer;
  int data_len;
  struct navi_stream_ctx_s **streams;
  int ptr;
  int res;
  uint16_t *crc_ptr;
  void *report_packet;
  int report_packet_len;

  if (!mcast_report_send_fd) return;

  if ((now_dt-navi_ctx->mcast.report_tx_time)<NAVI_MCAST_REPORT_PERIOD) return;
  navi_ctx->mcast.report_tx_time=now_dt;

  streams=(struct navi_stream_ctx_s **)alloca(sizeof(struct navi_stream_ctx_s *)*navi_ctx->rx_stream_count);
  ptr=0;
  for (struct navi_stream_ctx_s *s=navi_ctx->rx_streams; s; s=s->next) {
    streams[ptr++]=s;
  }

  data_len=tlv_encode(
    navi_ctx, 
    NULL, 
    multicast_report_dict, 
    navi_ctx,
    DICT_MCAST_REPORT_DOMAIN, navi_ctx->config.domain_name,
    DICT_MCAST_REPORT_CLIENT_NAME, navi_ctx->config.client_name,
    DICT_MCAST_REPORT_STREAM_COUNT, ptr,
    TLV_ARRAY_OF(DICT_MCAST_REPORT_STREAMS, ptr), streams, 
    TLV_END
  );
  if (data_len<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "can't seralize rx report\n");
    return;
  }

  buffer=alloca(data_len+16);
  data_len=tlv_encode(
    navi_ctx, 
    buffer, 
    multicast_report_dict, 
    navi_ctx,
    DICT_MCAST_REPORT_DOMAIN, navi_ctx->config.domain_name,
    DICT_MCAST_REPORT_CLIENT_NAME, navi_ctx->config.client_name,
    DICT_MCAST_REPORT_STREAM_COUNT, ptr,
    TLV_ARRAY_OF(DICT_MCAST_REPORT_STREAMS, ptr), streams, 
    TLV_END
  );
  if (data_len<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "can't seralize rx report\n");
    return;
  }

  crc_ptr=(uint16_t *)(buffer+data_len);
  *crc_ptr=htobe16(crc16(buffer, 0xFFFF, data_len));
  data_len+=sizeof(uint16_t);

  report_packet=navi_encrypt_with_mcast_secret(navi_ctx, buffer, data_len, &report_packet_len, NULL);
  if (!report_packet) {
    DEBUG_FAILURE(navi_ctx, NULL, "can't encrypt mcast report\n");
    return;
  }

  res=sendto(mcast_report_send_fd, report_packet, report_packet_len, MSG_DONTWAIT|MSG_NOSIGNAL, (struct sockaddr *)&mcast_report_addr, sizeof(mcast_report_addr));
  NAVI_free(report_packet);

  DEBUG_printf(navi_ctx,NULL,"send mcast report %d\n",res);

  if (res<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "can't send mcast report, error %s\n",strerror(errno));
  } else
  if (res<report_packet_len) {
    DEBUG_FAILURE(navi_ctx, NULL, "mcast report: short send %d\n",res);
  }

}

static int encode_stream_report(va_list *ap, uint8_t *dst, void *user_ctx) {
  struct navi_stream_ctx_s *stream=va_arg(*ap, struct navi_stream_ctx_s *);
  return tlv_encode(
    user_ctx,
    dst,
    stream_report_dict,
    NULL,
    DICT_STREAM_REPORT_STREAM_ID, stream->stream_id,
    DICT_STREAM_REPORT_RX_BYTES, navi_read_perfcounter_counter(&stream->counters.rx_bytes),
    DICT_STREAM_REPORT_RX_PACKETS, navi_read_perfcounter_counter(&stream->counters.rx_packets),
    DICT_STREAM_REPORT_RX_PACKETS_LOST, navi_read_perfcounter_counter(&stream->counters.rx_loss_count),
    TLV_END
  );
}

static
int encode_stream_report_va(uint8_t *dst, void *user_ctx, ...) {
  va_list ap;
  va_start(ap, user_ctx);
  return encode_stream_report(&ap, dst, user_ctx);
}

static int encode_stream_report_arr(void *ptr, const int idx, uint8_t *dst, void *user_ctx) {
  struct navi_stream_ctx_s **stream=(struct navi_stream_ctx_s **)ptr;
  return encode_stream_report_va(dst, user_ctx, stream[idx]);
}

static int decode_stream_report(uint8_t *src, const int src_len, void *dst, void *user_ctx) {
  int res;
  struct navi_protocol_ctx_s *navi_ctx=(struct navi_protocol_ctx_s *)dst;
  struct navi_stream_report_s report;

  memset(&report, 0, sizeof(struct navi_stream_report_s));

  res=tlv_decode(
    navi_ctx, 
    src, src_len, 
    stream_report_dict, 
    NULL, 
    DICT_STREAM_REPORT_STREAM_ID, &report.stream_id,
    DICT_STREAM_REPORT_RX_BYTES, &report.rx_bytes,
    DICT_STREAM_REPORT_RX_PACKETS, &report.rx_packets,
    DICT_STREAM_REPORT_RX_PACKETS_LOST, &report.rx_packets_lost,
    TLV_END
  );

  if (res>0) {
    const uint64_t now=navi_current_time(navi_ctx);
    for (struct navi_stream_ctx_s *s=navi_ctx->tx_streams; s; s=s->next) {
      if (s->stream_id==report.stream_id) {
        report.report_time=now;
        s->mcast.remote_report=report;
        break;
      }
    }
  } else {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't decode mcast report, res %d\n",res);
  }
  return res;
}

int navi_transport_receive_multicast_report(struct navi_protocol_ctx_s *navi_ctx, const int enable) {
  struct sockaddr_in report_A;
  struct ip_mreqn mreq;

  if (!enable && navi_ctx->mcast.mcast_report_recv_socket>0) {
    close(navi_ctx->mcast.mcast_report_recv_socket);
    navi_ctx->mcast.mcast_report_recv_socket=0;
    return 0;
  }

  navi_ctx->mcast.mcast_report_recv_socket=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (navi_ctx->mcast.mcast_report_recv_socket<0) {
    DEBUG_FAILURE(navi_ctx, NULL, "Can't create mcast report socket, error %s\n",strerror(errno));
    navi_ctx->mcast.mcast_report_recv_socket=0;
    return -1;
  }

  static const int yes=1;
  if (setsockopt(navi_ctx->mcast.mcast_report_recv_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))<0) {
    DEBUG_FAILURE(navi_ctx,NULL,"Can't set SO_REUSEADDR, error %s",strerror(errno));
    close(navi_ctx->mcast.mcast_report_recv_socket);
    navi_ctx->mcast.mcast_report_recv_socket=0;
    return -1;
  }

  static const int no=0;
  if (setsockopt(navi_ctx->mcast.mcast_report_recv_socket, IPPROTO_IP, IP_MULTICAST_LOOP, &no, sizeof (no))<0) {
    DEBUG_FAILURE(navi_ctx,NULL,"Can't unset IP_MULTICAST_LOOP, error %s",strerror(errno));
    close(navi_ctx->mcast.mcast_report_recv_socket);
    navi_ctx->mcast.mcast_report_recv_socket=0;
    return -1;
  }

  static const int multicastTTL=20;
  if (setsockopt(navi_ctx->mcast.mcast_report_recv_socket, IPPROTO_IP, IP_MULTICAST_TTL, &multicastTTL, sizeof(multicastTTL))<0) {
    DEBUG_FAILURE(navi_ctx,NULL,"Can't set IP_MULTICAST_TTL, error %s",strerror(errno));
    close(navi_ctx->mcast.mcast_report_recv_socket);
    navi_ctx->mcast.mcast_report_recv_socket=0;
    return -1;
  }

  report_A.sin_family=AF_INET;
  report_A.sin_port=htons(NAVI_MULTICAST_REPORT_PORT);
  report_A.sin_addr.s_addr=inet_addr(report_group_addr);

  if (bind(navi_ctx->mcast.mcast_report_recv_socket, (struct sockaddr *)&report_A, sizeof(report_A))<0) {
    DEBUG_FAILURE_A("Can't bind mcast report rx socket, error %s\n",strerror(errno));
    close(navi_ctx->mcast.mcast_report_recv_socket);
    navi_ctx->mcast.mcast_report_recv_socket=0;
    return -1;
  }

  mreq.imr_multiaddr=report_A.sin_addr;
  mreq.imr_address.s_addr=htonl(INADDR_ANY);
  mreq.imr_ifindex=0;

  if (setsockopt(navi_ctx->mcast.mcast_report_recv_socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))<0) {
    DEBUG_FAILURE_A("Can't join report group, error %s\n",strerror(errno));
    close(navi_ctx->mcast.mcast_report_recv_socket);
    navi_ctx->mcast.mcast_report_recv_socket=0;
    return -1;
  }

  return 0;    
}

void navi_mcast_check_report(struct navi_protocol_ctx_s *navi_ctx, const uint64_t now_dt) {
  uint8_t buffer[NAVI_MCAST_BUFFER_SIZE];

  if (!navi_ctx->mcast.mcast_report_recv_socket) return;
  if (navi_ctx->mcast.membership_check>now_dt) navi_ctx->mcast.membership_check=0;

  if (now_dt-navi_ctx->mcast.report_membership_check>NAVI_MCAST_MEMBERSHIP_TIMEOUT) {
    struct ip_mreq mreq;
    navi_ctx->mcast.report_membership_check=now_dt;

    mreq.imr_multiaddr.s_addr=inet_addr(report_group_addr);
    mreq.imr_interface.s_addr=htonl(INADDR_ANY);

    // don't care about result
    setsockopt(navi_ctx->mcast.mcast_report_recv_socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
  }

   for(;;) {
    ssize_t res;
    struct sockaddr_in pkt_addr;
    socklen_t pkt_addr_len=sizeof(pkt_addr);
    uint8_t *decrypted_data;
    int decrypted_len;
    uint16_t *crc_ptr;
    uint16_t rx_crc;
    char *domain=NULL;
    char *client_name=NULL;
    uint8_t stream_count;
    struct in_addr group_addr;
    uint16_t udp_port;
    struct navi_protocol_stream_list_s *streams=NULL;

    res=recvfrom(navi_ctx->mcast.mcast_report_recv_socket, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr *)&pkt_addr, &pkt_addr_len);
    if (res<(ssize_t)sizeof(navi_ctx->mcast.local_iv)) return;

    // loopback check
    if (memcmp(buffer, navi_ctx->mcast.local_iv, sizeof(navi_ctx->mcast.local_iv))==0) {
      continue;
    }

    decrypted_data=(uint8_t*)navi_decrypt_with_mcast_secret(navi_ctx, buffer, res, &decrypted_len);
    if (!decrypted_data) return;
    if (decrypted_len<8) {
      NAVI_free((void *)decrypted_data);
      continue;
    }

    //DEBUG_hexdump(decrypted_data, decrypted_len);

    crc_ptr=(uint16_t *)(decrypted_data+decrypted_len-sizeof(uint16_t));
    rx_crc=htobe16(crc16(decrypted_data, 0xFFFF, decrypted_len-sizeof(uint16_t)));
    if (*crc_ptr!=rx_crc) {
      DEBUG_FAILURE(navi_ctx, NULL, "bad mcast report crc\n");
      NAVI_free((void *)decrypted_data);
      continue;
    }

    res=tlv_decode(
      navi_ctx,
      decrypted_data,
      decrypted_len-sizeof(uint16_t),
      multicast_report_dict,
      navi_ctx,
      DICT_MCAST_REPORT_DOMAIN, &domain,
      DICT_MCAST_REPORT_CLIENT_NAME, &client_name,
      DICT_MCAST_REPORT_STREAM_COUNT, &stream_count,
      DICT_MCAST_REPORT_STREAMS, navi_ctx,
      TLV_END
    );

    DEBUG_printf(navi_ctx,NULL,"mcast report: res %ld name %s domain %s streams %d\n",res,client_name,domain,stream_count);

    NAVI_free(client_name);
    NAVI_free(domain);

    NAVI_free((void *)decrypted_data);
  }
}

static 
bool navi_mcast_can_send_stream(struct navi_protocol_ctx_s *navi_ctx, struct navi_stream_ctx_s *stream_ctx) {
  if (!navi_ctx->mcast.ondemand_enable) return true;
  return !stream_ctx->mcast.report_rx_timeout;
}
