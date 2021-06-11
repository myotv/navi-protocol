#ifndef _NAVI_PROTOCOL_H_
#define _NAVI_PROTOCOL_H_

#define NAVICMD_START (htobe16(0x4e53))
#define NAVICMD_STREAMS (htobe16(0x4e41))
#define NAVICMD_DATA (htobe16(0x4e44))

#define NAVI_INFO_STREAM 0x4e415649

struct NaviProtocolFrameHeader {
  uint16_t frameType;
  uint32_t streamId;
  uint16_t crc;
  uint16_t payloadLength;
  uint8_t payload[0];
} __attribute__((packed));

struct NaviProtocolStartFrame {
  uint8_t domain[16];
  uint8_t public_key[0];
} __attribute__((packed));

struct NaviProtocolDataFrameHeader {
  int64_t dts;
  int64_t pts;
#define NAVI_DATA_CHECK_BYTE 0x5A
  uint8_t check; // 0x5A here
// internal flags
#define NAVI_DATA_FLAG_FEC_FRAME 0x10
#define NAVI_DATA_FLAG_ENCRYPTED_DATA 0x20
  uint8_t flags;
  uint16_t frame_count;
  uint32_t frame_id;
  uint32_t frame_size;
  uint16_t frame_idx;
} __attribute__((packed));

static inline
int navi_protocol_frame_size(struct NaviProtocolFrameHeader *head) {
  return be16toh(head->payloadLength)+sizeof(struct NaviProtocolFrameHeader);
}

static inline
int navi_check_rx_frame_size(const int rx_size, struct NaviProtocolFrameHeader *head) {
  if (rx_size<sizeof(struct NaviProtocolFrameHeader)) return 0;
  return rx_size==navi_protocol_frame_size(head);
}

#endif
