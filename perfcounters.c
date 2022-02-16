#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>

#include "libnavi.h"
#include "perfcounters.h"
#include "utils.h"

static inline
uint16_t crc16_compute(const void *ptr, const size_t len) {
  return crc16(ptr, 0xFFFF, len);
}

void navi_init_perfcounter(navi_perfcounter *pc, const char *id, const char is_gauge) {
  pc->counter=0;
  pc->gauge=is_gauge;
  pc->remote=0;
  pc->rate=0.0;
  pc->read_dt_ms=0;
  strncpy(pc->id, id, sizeof(pc->id)-1);
  pc->hash=crc16_compute(id, strlen(id));
  pthread_spin_init(&pc->lock, PTHREAD_PROCESS_PRIVATE);
}

void navi_init_remote_perfcounter(navi_perfcounter *pc, const char *id, const char is_gauge) {
  pc->counter=0;
  pc->gauge=is_gauge;
  pc->remote=1;
  pc->rate=0.0;
  pc->read_dt_ms=0;
  strncpy(pc->id, id, sizeof(pc->id)-1);
  pc->hash=crc16_compute(id, strlen(id));
}

void navi_reset_perfcounter(navi_perfcounter *pc) {
  if (pc->remote) {
    pc->counter=0;
    pc->rate=0.0;
    return;
  }
  pthread_spin_lock(&pc->lock);
  pc->counter=0;
  pc->rate=0.0;
  pc->read_dt_ms=0;
  pthread_spin_unlock(&pc->lock);
}

double navi_read_perfcounter(navi_perfcounter *pc, const uint64_t current_dt_in_ms) {
  unsigned long counter,rate_ms;
  uint64_t time_delta;
  double rate;

  if (pc->remote) {
    if (pc->gauge) {
      double counter=pc->counter;
      return counter;
    }
    return pc->rate;
  }

  pthread_spin_lock(&pc->lock);

  if (pc->gauge) {
    double counter=pc->counter;
    pthread_spin_unlock(&pc->lock);
    return counter;
  }

  if (current_dt_in_ms<pc->read_dt_ms) {
    pthread_spin_unlock(&pc->lock);
    return -1;
  }

  time_delta=current_dt_in_ms-pc->read_dt_ms;
  if (time_delta<PERFCOUNTER_READ_PERIOD) {
    pthread_spin_unlock(&pc->lock);
    return pc->rate;
  }

  counter=pc->counter;
  pc->counter=0;
  rate_ms=counter/time_delta;
  rate=pc->rate=rate_ms/1000.0;
  pc->read_dt_ms=current_dt_in_ms;
  pthread_spin_unlock(&pc->lock);
  return rate;
}
