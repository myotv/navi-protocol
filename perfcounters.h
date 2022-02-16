#ifndef _PERFCOUNTERS_H_
#define _PERFCOUNTERS_H_

#define PERFCOUNTER_READ_PERIOD 1000 // in ms

typedef struct {
  volatile unsigned long counter;
  uint64_t read_dt_ms; // time of last read in ms
  double rate;
  char gauge:1; // counter is gauge, not ratemetter
  char remote:1; // counter is remote
  char id[32]; // including trailing zero
  uint16_t hash;
  pthread_spinlock_t lock;
} navi_perfcounter;

void navi_init_perfcounter(navi_perfcounter *pc, const char *id, const char is_gauge);
void navi_init_remote_perfcounter(navi_perfcounter *pc, const char *id, const char is_gauge);
void navi_reset_perfcounter(navi_perfcounter *pc);
double navi_read_perfcounter(navi_perfcounter *pc, const uint64_t current_dt_in_ms);

static inline
unsigned long navi_read_perfcounter_counter(navi_perfcounter *pc) {
  if (pc->remote) return pc->counter;
  unsigned long counter;
  pthread_spin_lock(&pc->lock);
  counter=pc->counter;
  pthread_spin_unlock(&pc->lock);
  return counter;
}

static inline
void navi_add_perfcounter(navi_perfcounter *pc, unsigned long value) {
  if (pc->remote) return;
  if (!pc->id[0]) return;
  pthread_spin_lock(&pc->lock);
  pc->counter+=value;
  pthread_spin_unlock(&pc->lock);
}

static inline
void navi_inc_perfcounter(navi_perfcounter *pc) {
  if (pc->remote) return;
  if (!pc->id[0]) return;
  pthread_spin_lock(&pc->lock);
  ++pc->counter;
  pthread_spin_unlock(&pc->lock);
}

static inline
void navi_set_perfcounter(navi_perfcounter *pc, unsigned long value) {
  if (!pc->id[0]) return;

  if (pc->remote) {
    pc->counter=value;
    return;
  }

  pthread_spin_lock(&pc->lock);
  pc->counter=value;
  pthread_spin_unlock(&pc->lock);
}

static inline
uint64_t navi_perfcounter_read_u64(const void *data) {
  return be64toh(*((uint64_t *)data));
}

static inline
double navi_perfcounter_read_double(const void *data) {
  const uint64_t local_data=navi_perfcounter_read_u64(data);
  return *((double *)&local_data);
}

static inline
void navi_perfcounter_write_u64(const uint64_t value, void *data) {
  uint64_t *data_ptr=(uint64_t *)data;
  *data_ptr=htobe64(value);
}

static inline
void navi_perfcounter_write_double(const double value, void *data) {
  navi_perfcounter_write_u64(*((uint64_t *)&value), data);
}


#endif
