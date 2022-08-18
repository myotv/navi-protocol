
#ifndef _NAVI_COMPAT_
#define _NAVI_COMPAT_

#ifdef __APPLE__

    #include <libkern/OSByteOrder.h>

    #define htobe16(x) OSSwapHostToBigInt16(x)
    #define htole16(x) OSSwapHostToLittleInt16(x)
    #define be16toh(x) OSSwapBigToHostInt16(x)
    #define le16toh(x) OSSwapLittleToHostInt16(x)

    #define htobe32(x) OSSwapHostToBigInt32(x)
    #define htole32(x) OSSwapHostToLittleInt32(x)
    #define be32toh(x) OSSwapBigToHostInt32(x)
    #define le32toh(x) OSSwapLittleToHostInt32(x)

    #define htobe64(x) OSSwapHostToBigInt64(x)
    #define htole64(x) OSSwapHostToLittleInt64(x)
    #define be64toh(x) OSSwapBigToHostInt64(x)
    #define le64toh(x) OSSwapLittleToHostInt64(x)

    #include <pthread.h>

    typedef int pthread_spinlock_t;

    int pthread_spin_init(pthread_spinlock_t *lock, int pshared);
    int pthread_spin_destroy(pthread_spinlock_t *lock);
    int pthread_spin_lock(pthread_spinlock_t *lock);
    int pthread_spin_unlock(pthread_spinlock_t *lock);

#endif // __APPLE__

#ifdef __linux__

    #include <endian.h>

#endif

#endif // _NAVI_COMPAT_
