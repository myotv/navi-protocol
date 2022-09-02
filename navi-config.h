#ifndef _NAVI_CONFIG_H_
#define _NAVI_CONFIG_H_

#ifndef NAVI_WITH_DEBUG
#define NAVI_WITH_DEBUG 1
#endif

#ifndef NAVI_DEBUG_DATA_PACKETS
#define NAVI_DEBUG_DATA_PACKETS 1
#endif

// allow to create __attribute__((constructor)) initializer, 
// otherwize must call navi_init_library() method
#ifndef NAVI_ALLOW_CONSTRUCTOR_INIT
#define NAVI_ALLOW_CONSTRUCTOR_INIT 1
#endif

#ifndef NAVI_WITH_MULTICAST
#define NAVI_WITH_MULTICAST 1
#endif

#ifndef NAVI_HANDLE_JIUCE_OUTPUT
#define NAVI_HANDLE_JIUCE_OUTPUT 1
#endif

#ifndef NAVI_DEBUG_MEMORY_ALLOCATION
#define NAVI_DEBUG_MEMORY_ALLOCATION 0
#endif

#endif
