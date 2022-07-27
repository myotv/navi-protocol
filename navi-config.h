#ifndef _NAVI_CONFIG_H_
#define _NAVI_CONFIG_H_

#define WITH_DEBUG 1
#define DEBUG_DATA_PACKETS 1

// allow to create __attribute__((constructor)) initializer, 
// otherwize must call navi_init_library() method
#ifndef NAVI_ALLOW_CONSTRUCTOR_INIT
#define NAVI_ALLOW_CONSTRUCTOR_INIT 1
#endif

#ifndef NAVI_WITH_MULTICAST
#define NAVI_WITH_MULTICAST 1
#endif

#endif
