project(navi LANGUAGES C)

option (NAVI_WITH_MULTICAST "" OFF)
option (NAVI_WITH_DEBUG "" OFF)

if (!NAVI_WITH_MULTICAST)
  add_compile_definitions(NAVI_WITH_MULTICAST=0)
endif()

if (!NAVI_WITH_DEBUG) 
  add_compile_definitions(NAVI_WITH_DEBUG=0)
endif()

set(SOURCES
    encryption.c 
    libnavi.c
    perfcounters.c
    tlv.c
    transport.c
    utils.c
    navi-compat.c
)

add_library(${PROJECT_NAME} ${SOURCES})
