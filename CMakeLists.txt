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

add_compile_definitions(_FILE_OFFSET_BITS=64 _GNU_SOURCE)
target_compile_options(${PROJECT_NAME} PRIVATE -MMD -funsigned-char -Wno-pointer-sign -std=c11 -Werror -fvisibility=hidden)
