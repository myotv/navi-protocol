project(navi LANGUAGES C)

option (NAVI_WITH_MULTICAST "" OFF)
option (NAVI_WITH_DEBUG "" OFF)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -MMD -funsigned-char -g -std=c11 -D_FILE_OFFSET_BITS=64 -Werror -D_GNU_SOURCE -fvisibility=hidden")
set(CMAKE_C_FLAGS_RELEAE "${CMAKE_C_FLAGS_DEBUG} -MMD -O3 -funsigned-char -g -std=c11 -D_FILE_OFFSET_BITS=64 -Werror -D_GNU_SOURCE -fvisibility=hidden")

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
