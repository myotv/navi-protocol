project(navi LANGUAGES C)

option (NAVI_WITH_MULTICAST "" OFF)
option (NAVI_WITH_DEBUG "" OFF)

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

target_compile_definitions(${PROJECT_NAME} PRIVATE NAVI_WITH_MULTICAST=${NAVI_WITH_MULTICAST} NAVI_WITH_DEBUG=${NAVI_WITH_DEBUG})
