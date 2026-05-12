include_guard()

set(${PROJECT_NAME}_CX_WARNING_FLAGS
    # Disabled Warnings
    -Wno-unknown-pragmas
    -Wno-c++98-compat
    -Wno-c++98-compat-pedantic
    -Wno-padded
    -Wno-covered-switch-default
    -Wfloat-equal
    -Wextra
    # -Wconversion
    -Wlogical-op
    -Wundef
    -Wredundant-decls
    -Wshadow
    -Walloca
    -Wstrict-overflow=2
    -Wwrite-strings
    -Wpointer-arith
    # -Wcast-qual
    -Wformat=2
    -Wformat-truncation
    -Wmissing-include-dirs
    # -Wcast-align
    -Wswitch-enum
    -Wsign-conversion
    -Wdisabled-optimization
    -Winvalid-pch
    -Wmissing-declarations
    -Wdouble-promotion
    -Wtrampolines
    -Wvector-operation-performance
    -Wshift-overflow=2
    -Wnull-dereference
    -Wduplicated-cond
    -Wcast-align=strict
)

set(${PROJECT_NAME}_CXX_WARNING_FLAGS
    -Wold-style-cast
    # "-Wnon-virtual-dtor"
    -Wctor-dtor-privacy
    -Woverloaded-virtual
    -Wnoexcept
    -Wstrict-null-sentinel
    -Wuseless-cast
    -Wzero-as-null-pointer-constant
    -Wextra-semi
)

set(${PROJECT_NAME}_CX_FLAGS
    -ffreestanding
    # "-nostdinc"
    -nostdlib
    -fno-stack-protector
    -ffunction-sections
    -fdata-sections
    -fno-common
    -funsigned-char
    -static
)

set(${PROJECT_NAME}_C_FLAGS)
if(DEFINED ${PROJECT_NAME}_C_STD_FLAG AND NOT "${${PROJECT_NAME}_C_STD_FLAG}" STREQUAL "")
    list(APPEND ${PROJECT_NAME}_C_FLAGS "${${PROJECT_NAME}_C_STD_FLAG}")
endif()

set(${PROJECT_NAME}_KERNEL_CX_FLAGS -mgeneral-regs-only -mno-red-zone)

set(${PROJECT_NAME}_USERLAND_CX_FLAGS)

set(${PROJECT_NAME}_CXX_FLAGS
    -fno-rtti
    -fno-exceptions
    -fsized-deallocation
    -fcheck-new
    -fstrict-vtable-pointers
)
if(DEFINED ${PROJECT_NAME}_CXX_STD_FLAG AND NOT "${${PROJECT_NAME}_CXX_STD_FLAG}" STREQUAL "")
    list(APPEND ${PROJECT_NAME}_CXX_FLAGS "${${PROJECT_NAME}_CXX_STD_FLAG}")
endif()

set(${PROJECT_NAME}_LINK_FLAGS
    -ffreestanding
    -Wl,--gc-sections
    -Wl,-static
    -Wl,-znoexecstack
    -Wl,-zmax-page-size=0x1000
)

set(${PROJECT_NAME}_CX_DEFINES LIMINE_API_REVISION=${${PROJECT_NAME}_LIMINE_API_REV})

if(${PROJECT_NAME}_ARCHITECTURE STREQUAL "x86_64")
    list(APPEND ${PROJECT_NAME}_CX_FLAGS -march=x86-64 -mabi=sysv)

    list(
        APPEND ${PROJECT_NAME}_KERNEL_CX_FLAGS
        -mno-mmx
        -mno-sse
        -mno-sse2
        -mno-80387
        -mno-x87
        -mcmodel=kernel
        -mstack-alignment=8
    )

    list(
        APPEND ${PROJECT_NAME}_CX_DEFINES
        KSTACK_SIZE=0x2000
        USTACK_SIZE=0x4000
        CACHE_LINE_SIZE=64
    )
else()
    message(
        FATAL_ERROR
        "Unsupported ${PROJECT_NAME} Architecture: '${${PROJECT_NAME}_ARCHITECTURE}'"
    )
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
    list(APPEND ${PROJECT_NAME}_LINK_FLAGS -Wl,--strip-debug)

    list(
        APPEND ${PROJECT_NAME}_CX_DEFINES
        LOG_LEVEL_THRESHOLD=LOG_INFO
        KERNEL_DEBUG=0
        CONFIG_FRAME_POINTER=0
    )
else()
    list(
        APPEND ${PROJECT_NAME}_CX_DEFINES
        KERNEL_DEBUG=1
        LOG_LEVEL_THRESHOLD=LOG_TRACE
        CONFIG_FRAME_POINTER=1
    )
endif()

list(REMOVE_DUPLICATES ${PROJECT_NAME}_CX_WARNING_FLAGS)
list(REMOVE_DUPLICATES ${PROJECT_NAME}_CXX_WARNING_FLAGS)
list(REMOVE_DUPLICATES ${PROJECT_NAME}_CX_FLAGS)
list(REMOVE_DUPLICATES ${PROJECT_NAME}_C_FLAGS)
list(REMOVE_DUPLICATES ${PROJECT_NAME}_KERNEL_CX_FLAGS)
list(REMOVE_DUPLICATES ${PROJECT_NAME}_USERLAND_CX_FLAGS)
list(REMOVE_DUPLICATES ${PROJECT_NAME}_CXX_FLAGS)
list(REMOVE_DUPLICATES ${PROJECT_NAME}_LINK_FLAGS)
list(REMOVE_DUPLICATES ${PROJECT_NAME}_CX_DEFINES)
