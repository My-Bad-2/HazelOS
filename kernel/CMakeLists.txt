set(
    KERNEL_CX_FLAGS
    "-fno-pic"
    "-fno-pie"
)

set(KERNEL_LINK_SCRIPT ${CMAKE_SOURCE_DIR}/misc/linker/${${PROJECT_NAME}_ARCHITECTURE}-kernel.ld)
set(
    KERNEL_INCLUDE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/arch/${${PROJECT_NAME}_ARCHITECTURE}"
    ${FREESTND_HDRS_DIR}
    ${UACPI_INCLUDES}
)

collect_sources_filtered(
    VAR KERNEL_SOURCES
    ROOT ${CMAKE_CURRENT_SOURCE_DIR}/src
    ARCH_DIR arch
    CURRENT_ARCH ${${PROJECT_NAME}_ARCHITECTURE}
    DEBUG OFF
)

add_library(kernel_objs OBJECT ${KERNEL_SOURCES} ${UACPI_SOURCES})
target_compile_options(kernel_objs PRIVATE -fno-omit-frame-pointer)
target_include_directories(kernel_objs PRIVATE ${KERNEL_INCLUDE_DIR})
target_link_libraries(kernel_objs PRIVATE llvm-libc)

target_apply_compile_settings(
    TARGET kernel_objs
    LANG "C;ASM"
    FLAGS ${${PROJECT_NAME}_CX_FLAGS} ${KERNEL_CX_FLAGS} ${${PROJECT_NAME}_CX_DEFINES} ${${PROJECT_NAME}_CX_WARNING_FLAGS}
)

function(define_kernel_link_step target_name symbol_source)
    add_executable(${target_name} $<TARGET_OBJECTS:kernel_objs> ${symbol_source})
    target_include_directories(${target_name} PRIVATE ${KERNEL_INCLUDE_DIR})
    target_link_libraries(${target_name} llvm-libc ${CRT_LIBRARY_PATH}/libclang_rt.builtins.a)

    target_apply_linker_settings(
        TARGET ${target_name}
        LANG "C"
        SCRIPT ${KERNEL_LINK_SCRIPT}
        SKIP_CHECK ON
        FLAGS ${${PROJECT_NAME}_LINK_FLAGS}
    )
endfunction()

if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    define_kernel_link_step(kernel_step1 misc/dummy_symbols.c)

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/symbols_pass1.c
        COMMAND python3 ${CMAKE_SOURCE_DIR}/misc/scripts/map_to_c.py ${CMAKE_NM} $<TARGET_FILE:kernel_step1> ${CMAKE_CURRENT_BINARY_DIR}/symbols_pass1.c
        DEPENDS kernel_step1 ${CMAKE_SOURCE_DIR}/misc/scripts/map_to_c.py
        COMMENT "Generating Pass 1 symbols (fixing size drift)..."
    )

    define_kernel_link_step(kernel_step2 ${CMAKE_CURRENT_BINARY_DIR}/symbols_pass1.c)

    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/symbols_final.c
        COMMAND python3 ${CMAKE_SOURCE_DIR}/misc/scripts/map_to_c.py ${CMAKE_NM} $<TARGET_FILE:kernel_step2> ${CMAKE_CURRENT_BINARY_DIR}/symbols_final.c
        DEPENDS kernel_step2 ${CMAKE_SOURCE_DIR}/misc/scripts/map_to_c.py
        COMMENT "Generating Final symbols (byte-perfect convergence)..."
    )

    define_kernel_link_step(kernel_final ${CMAKE_CURRENT_BINARY_DIR}/symbols_final.c)
else()
    define_kernel_link_step(kernel_final "")
endif()

set_target_properties(kernel_final PROPERTIES OUTPUT_NAME "${PROJECT_NAME}.elf")

add_custom_command(
    TARGET kernel_final POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:kernel_final>
            ${${PROJECT_NAME}_ISO_DIR}/boot/limine/
    COMMENT "Copying Kernel to ISO directory"
    VERBATIM
)

# install(TARGETS kernel_final DESTINATION ${${PROJECT_NAME}_ISO_DIR}/boot/limine)