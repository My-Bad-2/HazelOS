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

add_executable(kernel ${KERNEL_SOURCES} ${UACPI_SOURCES})

set_target_properties(kernel PROPERTIES OUTPUT_NAME "${PROJECT_NAME}.elf")

target_include_directories(kernel PRIVATE ${KERNEL_INCLUDE_DIR})
target_link_libraries(kernel llvm-libc ${CRT_LIBRARY_PATH}/libclang_rt.builtins.a)

target_apply_compile_settings(
    TARGET kernel
    LANG "C;ASM"
    FLAGS ${${PROJECT_NAME}_CX_FLAGS} ${KERNEL_CX_FLAGS} ${${PROJECT_NAME}_CX_DEFINES} ${${PROJECT_NAME}_CX_WARNING_FLAGS}
)

target_apply_linker_settings(
    TARGET kernel
    LANG "C"
    SCRIPT ${KERNEL_LINK_SCRIPT}
    SKIP_CHECK ON
    FLAGS ${${PROJECT_NAME}_LINK_FLAGS}
)

add_custom_command(
    TARGET kernel POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:kernel>
            ${${PROJECT_NAME}_ISO_DIR}/boot/limine/
    COMMENT "Copying Kernel to ISO directory"
    VERBATIM
)

install(TARGETS kernel DESTINATION ${${PROJECT_NAME}_ISO_DIR}/boot/limine)