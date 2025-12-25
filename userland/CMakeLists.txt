set(USERLAND_LINK_SCRIPT ${CMAKE_SOURCE_DIR}/misc/linker/${${PROJECT_NAME}_ARCHITECTURE}-userland.ld)
set(
    USERLAND_INCLUDE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/arch/${${PROJECT_NAME}_ARCHITECTURE}"
    ${FREESTND_HDRS_DIR}
    ${UACPI_INCLUDES}
)

collect_sources_filtered(
    VAR USERLAND_SOURCES
    ROOT ${CMAKE_CURRENT_SOURCE_DIR}/src
    ARCH_DIR arch
    CURRENT_ARCH ${${PROJECT_NAME}_ARCHITECTURE}
    DEBUG OFF
)

add_executable(userland ${USERLAND_SOURCES} ${UACPI_SOURCES})

set_target_properties(userland PROPERTIES OUTPUT_NAME "init.elf")

target_include_directories(userland PRIVATE ${USERLAND_INCLUDE_DIR})
target_link_libraries(userland llvm-libc ${CRT_LIBRARY_PATH}/libclang_rt.builtins.a)

target_apply_compile_settings(
    TARGET userland
    LANG "C;ASM"
    FLAGS ${${PROJECT_NAME}_CX_FLAGS} ${USERLAND_CX_FLAGS} ${${PROJECT_NAME}_CX_DEFINES} ${${PROJECT_NAME}_CX_WARNING_FLAGS}
)

target_apply_linker_settings(
    TARGET userland
    LANG "C"
    SCRIPT ${USERLAND_LINK_SCRIPT}
    SKIP_CHECK ON
    FLAGS ${${PROJECT_NAME}_LINK_FLAGS}
)

add_custom_command(
    TARGET userland POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:userland>
            ${${PROJECT_NAME}_ISO_DIR}/boot/limine/
    COMMENT "Copying userland to ISO directory"
    VERBATIM
)

install(TARGETS userland DESTINATION ${${PROJECT_NAME}_ISO_DIR}/boot/limine)