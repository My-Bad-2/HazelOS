include("${CMAKE_CURRENT_LIST_DIR}/../cmake/misc/ComponentProject.cmake")

hazel_component_project(NAME HazelUserland OUT_SUPERPROJECT_VAR HAZEL_USERLAND_SUPERPROJECT)

set(_hazel_userland_namespace "${HAZEL_USERLAND_SUPERPROJECT}")

set(USERLAND_CX_FLAGS -mavx -mavx2)

set(USERLAND_LINK_SCRIPT
    ${CMAKE_SOURCE_DIR}/misc/linker/${${_hazel_userland_namespace}_ARCHITECTURE}-userland.ld
)
set(USERLAND_INCLUDE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/arch/${${_hazel_userland_namespace}_ARCHITECTURE}"
    ${FREESTND_HDRS_DIR}
    ${UACPI_INCLUDES}
)

collect_sources_filtered(
    VAR USERLAND_SOURCES
    ROOT ${CMAKE_CURRENT_SOURCE_DIR}/src
    ARCH_DIR arch
    CURRENT_ARCH ${${_hazel_userland_namespace}_ARCHITECTURE}
    DEBUG OFF
)

add_executable(userland ${USERLAND_SOURCES} ${UACPI_SOURCES})

set_target_properties(userland PROPERTIES OUTPUT_NAME "init.elf")

target_include_directories(userland PRIVATE ${USERLAND_INCLUDE_DIR})
target_link_libraries(userland llvm-libc ${CRT_LIBRARY_PATH}/libclang_rt.builtins.a)
target_compile_definitions(userland PRIVATE ${${_hazel_userland_namespace}_CX_DEFINES})

target_apply_compile_settings(
    TARGET userland
    LANG "C;ASM"
    FLAGS
        ${${_hazel_userland_namespace}_CX_FLAGS}
        ${${_hazel_userland_namespace}_USERLAND_CX_FLAGS}
        ${USERLAND_CX_FLAGS}
        ${${_hazel_userland_namespace}_CX_WARNING_FLAGS}
)

target_apply_compile_settings(
    TARGET userland
    LANG "C"
    FLAGS
        ${${_hazel_userland_namespace}_C_FLAGS}
)

target_apply_compile_settings(
    TARGET userland
    LANG "CXX"
    FLAGS
        ${${_hazel_userland_namespace}_CX_FLAGS}
        ${${_hazel_userland_namespace}_CXX_FLAGS}
        ${${_hazel_userland_namespace}_USERLAND_CX_FLAGS}
        ${USERLAND_CX_FLAGS}
        ${${_hazel_userland_namespace}_CX_WARNING_FLAGS}
        ${${_hazel_userland_namespace}_CXX_WARNING_FLAGS}
)

target_apply_linker_settings(
    TARGET userland
    LANG "C;CXX"
    SCRIPT ${USERLAND_LINK_SCRIPT}
    FLAGS ${${_hazel_userland_namespace}_LINK_FLAGS}
)

add_custom_command(
    TARGET userland
    POST_BUILD
    COMMAND
        ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:userland>
        ${${_hazel_userland_namespace}_ISO_DIR}/boot/limine/
    COMMENT "Copying userland to ISO directory"
    VERBATIM
)

install(TARGETS userland DESTINATION ${${_hazel_userland_namespace}_ISO_DIR}/boot/limine)

hazel_component_export_target(EXPORT_VAR HAZEL_USERLAND_TARGET TARGET userland)
