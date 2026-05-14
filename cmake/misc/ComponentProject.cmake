include_guard()

include(CMakeParseArguments)

function(hazel_component_project)
    set(oneValueArgs NAME OUT_SUPERPROJECT_VAR)
    cmake_parse_arguments(ARG "" "${oneValueArgs}" "" ${ARGN})

    if(NOT ARG_NAME)
        message(FATAL_ERROR "hazel_component_project: NAME argument is required.")
    endif()

    if(NOT ARG_OUT_SUPERPROJECT_VAR)
        message(FATAL_ERROR "hazel_component_project: OUT_SUPERPROJECT_VAR argument is required.")
    endif()

    if(NOT DEFINED HAZEL_SUPERPROJECT_NAME OR "${HAZEL_SUPERPROJECT_NAME}" STREQUAL "")
        message(
            FATAL_ERROR
            "${ARG_NAME}: HAZEL_SUPERPROJECT_NAME is not set. Add this component through the top-level project."
        )
    endif()

    project(${ARG_NAME} LANGUAGES C CXX ASM)
    set(${ARG_OUT_SUPERPROJECT_VAR} "${HAZEL_SUPERPROJECT_NAME}" PARENT_SCOPE)
endfunction()

function(hazel_component_export_target)
    set(oneValueArgs EXPORT_VAR TARGET)
    cmake_parse_arguments(ARG "" "${oneValueArgs}" "" ${ARGN})

    if(NOT ARG_EXPORT_VAR)
        message(FATAL_ERROR "hazel_component_export_target: EXPORT_VAR argument is required.")
    endif()

    if(NOT ARG_TARGET)
        message(FATAL_ERROR "hazel_component_export_target: TARGET argument is required.")
    endif()

    if(NOT TARGET ${ARG_TARGET})
        message(FATAL_ERROR "hazel_component_export_target: Target '${ARG_TARGET}' does not exist.")
    endif()

    set(${ARG_EXPORT_VAR} "${ARG_TARGET}" PARENT_SCOPE)
endfunction()
