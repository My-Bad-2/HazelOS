include_guard()

# ==============================================================================
# Function: collect_sources_filtered
#
# Arguments:
#   VAR           : Output variable name
#   ROOT          : The source directory (e.g. "${CMAKE_CURRENT_SOURCE_DIR}/src")
#   ARCH_DIR      : The architecture specific folder name (e.g. "arch")
#   CURRENT_ARCH  : The target architecture to keep (e.g. "arm")
#   DEBUG         : (Optional) Set to TRUE to print decision logic for every file
# ==============================================================================
function(collect_sources_filtered)
    set(oneValueArgs
        VAR
        ROOT
        ARCH_DIR
        CURRENT_ARCH
        DEBUG
    )
    cmake_parse_arguments(ARG "" "${oneValueArgs}" "" ${ARGN})

    if(NOT ARG_VAR OR NOT ARG_ROOT OR NOT ARG_ARCH_DIR OR NOT ARG_CURRENT_ARCH)
        message(FATAL_ERROR "collect_sources_filtered: Missing arguments.")
    endif()

    get_filename_component(ROOT_ABS "${ARG_ROOT}" ABSOLUTE)
    file(TO_CMAKE_PATH "${ROOT_ABS}" ROOT_NORM)

    set(ARCH_BASE_PATH "${ROOT_NORM}/${ARG_ARCH_DIR}/")
    set(TARGET_ARCH_PATH "${ROOT_NORM}/${ARG_ARCH_DIR}/${ARG_CURRENT_ARCH}/")

    if(ARG_DEBUG)
        message(STATUS "---------------------------------------------------")
        message(STATUS "Filtering Sources")
        message(STATUS "  Root:        ${ROOT_NORM}")
        message(STATUS "  Arch Folder: ${ARCH_BASE_PATH}")
        message(STATUS "  Keep Arch:   ${TARGET_ARCH_PATH}")
        message(STATUS "---------------------------------------------------")
    endif()

    file(
        GLOB_RECURSE FOUND_SOURCES
        CONFIGURE_DEPENDS
        "${ROOT_NORM}/*.c"
        "${ROOT_NORM}/*.cpp"
        "${ROOT_NORM}/*.s"
        "${ROOT_NORM}/*.S"
        "${ROOT_NORM}/*.h"
        "${ROOT_NORM}/*.hpp"
    )

    set(FINAL_LIST "")

    foreach(RAW_FILE ${FOUND_SOURCES})
        file(TO_CMAKE_PATH "${RAW_FILE}" FILE_NORM)

        string(FIND "${FILE_NORM}" "${ARCH_BASE_PATH}" IS_IN_ARCH_FOLDER)

        if(IS_IN_ARCH_FOLDER EQUAL 0)
            string(FIND "${FILE_NORM}" "${TARGET_ARCH_PATH}" IS_TARGET_ARCH)

            if(IS_TARGET_ARCH EQUAL 0)
                if(ARG_DEBUG)
                    message(STATUS "[KEEP]  ${FILE_NORM} (Matched Target Arch)")
                endif()
                list(APPEND FINAL_LIST "${FILE_NORM}")
            else()
                if(ARG_DEBUG)
                    message(STATUS "[DROP]  ${FILE_NORM} (Wrong Arch)")
                endif()
            endif()
        else()
            if(ARG_DEBUG)
                message(STATUS "[KEEP]  ${FILE_NORM} (Common Code)")
            endif()

            list(APPEND FINAL_LIST "${FILE_NORM}")
        endif()
    endforeach()

    set(${ARG_VAR} ${FINAL_LIST} PARENT_SCOPE)
endfunction()
