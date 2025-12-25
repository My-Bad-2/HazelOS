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
    set(oneValueArgs VAR ROOT ARCH_DIR CURRENT_ARCH DEBUG)
    cmake_parse_arguments(ARG "" "${oneValueArgs}" "" ${ARGN})

    if(NOT ARG_VAR OR NOT ARG_ROOT OR NOT ARG_ARCH_DIR OR NOT ARG_CURRENT_ARCH)
        message(FATAL_ERROR "collect_sources_filtered: Missing arguments.")
    endif()

    # 1. Normalize Root Path (CRITICAL FIX)
    #    Resolves ../, symlinks, and converts Windows '\' to CMake '/'
    get_filename_component(ROOT_ABS "${ARG_ROOT}" ABSOLUTE)
    file(TO_CMAKE_PATH "${ROOT_ABS}" ROOT_NORM)

    # 2. Construct the "Gatekeeper" paths
    #    Note the trailing slash "/" to prevent partial matches (e.g. "arch" matching "archive")
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

    # 3. Find all files
    file(GLOB_RECURSE FOUND_SOURCES CONFIGURE_DEPENDS
        "${ROOT_NORM}/*.c" "${ROOT_NORM}/*.cpp" 
        "${ROOT_NORM}/*.s" "${ROOT_NORM}/*.S" 
        "${ROOT_NORM}/*.h" "${ROOT_NORM}/*.hpp"
    )

    set(FINAL_LIST "")

    # 4. Filter Logic
    foreach(RAW_FILE ${FOUND_SOURCES})
        
        # Normalize the individual file path so it matches the ROOT format
        file(TO_CMAKE_PATH "${RAW_FILE}" FILE_NORM)

        # Check: Is this file inside the 'arch' folder?
        # string(FIND <string> <substring> <output_variable>)
        # Returns 0 if FILE_NORM starts with ARCH_BASE_PATH
        string(FIND "${FILE_NORM}" "${ARCH_BASE_PATH}" IS_IN_ARCH_FOLDER)

        if(IS_IN_ARCH_FOLDER EQUAL 0)
            # It IS in the arch folder. Now check if it's the RIGHT arch.
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
            # It is NOT in the arch folder (Common code)
            if(ARG_DEBUG)
                message(STATUS "[KEEP]  ${FILE_NORM} (Common Code)")
            endif()
            list(APPEND FINAL_LIST "${FILE_NORM}")
        endif()

    endforeach()

    # 5. Return result
    set(${ARG_VAR} ${FINAL_LIST} PARENT_SCOPE)

endfunction()