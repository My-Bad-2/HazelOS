include_guard()

include(CheckLinkerFlag)
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CMakeParseArguments)

# ==============================================================================
# Function: target_apply_linker_settings
# Description: Applies linker flags. Can optionally SKIP checks for flags
#              that break standard linking (like -nostdlib).
#
# Arguments:
#   TARGET     (Required) : The target name
#   FLAGS      (Optional) : List of linker flags
#   SCRIPT     (Optional) : Path to linker script
#   LANG       (Optional) : Language for checking (default: C)
#   SCOPE      (Optional) : PRIVATE/PUBLIC/INTERFACE (default: PRIVATE)
#   SKIP_CHECK (Optional) : Boolean. If TRUE, applies flags without checking.
# ==============================================================================
function(target_apply_linker_settings)
    set(options SKIP_CHECK)
    set(oneValueArgs TARGET SCRIPT LANG SCOPE)
    set(multiValueArgs FLAGS)
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT ARG_TARGET)
        message(FATAL_ERROR "target_apply_linker_settings: TARGET argument is required.")
    endif()
    if(NOT ARG_LANG)
        set(ARG_LANG "C")
    endif()
    if(NOT ARG_SCOPE)
        set(ARG_SCOPE "PRIVATE")
    endif()

    # --- 1. Process Flags ---
    foreach(FLAG IN LISTS ARG_FLAGS)
        
        if(ARG_SKIP_CHECK)
            # FORCE MODE: Apply blindly
            # Useful for -nostdlib, -static, etc.
            message(STATUS "Linker flag applied (Unchecked): ${FLAG}")
            target_link_options(${ARG_TARGET} ${ARG_SCOPE} "SHELL:${FLAG}")
        
        else()
            # CHECK MODE: Verify before applying
            string(REGEX REPLACE "[^a-zA-Z0-9_+=.-]" "_" SAFE_FLAG_NAME "${FLAG}")
            set(CHECK_VAR "LINKER_SUPPORTS_${ARG_LANG}_${SAFE_FLAG_NAME}")

            check_linker_flag(${ARG_LANG} "${FLAG}" ${CHECK_VAR})

            if(${${CHECK_VAR}})
                target_link_options(${ARG_TARGET} ${ARG_SCOPE} "SHELL:${FLAG}")
            endif()
        endif()

    endforeach()

    # --- 2. Process Linker Script ---
    if(ARG_SCRIPT)
        get_filename_component(SCRIPT_ABS_PATH "${ARG_SCRIPT}" ABSOLUTE)
        if(EXISTS "${SCRIPT_ABS_PATH}")
            message(STATUS "Applying Linker Script: ${SCRIPT_ABS_PATH}")
            target_link_options(${ARG_TARGET} ${ARG_SCOPE} "-T${SCRIPT_ABS_PATH}")
            set_target_properties(${ARG_TARGET} PROPERTIES LINK_DEPENDS "${SCRIPT_ABS_PATH}")
        else()
            message(FATAL_ERROR "Linker script not found at: ${SCRIPT_ABS_PATH}")
        endif()
    endif()
endfunction()

# ==============================================================================
# Function: target_apply_compile_settings
# Description: Checks and applies compiler flags specific to languages.
#              Supports applying to multiple languages at once (e.g. C;CXX).
#
# Arguments:
#   TARGET (Required) : The target name
#   FLAGS  (Optional) : List of flags
#   LANG   (Optional) : List of languages to apply to (default: C)
#                       Example: "C;CXX"
#   SCOPE  (Optional) : PRIVATE, PUBLIC, or INTERFACE (default: PRIVATE)
# ==============================================================================
function(target_apply_compile_settings)
    set(options "")
    set(oneValueArgs TARGET SCOPE)
    set(multiValueArgs FLAGS LANG)
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT ARG_TARGET)
        message(FATAL_ERROR "target_apply_compile_settings: TARGET argument is required.")
    endif()

    if(NOT ARG_LANG)
        set(ARG_LANG "C")
    endif()

    if(NOT ARG_SCOPE)
        set(ARG_SCOPE "PRIVATE")
    endif()

    # Iterate over every language requested (e.g. C, then CXX)
    foreach(LANG_ITr IN LISTS ARG_LANG)
        
        foreach(FLAG IN LISTS ARG_FLAGS)
            # Unique variable: COMPILER_SUPPORTS_CXX_-Wall, etc.
            string(REGEX REPLACE "[^a-zA-Z0-9_+=.-]" "_" SAFE_FLAG_NAME "${FLAG}")
            set(CHECK_VAR "COMPILER_SUPPORTS_${LANG_ITr}_${SAFE_FLAG_NAME}")

            # 1. Check
            if(LANG_ITr STREQUAL "C")
                check_c_compiler_flag("${FLAG}" ${CHECK_VAR})
            elseif(LANG_ITr STREQUAL "CXX")
                check_cxx_compiler_flag("${FLAG}" ${CHECK_VAR})
            elseif(LANG_ITr STREQUAL "ASM")
                # CMake has no check_asm_compiler_flag built-in usually, assume TRUE or skip
                check_c_compiler_flag("${FLAG}" ${CHECK_VAR})
                # set(${CHECK_VAR} TRUE)
            else()
                message(WARNING "Unsupported LANG '${LANG_ITr}'")
                continue()
            endif()

            # 2. Apply with Guard
            # This ensures -std=c99 is NOT passed to C++ files, and -fno-rtti is NOT passed to C files.
            if(${${CHECK_VAR}})
                target_compile_options(${ARG_TARGET} ${ARG_SCOPE}
                    "$<$<COMPILE_LANGUAGE:${LANG_ITr}>:${FLAG}>"
                )
            endif()
        endforeach()
        
    endforeach()
endfunction()