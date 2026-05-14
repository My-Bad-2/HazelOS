include_guard()

# Enable cache if available
function(project_enable_cache)
    set(_hazel_cache_option_values "auto" "ccache" "sccache" "none")

    set(${PROJECT_NAME}_COMPILER_CACHE
        "auto"
        CACHE STRING
        "Compiler cache to use (auto, ccache, sccache, none)"
    )
    set_property(
        CACHE ${PROJECT_NAME}_COMPILER_CACHE
        PROPERTY STRINGS ${_hazel_cache_option_values}
    )

    set(_hazel_cache_choice "${${PROJECT_NAME}_COMPILER_CACHE}")

    list(FIND _hazel_cache_option_values "${_hazel_cache_choice}" _hazel_cache_choice_index)
    if(_hazel_cache_choice_index EQUAL -1)
        message(
            FATAL_ERROR
            "Unsupported compiler cache '${_hazel_cache_choice}'. Supported values: ${_hazel_cache_option_values}"
        )
    endif()

    if(_hazel_cache_choice STREQUAL "none")
        message(STATUS "Compiler cache disabled.")
        return()
    endif()

    if(_hazel_cache_choice STREQUAL "auto")
        find_program(_hazel_cache_binary NAMES sccache ccache)
    else()
        find_program(_hazel_cache_binary NAMES ${_hazel_cache_choice})
    endif()

    if(_hazel_cache_binary)
        message(STATUS "Using compiler cache launcher: ${_hazel_cache_binary}")

        set(CMAKE_C_COMPILER_LAUNCHER
            ${_hazel_cache_binary}
            CACHE FILEPATH
            "C compiler cache launcher"
            FORCE
        )

        set(CMAKE_CXX_COMPILER_LAUNCHER
            ${_hazel_cache_binary}
            CACHE FILEPATH
            "CXX compiler cache launcher"
            FORCE
        )
    elseif(_hazel_cache_choice STREQUAL "auto")
        message(STATUS "No compiler cache launcher detected. Building without ccache/sccache.")
    else()
        message(
            WARNING
            "Requested compiler cache '${_hazel_cache_choice}' was not found. Building without compiler launcher."
        )
    endif()
endfunction()
