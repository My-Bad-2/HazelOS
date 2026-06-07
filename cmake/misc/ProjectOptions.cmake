include_guard()

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

function(_hazel_pick_first_supported_std_flag lang out_var)
    set(_hazel_selected "")

    foreach(_hazel_flag IN LISTS ARGN)
        if("${_hazel_flag}" STREQUAL "")
            continue()
        endif()

        if("${lang}" STREQUAL "C")
            check_c_compiler_flag("${_hazel_flag}" _hazel_flag_supported)
        elseif("${lang}" STREQUAL "CXX")
            check_cxx_compiler_flag("${_hazel_flag}" _hazel_flag_supported)
        else()
            message(FATAL_ERROR "_hazel_pick_first_supported_std_flag: Unsupported lang '${lang}'.")
        endif()

        if(_hazel_flag_supported)
            set(_hazel_selected "${_hazel_flag}")
            break()
        endif()
    endforeach()

    set(${out_var} "${_hazel_selected}" PARENT_SCOPE)
endfunction()

function(project_apply_default_options)
    if(NOT CMAKE_CONFIGURATION_TYPES)
        if(NOT CMAKE_BUILD_TYPE)
            message(STATUS "Setting build type to 'RelWithDebInfo' as none was specified.")
            set(_hazel_build_type "RelWithDebInfo")
        else()
            set(_hazel_build_type "${CMAKE_BUILD_TYPE}")
        endif()

        set(CMAKE_BUILD_TYPE "${_hazel_build_type}" CACHE STRING "Choose Build Type" FORCE)
        set_property(
            CACHE CMAKE_BUILD_TYPE
            PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo"
        )
    endif()

    set(_hazel_architectures "x86_64")
    if(NOT DEFINED ${PROJECT_NAME}_ARCHITECTURE OR "${${PROJECT_NAME}_ARCHITECTURE}" STREQUAL "")
        message(STATUS "Setting Kernel Architecture to 'x86_64' as none was specified.")
        set(_hazel_architecture "x86_64")
    else()
        set(_hazel_architecture "${${PROJECT_NAME}_ARCHITECTURE}")
    endif()

    set(${PROJECT_NAME}_ARCHITECTURE
        "${_hazel_architecture}"
        CACHE STRING
        "Choose Kernel Architecture"
        FORCE
    )
    set_property(CACHE ${PROJECT_NAME}_ARCHITECTURE PROPERTY STRINGS ${_hazel_architectures})

    list(FIND _hazel_architectures "${${PROJECT_NAME}_ARCHITECTURE}" _hazel_arch_index)
    if(_hazel_arch_index EQUAL -1)
        message(
            FATAL_ERROR
            "Unsupported ${PROJECT_NAME} architecture '${${PROJECT_NAME}_ARCHITECTURE}'. Supported values: ${_hazel_architectures}"
        )
    endif()

    set(_hazel_limine_api_values
        "0"
        "1"
        "2"
        "3"
        "4"
        "5"
        "6"
    )
    if(
        NOT DEFINED ${PROJECT_NAME}_LIMINE_API_REV
        OR "${${PROJECT_NAME}_LIMINE_API_REV}" STREQUAL ""
    )
        message(STATUS "Setting Limine API Revision to '4' as none was specified.")
        set(_hazel_limine_api_rev "4")
    else()
        set(_hazel_limine_api_rev "${${PROJECT_NAME}_LIMINE_API_REV}")
    endif()

    set(${PROJECT_NAME}_LIMINE_API_REV
        "${_hazel_limine_api_rev}"
        CACHE STRING
        "Choose Limine API Revision"
        FORCE
    )
    set_property(CACHE ${PROJECT_NAME}_LIMINE_API_REV PROPERTY STRINGS ${_hazel_limine_api_values})

    list(FIND _hazel_limine_api_values "${${PROJECT_NAME}_LIMINE_API_REV}" _hazel_limine_api_index)
    if(_hazel_limine_api_index EQUAL -1)
        message(
            FATAL_ERROR
            "Unsupported Limine API revision '${${PROJECT_NAME}_LIMINE_API_REV}'. Supported values: ${_hazel_limine_api_values}"
        )
    endif()

    if(NOT DEFINED ${PROJECT_NAME}_MAX_CPUS OR "${${PROJECT_NAME}_MAX_CPUS}" STREQUAL "")
        set(_hazel_max_cpus "32")
    else()
        set(_hazel_max_cpus "${${PROJECT_NAME}_MAX_CPUS}")
    endif()

    if(NOT "${_hazel_max_cpus}" MATCHES "^[0-9]+$")
        message(
            FATAL_ERROR
            "Invalid ${PROJECT_NAME}_MAX_CPUS '${_hazel_max_cpus}'. Must be an integer in [1, 4294967295]."
        )
    endif()

    if(_hazel_max_cpus LESS 1 OR _hazel_max_cpus GREATER 4294967295)
        message(
            FATAL_ERROR
            "Invalid ${PROJECT_NAME}_MAX_CPUS '${_hazel_max_cpus}'. Must be an integer in [1, 4294967295]."
        )
    endif()

    set(${PROJECT_NAME}_MAX_CPUS
        "${_hazel_max_cpus}"
        CACHE STRING
        "Maximum supported CPU count (uint32_t)"
        FORCE
    )

    if(NOT DEFINED ${PROJECT_NAME}_QEMU_VNC)
        set(_hazel_qemu_vnc OFF)
    else()
        set(_hazel_qemu_vnc "${${PROJECT_NAME}_QEMU_VNC}")
    endif()

    set(${PROJECT_NAME}_QEMU_VNC
        "${_hazel_qemu_vnc}"
        CACHE BOOL
        "Enable QEMU VNC remote access"
        FORCE
    )

    if(NOT DEFINED ${PROJECT_NAME}_ENABLE_KASLR)
        set(_hazel_enable_kaslr ON)
    else()
        set(_hazel_enable_kaslr "${${PROJECT_NAME}_ENABLE_KASLR}")
    endif()

    set(${PROJECT_NAME}_ENABLE_KASLR
        "${_hazel_enable_kaslr}"
        CACHE BOOL
        "Enable kernel KASLR (PIE)"
        FORCE
    )
endfunction()

function(project_configure_language_standards)
    set(_hazel_c_std "${${PROJECT_NAME}_C_STD}")
    set(_hazel_cxx_std "${${PROJECT_NAME}_CXX_STD}")

    set(_hazel_c_std_flag "")
    set(_hazel_cxx_std_flag "")
    set(_hazel_need_c_flag OFF)
    set(_hazel_need_cxx_flag OFF)

    if(_hazel_c_std MATCHES "^[0-9]+$")
        if(_hazel_c_std LESS_EQUAL 23)
            set(CMAKE_C_STANDARD "${_hazel_c_std}" CACHE STRING "C standard" FORCE)
            set(CMAKE_C_STANDARD_REQUIRED ON)
            set(CMAKE_C_EXTENSIONS ON)
        else()
            set(_hazel_need_c_flag ON)
        endif()
    else()
        set(_hazel_need_c_flag ON)
    endif()

    if(_hazel_need_c_flag)
        if(_hazel_c_std MATCHES "^[0-9]+$")
            set(_hazel_c_std_lower "2y")
        else()
            string(TOLOWER "${_hazel_c_std}" _hazel_c_std_lower)
        endif()

        if(_hazel_c_std_lower STREQUAL "2y")
            _hazel_pick_first_supported_std_flag(
                "C"
                _hazel_c_std_flag
                "-std=gnu2y"
                "-std=gnu2x"
                "-std=gnu23"
            )
        elseif(_hazel_c_std_lower STREQUAL "2x")
            _hazel_pick_first_supported_std_flag(
                "C"
                _hazel_c_std_flag
                "-std=gnu2x"
                "-std=gnu23"
            )
        else()
            message(
                FATAL_ERROR
                "Unsupported C standard '${_hazel_c_std}'. Use a numeric value like 20/23 or 2Y/2X."
            )
        endif()

        if("${_hazel_c_std_flag}" STREQUAL "")
            message(
                FATAL_ERROR
                "Requested C standard '${_hazel_c_std}' is unsupported by ${CMAKE_C_COMPILER_ID}."
            )
        endif()

        message(STATUS "Using C standard flag: ${_hazel_c_std_flag}")
    endif()

    if(_hazel_cxx_std MATCHES "^[0-9]+$")
        if(_hazel_cxx_std LESS_EQUAL 26)
            set(CMAKE_CXX_STANDARD "${_hazel_cxx_std}" CACHE STRING "CXX standard" FORCE)
            set(CMAKE_CXX_STANDARD_REQUIRED ON)
            set(CMAKE_CXX_EXTENSIONS ON)
        else()
            set(_hazel_need_cxx_flag ON)
            set(_hazel_cxx_std_lower "2c")
        endif()
    else()
        set(_hazel_need_cxx_flag ON)
        string(TOLOWER "${_hazel_cxx_std}" _hazel_cxx_std_lower)
    endif()

    if(_hazel_need_cxx_flag)
        if(_hazel_cxx_std_lower STREQUAL "2c")
            _hazel_pick_first_supported_std_flag(
                "CXX"
                _hazel_cxx_std_flag
                "-std=gnu++2c"
                "-std=gnu++2b"
                "-std=gnu++23"
                "-std=gnu++20"
            )
        elseif(_hazel_cxx_std_lower STREQUAL "2b")
            _hazel_pick_first_supported_std_flag(
                "CXX"
                _hazel_cxx_std_flag
                "-std=gnu++2b"
                "-std=gnu++23"
                "-std=gnu++20"
            )
        else()
            message(
                FATAL_ERROR
                "Unsupported CXX standard '${_hazel_cxx_std}'. Use a numeric value like 20/23 or 2B/2C."
            )
        endif()

        if("${_hazel_cxx_std_flag}" STREQUAL "")
            message(
                FATAL_ERROR
                "Requested CXX standard '${_hazel_cxx_std}' is unsupported by ${CMAKE_CXX_COMPILER_ID}."
            )
        endif()

        message(STATUS "Using CXX standard flag: ${_hazel_cxx_std_flag}")
    endif()

    set(${PROJECT_NAME}_C_STD_FLAG
        "${_hazel_c_std_flag}"
        CACHE INTERNAL
        "Resolved C standard flag"
        FORCE
    )
    set(${PROJECT_NAME}_CXX_STD_FLAG
        "${_hazel_cxx_std_flag}"
        CACHE INTERNAL
        "Resolved CXX standard flag"
        FORCE
    )
endfunction()

function(project_append_compiler_diagnostic_flags)
    set(_hazel_cx_flags "${${PROJECT_NAME}_CX_FLAGS}")

    if(CMAKE_CXX_COMPILER_ID MATCHES ".*Clang")
        list(APPEND _hazel_cx_flags "-fcolor-diagnostics" "-fdiagnostics-show-option")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        list(APPEND _hazel_cx_flags "-fdiagnostics-color=always")
    else()
        message(
            STATUS
            "No colored compiler diagnostics set for '${CMAKE_CXX_COMPILER_ID}' compiler."
        )
    endif()

    list(REMOVE_DUPLICATES _hazel_cx_flags)
    set(${PROJECT_NAME}_CX_FLAGS "${_hazel_cx_flags}" PARENT_SCOPE)
endfunction()
