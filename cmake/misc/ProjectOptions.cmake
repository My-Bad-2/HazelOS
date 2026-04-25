include_guard()

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
