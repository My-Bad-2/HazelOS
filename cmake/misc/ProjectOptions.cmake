include_guard()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to 'RelWithDebInfo' as none was specified.")
    set(
        CMAKE_BUILD_TYPE
        "RelWithDebInfo"
        CACHE STRING "Choose Build Type" FORCE
    )

    set_property(
        CACHE CMAKE_BUILD_TYPE
        PROPERTY STRINGS
        "Debug"
        "Release"
        "MinSizeRel"
        "RelWithDebInfo"
    )
endif()

if(NOT ${PROJECT_NAME}_ARCHITECTURE)
    message(STATUS "Setting Kernel Architecture to 'x86_64' as none was specified.")

    set(
        ${PROJECT_NAME}_ARCHITECTURE
        "x86_64"
        CACHE STRING "Choose Kernel Architecture" FORCE
    )

    set(${PROJECT_NAME}_ARCHITECTURES_LIST "x86_64")

    set_property(
        CACHE ${PROJECT_NAME}_ARCHITECTURE
        PROPERTY STRINGS
        ${PROJECT_NAME}_ARCHITECTURES_LIST
    )
endif()

if(NOT ${PROJECT_NAME}_LIMINE_API_REV)
    message(STATUS "Setting Limine API Revision to '4' as none was specified.")

    set(
        ${PROJECT_NAME}_ARCHITECTURE
        "4"
        CACHE STRING "Choose Kernel Architecture" FORCE
    )

    set_property(
        CACHE ${PROJECT_NAME}_ARCHITECTURE
        PROPERTY STRINGS
        "0" "1" "2" "3" "4"
    )
endif()

set(CMAKE_CXX_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_CXX_COMPILER_ID MATCHES ".*Clang")
    list(
        APPEND
        ${PROJECT_NAME}_CX_FLAGS
        "-fcolor-diagnostics"
        "-fdiagnostics-show-option"
    )
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    list(
        APPEND
        ${PROJECT_NAME}_CX_FLAGS
        "-fdiagnostics-color=always"
    )    
else()
    message(STATUS "No colored compiler diagnostic set for '${CMAKE_CXX_COMPILER_ID}' compiler.")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    list(
        APPEND
        ${PROJECT_NAME}_CX_FLAGS
        "-flto"
    )
endif()

if(NOT ${PROJECT_NAME}_QEMU_VNC)
    set(
        ${PROJECT_NAME}_QEMU_VNC
        OFF
        CACHE STRING "Enable QEMU Virtual Network Computing to provite remote access"
    )
endif()