include("${CMAKE_CURRENT_LIST_DIR}/../cmake/misc/ComponentProject.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/../cmake/misc/AddSource.cmake")

hazel_component_project(NAME HazelCommon OUT_SUPERPROJECT_VAR HAZEL_COMMON_SUPERPROJECT)

set(_hazel_common_namespace "${HAZEL_COMMON_SUPERPROJECT}")

set(COMMON_CX_FLAGS "-fno-pic" "-fno-pie")
if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
else()
	list(APPEND COMMON_CX_FLAGS "-fno-omit-frame-pointer")
endif()

collect_sources_filtered(
	VAR COMMON_SOURCES
	ROOT ${CMAKE_CURRENT_SOURCE_DIR}/src
	ARCH_DIR arch
	CURRENT_ARCH ${${_hazel_common_namespace}_ARCHITECTURE}
	DEBUG OFF
)

add_library(common STATIC ${COMMON_SOURCES})

target_include_directories(common PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/arch/${${_hazel_common_namespace}_ARCHITECTURE}>
)

target_compile_definitions(common PRIVATE ${${_hazel_common_namespace}_CX_DEFINES})

target_apply_compile_settings(
	TARGET common
	LANG "C;ASM"
	FLAGS
		${${_hazel_common_namespace}_CX_FLAGS}
		${${_hazel_common_namespace}_KERNEL_CX_FLAGS}
		${COMMON_CX_FLAGS}
		${${_hazel_common_namespace}_CX_WARNING_FLAGS}
)

target_apply_compile_settings(
	TARGET common
	LANG "C"
	FLAGS
		${${_hazel_common_namespace}_C_FLAGS}
)

target_apply_compile_settings(
	TARGET common
	LANG "CXX"
	FLAGS
		${${_hazel_common_namespace}_CX_FLAGS}
		${${_hazel_common_namespace}_CXX_FLAGS}
		${${_hazel_common_namespace}_KERNEL_CX_FLAGS}
		${COMMON_CX_FLAGS}
		${${_hazel_common_namespace}_CX_WARNING_FLAGS}
		${${_hazel_common_namespace}_CXX_WARNING_FLAGS}
)

hazel_component_export_target(EXPORT_VAR HAZEL_COMMON_TARGET TARGET common)
