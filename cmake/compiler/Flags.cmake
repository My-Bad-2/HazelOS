include_guard()

set(
    ${PROJECT_NAME}_CX_WARNING_FLAGS
    # Disabled Warnings
	"-Wno-unknown-pragmas" # Some compilers complain about our use of #pragma mark
	"-Wno-c++98-compat"
	"-Wno-c++98-compat-pedantic"
	"-Wno-padded"
	"-Wno-covered-switch-default"
	# Desired Warnings
	"-Wfloat-equal"
	"-Wconversion"
	"-Wlogical-op"
	"-Wundef"
	"-Wredundant-decls"
	"-Wshadow"
	"-Wstrict-overflow=2"
	"-Wwrite-strings"
	"-Wpointer-arith"
	"-Wcast-qual"
	"-Wformat=2"
	"-Wformat-truncation"
	"-Wmissing-include-dirs"
	"-Wcast-align"
	"-Wswitch-enum"
	"-Wsign-conversion"
	"-Wdisabled-optimization"
	"-Winvalid-pch"
	"-Wmissing-declarations"
	"-Wdouble-promotion"
	"-Wshadow"
	"-Wtrampolines"
	"-Wvector-operation-performance"
	"-Wshift-overflow=2"
	"-Wnull-dereference"
	"-Wduplicated-cond"
	"-Wshift-overflow=2"
	"-Wnull-dereference"
	"-Wduplicated-cond"
	"-Wcast-align=strict"
)

set(
    ${PROJECT_NAME}_CXX_WARNING_FLAGS
    "-Wold-style-cast"
	# "-Wnon-virtual-dtor"
	"-Wctor-dtor-privacy"
	"-Woverloaded-virtual"
	"-Wnoexcept"
	"-Wstrict-null-sentinel"
	"-Wuseless-cast"
	"-Wzero-as-null-pointer-constant"
	"-Wextra-semi"
)

set(
    ${PROJECT_NAME}_CX_FLAGS
    "-ffreestanding"
    # "-nostdinc"
	"-nostdlib"
    "-fno-stack-protector"
    "-fstrict-vtable-pointers"
    "-funsigned-char"
    "-mgeneral-regs-only"
    "-mno-red-zone"
	"-static"
)

set(
    ${PROJECT_NAME}_CXX_FLAGS
    "-fno-rtti"
    "-fno-exceptions"
    "-fsized-deallocation"
    "-fcheck-new"
)

set(
    ${PROJECT_NAME}_LINK_FLAGS
	"-ffreestanding"
    "-Wl,--gc-sections"
    "-Wl,-static"
    "-Wl,-znoexecstack"
    "-Wl,-zmax-page-size=0x1000"
)

set(
	${PROJECT_NAME}_CX_DEFINES
	"-DLIMINE_API_REVISION=${${PROJECT_NAME}_LIMINE_API_REV}"
)

if(CMAKE_BUILD_TYPE MATCHES "^(Debug|ReleaseDbg)$")
	list(
		APPEND
		${PROJECT_NAME}_CX_DEFINES
		"-DNOISE_DEBUG=1"
	)
else()
	list(
		APPEND
		${PROJECT_NAME}_CX_DEFINES
		"-DNOISE_DEBUG=0"
		"-DNDEBUG=1"
	)
endif()

if(${PROJECT_NAME}_ARCHITECTURE STREQUAL "x86_64")
	list(
		APPEND
		${PROJECT_NAME}_CX_FLAGS
		"-march=x86-64"
        "-mno-red-zone"
        "-mno-mmx"
        "-mno-sse"
        "-mno-sse2"
        "-mno-80387"
        "-mno-x87"
        "-mcmodel=kernel"
		"-mstack-alignment=8"
	)

	list(
		APPEND
		${PROJECT_NAME}_CX_DEFINES
		"-DKSTACK_SIZE=0x2000"
		"-DUSTACK_SIZE=0x4000"
		"-DCACHE_LINE_SIZE=64"
	)
else()
	message(FATAL_ERROR "Unsupported ${PROJECT_NAME} Architecture: '${${PROJECT_NAME}_ARCHITECTURE}'")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
	list(
		APPEND
		${PROJECT_NAME}_LINK_FLAGS
		"-Wl,--strip-debug"
	)
endif()

set(
	XORRISO_FLAGS
	-as mkisofs
	-R -r
	-J
	-b boot/limine/limine-bios-cd.bin
	-no-emul-boot
	-boot-load-size 4
	-boot-info-table
	-hfsplus
	-apm-block-size 2048
	--efi-boot boot/limine/limine-uefi-cd.bin
	-efi-boot-part
	--efi-boot-image
	--protective-msdos-label
)

set(QEMU_LOGFILE "${CMAKE_BINARY_DIR}/qemu-logs.txt")

set(
	QEMU_COMMON_FLAGS
	-m 512M
	-no-reboot
	-no-shutdown
	-serial stdio
	-rtc base=localtime
	-boot order=d,menu=on,splash-time=0	
	-smp 2
)

if(${PROJECT_NAME}_ARCHITECTURE STREQUAL "x86_64")
	list(
		APPEND
		QEMU_COMMON_FLAGS
		-M q35,smm=off
	)
endif()

if(${PROJECT_NAME}_QEMU_VNC)
	list(APPEND QEMU_COMMON_FLAGS -vnc 127.0.0.1:1)
endif()

set(
	QEMU_DEBUG_FLAGS
	-d int # Log CPU Interrupts
	# -d guest_errors # Log when OS accesses invalid hardware addresses
	-D ${QEMU_LOGFILE}
	-S # Freeze CU at startup (wait for 'c' command in Debugger)
	-s # Short for `-gdb tcp::1234`
)

if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Linux")
	set(QEMU_HARDWARE_ACCEL_FLAGS -enable-kvm -cpu max)
elseif(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Darwin")
	set(QEMU_HARDWARE_ACCEL_FLAGS -accel hvf -cpu host)
elseif(${CMAKE_HOST_SYSTEM} STREQUAL "Windows")
	set(QEMU_HARDWARE_ACCEL_FLAGS -accel whpx)
else()
	set(QEMU_HARDWARE_ACCEL_FLAGS "")
endif()