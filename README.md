# Hazel

A Work-In-Progress kernel.

## Prerequisites
Before building and running this project, ensure you have the following tools installed on your system:

### Build Tools
- **CMAKE (Version 3.21 or newer)**
- **Make**

### Compilers
- **Clang/LLVM** (Required for `x86_64-clang*` presets. Ensure you have the `x86_64` target support enabled)
- **GCC Cross-Compiler** (Required ONLY for `x86_64-gcc*` presets. System GCC usually targets the host OS, which is unsuitable for kernel development. You must build a specific cross-compiler)

### Packing Utilities
- **Xorriso**

### Emulation (Optional, for testing)
- **QEMU**

## Build Configuration
This project uses CMake Presets to manage build configurations. The following presents are available:

### Clang Presets (Recommended)
Standard presets using the host Clang compiler.
| Preset Name | Configuration Type |Description |
| :--- | :--- | :--- |
| `x86_64-clang` | RelWithDebInfo | The standard build configuration. Good for general testing |
| `x86_64-clang-debug` | Debug | **Recommended for development.** Includes full debug symbols and disables optimizations. |
| `x86_64-clang-minsize` | MinSizeRel | Optimizes heavily for the smallest possible binary size (`-Os`). |
| `x86_64-clang-release` | Release | Optimizes heavily for speed (`-O3`) and strips debug symbols. Use this for performance benchmarks. |

### GCC Presets
Standard presets using a GCC Cross-Compiler.
> **⚠️ Important Note:** To use these presets, you must compile and install a GCC cross-compiler for x86_64. The standard system GCC will not work. 
> 
> Please follow the instructions here: [OSDev Wiki: GCC Cross-Compiler](https://osdev.wiki/wiki/GCC_Cross-Compiler)

| Preset Name | Configuration Type |Description |
| :--- | :--- | :--- |
| `x86_64-gcc` | RelWithDebInfo | The standard build configuration. Good for general testing |
| `x86_64-gcc-debug` | Debug | **Recommended for development.** Includes full debug symbols and disables optimizations. |
| `x86_64-gcc-minsize` | MinSizeRel | Optimizes heavily for the smallest possible binary size (`-Os`). |
| `x86_64-gcc-release` | Release | Optimizes heavily for speed (`-O3`) and strips debug symbols. Use this for performance benchmarks. |

## Building the Kernel
Follow these steps to configure and build the bootable ISO.

1. **Configure the Project**
    Run CMake from the project root directory using one of the above listed presents
    *Example (using the default preset):*
    ```shell
    cmake --preset x86_64-clang
    ```
2. **Build and Package**
    After configuration, CMake creates a build directory specific to your chosen preset (e.g., `build/x86_64-clang`). You must navigate into this directory to run the build commands.
    1. **Enter the build directory:**
        ```shell
        # Replace `x86_64-clang` with the name of the present you used above
        cd build/x86_64-clang
        ```
    2. **Compile the source code:** This compiles the kernel object files, links the final executable and copy it to ISO root directory.
        ```shell
        make
        ```
    3. **Install the Bootloader:** This copies the necessary Limine bootloader binaries to the ISO root directory.
        ```shell
        make install_limine
        ```
    4. **Generate the ISO:** This uses `xorriso` to pack the kernel and bootloader into a disk image (`image.iso`).
        ```shell
        make iso
        ```
    5. **Patch the ISO:** This final step applies necessary patches to the ISO to ensure it is bootable on both BIOS and UEFI systems.
        ```shell
        make patch_limine
        ```

## Running and Debugging
### Standard Run Mode
To run the kernel with hardware acceleration (KVM/HVF/WHPX) enabled for better performance:
```shell
make run
```
### Debug Mode
To run the kernel in debug mode. This disables hardware acceleration (to allow software breakpoints) and freezes the CPU at startup, waiting for a GDB/LLDB debugger to connect:
```shell
make debug
```

## Acknowledgments
We gratefully acknowledge the developers of the following third-party libraries and tools used in this project:

| Library/Tool | Repository/Link |
| :--- | :--- |
| **Limine Bootloader** | https://codeberg.org/Limine/Limine | 
| **LLVM C Library** | https://github.com/llvm/llvm-project |
| **uACPI** | https://github.com/uACPI/uACPI |

## Licensing
This project is Licensed under the **MIT License**. Please refer to the `LICENSE.md` file in the root directory for the full text.

**Third Party Licenses:** This project incorporates or links against third-party software. These components are subject to their own respective licenses which can typically be found in their source repositories.