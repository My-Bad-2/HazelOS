#ifndef KERNEL_CORE_ERRORS_H
#define KERNEL_CORE_ERRORS_H 1

#define ERR_OK (0)

#define ERR_PERM    (-1)   // Operation not permitted
#define ERR_NO_ENT  (-2)   // No such file or directory
#define ERR_SRCH    (-3)   // No such process
#define ERR_INTR    (-4)   // Interrupted system call
#define ERR_IO      (-5)   // I/O error
#define ERR_NXIO    (-6)   // No such device or address
#define ERR_2BIG    (-7)   // Argument list too long
#define ERR_NO_EXEC (-8)   // Exec format error
#define ERR_BAD_F   (-9)   // Bad file number
#define ERR_CHILD   (-10)  // No child processes
#define ERR_AGAIN   (-11)  // Try again / Would block

#define ERR_NO_MEM      (-12)  // Out of memory
#define ERR_DENIED      (-13)  // Permission denied
#define ERR_FAULT       (-14)  // Bad address/Page fault
#define ERR_NOT_BLK     (-15)  // Block device required
#define ERR_BUSY        (-16)  // Device or resource busy
#define ERR_EXIST       (-17)  // File exists
#define ERR_XDEV        (-18)  // Cross-device link
#define ERR_NO_DEV      (-19)  // No such device
#define ERR_NOT_DIR     (-20)  // Not a directory
#define ERR_IS_DIR      (-21)  // Is a directory
#define ERR_INVALID     (-22)  // Invalid argument
#define ERR_FILE_TABLE  (-23)  // File table overflow
#define ERR_MFILE       (-24)  // Too many open files
#define ERR_NOT_TTY     (-25)  // Not a typewriter
#define ERR_TXT_BSY     (-26)  // Text file busy
#define ERR_F_BIG       (-27)  // File too large
#define ERR_NO_SPC      (-28)  // No space left on device
#define ERR_PIPE        (-29)  // Illegal seek / Broken pipe (ESPIPE/EPIPE)
#define ERR_ROFS        (-30)  // Read-only file system
#define ERR_M_LINK      (-31)  // Too many links
#define ERR_PIPE_BROKEN (-32)  // Broken pipe
#define ERR_NO_SYS      (-38)  // Function not implemented
#define ERR_BAD_MSG     (-74)  // Not a data message
#define ERR_OVERFLOW    (-75)  // Value too large for defined data type

// User Requested Network/Timeout Errors
#define ERR_TIMEOUT      (-110)  // Connection/Operation timed out
#define ERR_CONN_REFUSED (-111)  // Connection refused
#define ERR_HOST_UNREACH (-113)  // No route to host

#define ERR_INVALID_CAP (-200)  // Capability slot is empty, invalid, or forged

// Capability Management
#define ERR_CAP_REVOKED   (-201)  // Capability was revoked by its parent
#define ERR_CAP_EXHAUSTED (-202)  // Kernel capability space  exhausted
#define ERR_CAP_NOT_DERIV (-203)  // Missing derivation rights for capability
#define ERR_CAP_NO_SYS    (-204)  // Capability does not map to a valid syscall

// Inter-Process Communication
#define ERR_IPC_ABORTED     (-210)  // IPC operation aborted by kernel or thread kill
#define ERR_IPC_RCV_TIMEOUT (-211)  // Receiver blocked past timeout
#define ERR_IPC_SND_TIMEOUT (-212)  // Sender blocked past timeout
#define ERR_IPC_TRUNCATED   (-213)  // IPC message truncated (buffer too small)
#define ERR_IPC_DISCONNECT  (-214)  // IPC endpoint disconnected or destroyed

// Scheduling / Resource Allocation
#define ERR_QUOTA_EXCEEDED  (-220)  // CPU time or memory quota exceeded
#define ERR_THREAD_DETACHED (-221)  // Operation requires a joinable thread
#define ERR_BAD_SYSCALL     (-222)  // Sycall trapped, but unimplemented/invalid
#define ERR_HW_UNSUPP       (-223)  // Hardware feature unsupported by kernel

#endif