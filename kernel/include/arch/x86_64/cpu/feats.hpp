#include <utility>
#ifndef KERNEL_ARCH_CPU_FEATS_HPP
#define KERNEL_ARCH_CPU_FEATS_HPP 1

#include <array>
#include <cstdint>
#include <span>
#include <string_view>

#include "compiler.h"

namespace kernel {
namespace x86_64 {
namespace cpu {
struct CpuidRegs {
  std::uint32_t eax, ebx, ecx, edx;
};

enum class TargetRegister : std::uint8_t { EAX, EBX, ECX, EDX };

struct FeatureCoordinate {
  std::uint32_t leaf;
  std::uint32_t subleaf;
  TargetRegister reg;
  std::uint8_t bit;
};

enum class CpuFeature : std::uint16_t {
  // Leaf 1, EDX: Standard Features
  FPU   = 0,   // Floating Point Unit On-Chip
  VME   = 1,   // Virtual 8086 Mode Extensions
  DE    = 2,   // Debugging Extensions
  PSE   = 3,   // Page Size Extension (4MB pages)
  TSC   = 4,   // Time Stamp Counter
  MSR   = 5,   // Model Specific Registers
  PAE   = 6,   // Physical Address Extension
  MCE   = 7,   // Machine-Check Exception
  CX8   = 8,   // CMPXCHG8B Instruction
  APIC  = 9,   // APIC On-Chip
  SEP   = 11,  // SYSENTER/SYSEXIT instructions
  MTRR  = 12,  // Memory Type Range Registers
  PGE   = 13,  // Page Global Bit
  MCA   = 14,  // Machine-Check Architecture
  CMOV  = 15,  // Conditional Move Instruction
  PAT   = 16,  // Page Attribute Table
  PSE36 = 17,  // 36-bit Page Size Extension
  PSN   = 18,  // Processor Serial Number
  CLFSH = 19,  // CLFLUSH Instruction
  DS    = 21,  // Debug Store
  ACPI  = 22,  // Thermal Monitor and Software Controlled Clock Facilities
  MMX   = 23,  // MMX Technology
  FXSR  = 24,  // FXSAVE and FXRSTOR Instructions
  SSE   = 25,  // Streaming SIMD Extensions
  SSE2  = 26,  // Streaming SIMD Extensions 2
  SS    = 27,  // Self Snoop
  HTT   = 28,  // Max APIC IDs reserved field is Valid (Hyper-Threading)
  TM    = 29,  // Thermal Monitor
  IA64  = 30,  // IA-64 processor (Itanium)
  PBE   = 31,  // Pending Break Enable

  // Leaf 1, ECX: Standard Features
  SSE3       = 32 + 0,   // Streaming SIMD Extensions 3
  PCLMULQDQ  = 32 + 1,   // PCLMULQDQ Instruction
  DTES64     = 32 + 2,   // 64-bit DS Area
  MONITOR    = 32 + 3,   // MONITOR/MWAIT Instructions
  DS_CPL     = 32 + 4,   // CPL Qualified Debug Store
  VMX        = 32 + 5,   // Virtual Machine Extensions (Intel VT-x)
  SMX        = 32 + 6,   // Safer Mode Extensions (Intel TXT)
  EST        = 32 + 7,   // Enhanced Intel SpeedStep Technology
  TM2        = 32 + 8,   // Thermal Monitor 2
  SSSE3      = 32 + 9,   // Supplemental Streaming SIMD Extensions 3
  CNXT_ID    = 32 + 10,  // L1 Context ID
  SDBG       = 32 + 11,  // Silicon Debug
  FMA        = 32 + 12,  // Fused Multiply-Add
  CX16       = 32 + 13,  // CMPXCHG16B Instruction
  XTPR       = 32 + 14,  // xTPR Update Control
  PDCM       = 32 + 15,  // Perfmon and Debug Capability
  PCID       = 32 + 17,  // Process-Context Identifiers
  DCA        = 32 + 18,  // Direct Cache Access
  SSE4_1     = 32 + 19,  // Streaming SIMD Extensions 4.1
  SSE4_2     = 32 + 20,  // Streaming SIMD Extensions 4.2
  X2APIC     = 32 + 21,  // x2APIC Support
  MOVBE      = 32 + 22,  // MOVBE Instruction
  POPCNT     = 32 + 23,  // POPCNT Instruction
  TSC_DEAD   = 32 + 24,  // TSC-Deadline
  AES        = 32 + 25,  // AESNI Instructions
  XSAVE      = 32 + 26,  // XSAVE/XRSTOR/XSETBV/XGETBV
  OSXSAVE    = 32 + 27,  // XSAVE enabled by OS
  AVX        = 32 + 28,  // Advanced Vector Extensions
  F16C       = 32 + 29,  // 16-bit FP Conversion Instructions
  RDRND      = 32 + 30,  // RDRAND Instruction
  HYPERVISOR = 32 + 31,  // Running on a Hypervisor (Always 0 on bare metal)

  // Leaf 7, Subleaf 0, EBX
  FSGSBASE  = 64 + 0,   // RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE
  TSC_ADJ   = 64 + 1,   // IA32_TSC_ADJUST MSR
  SGX       = 64 + 2,   // Software Guard Extensions
  BMI1      = 64 + 3,   // Bit Manipulation Instruction Set 1
  HLE       = 64 + 4,   // Hardware Lock Elision (Transactional Synchronization)
  AVX2      = 64 + 5,   // Advanced Vector Extensions 2
  FDP_EXCPT = 64 + 6,   // FDP_EXCPTN_ONLY
  SMEP      = 64 + 7,   // Supervisor-Mode Execution Prevention
  BMI2      = 64 + 8,   // Bit Manipulation Instruction Set 2
  ERMS      = 64 + 9,   // Enhanced REP MOVSB/STOSB
  INVPCID   = 64 + 10,  // INVPCID Instruction
  RTM       = 64 + 11,  // Restricted Transactional Memory
  PQM       = 64 + 12,  // Platform Quality of Service Monitoring
  MPX       = 64 + 14,  // Memory Protection Extensions
  PQE       = 64 + 15,  // Platform Quality of Service Enforcement
  AVX512_F  = 64 + 16,  // AVX-512 Foundation
  AVX512_DQ = 64 + 17,  // AVX-512 Doubleword and Quadword Instructions
  RDSEED    = 64 + 18,  // RDSEED Instruction
  ADX       = 64 + 19,  // Multi-Precision Add-Carry Instruction Extensions
  SMAP      = 64 + 20,  // Supervisor-Mode Access Prevention
  AVX512_IFMA = 64 + 21,  // AVX-512 Integer Fused Multiply-Add Instructions
  PCOMMIT     = 64 + 22,  // PCOMMIT Instruction
  CLFLUSHOPT  = 64 + 23,  // CLFLUSHOPT Instruction
  CLWB        = 64 + 24,  // CLWB Instruction
  PT          = 64 + 25,  // Intel Processor Trace
  AVX512_PF   = 64 + 26,  // AVX-512 Prefetch Instructions
  AVX512_ER   = 64 + 27,  // AVX-512 Exponential and Reciprocal Instructions
  AVX512_CD   = 64 + 28,  // AVX-512 Conflict Detection Instructions
  SHA         = 64 + 29,  // SHA Extensions
  AVX512_BW   = 64 + 30,  // AVX-512 Byte and Word Instructions
  AVX512_VL   = 64 + 31,  // AVX-512 Vector Length Extensions

  // Leaf 7, Subleaf 0, ECX
  PREFETCHWT1      = 96 + 0,   // PREFETCHWT1 Instruction
  AVX512_VBMI      = 96 + 1,   // AVX-512 Vector Bit Manipulation Instructions
  UMIP             = 96 + 2,   // User-Mode Instruction Prevention
  PKU              = 96 + 3,   // Protection Keys for User-Mode Pages
  OSPKE            = 96 + 4,   // OS Enable Protection Keys
  WAITPKG          = 96 + 5,   // UMONITOR/UMWAIT/TPAUSE
  AVX512_VBMI2     = 96 + 6,   // AVX-512 Vector Bit Manipulation Instructions 2
  CET_SS           = 96 + 7,   // CET Shadow Stack
  GFNI             = 96 + 8,   // Galois Field New Instructions
  VAES             = 96 + 9,   // Vector AES
  VPCLMULQDQ       = 96 + 10,  // Vector PCLMULQDQ
  AVX512_VNNI      = 96 + 11,  // AVX-512 Vector Neural Network Instructions
  AVX512_BITALG    = 96 + 12,  // AVX-512 BITALG Instructions
  TME_EN           = 96 + 13,  // Total Memory Encryption
  AVX512_VPOPCNTDQ = 96 + 14,  // AVX-512 VPOPCNTDQ Instruction
  LA57             = 96 + 16,  // 5-Level Paging
  RDPID            = 96 + 22,  // RDPID Instruction
  KL               = 96 + 23,  // Key Locker
  BUS_LOCK_DET     = 96 + 24,  // Bus Lock Debug Exception
  CLDEMOTE         = 96 + 25,  // Cache Line Demote
  MOVDIRI          = 96 + 27,  // MOVDIRI Instruction
  MOVDIR64B        = 96 + 28,  // MOVDIR64B Instruction
  ENQCMD           = 96 + 29,  // Enqueue Stores
  SGX_LC           = 96 + 30,  // SGX Launch Configuration
  PKS              = 96 + 31,  // Protection Keys for Supervisor-Mode Pages

  // Leaf 7, Subleaf 0, EDX
  AVX512_4VNNIW = 128 + 2,  // AVX-512 4-Register Neural Network Instructions
  AVX512_4FMAPS = 128 + 3,  // AVX-512 4-Register Multiply Accumulation
  FSRM          = 128 + 4,  // Fast Short REP MOVSB
  AVX512_VP2INTERSECT = 128 + 8,  // AVX-512 VP2INTERSECT
  SRBDS_CTRL = 128 + 9,  // Special Register Buffer Data Sampling Mitigations
  MD_CLEAR = 128 + 10,   // VERW Instruction Clears CPU Buffers (MDS Mitigation)
  RTM_ALWAYS_ABORT = 128 + 11,
  TSX_FORCE_ABORT  = 128 + 13,  // MSR_TSX_FORCE_ABORT available
  SERIALIZE        = 128 + 14,  // SERIALIZE Instruction
  HYBRID           = 128 + 15,  // Hybrid Processor (e.g., P-Cores and E-Cores)
  TSXLDTRK         = 128 + 16,  // TSX Suspend Load Address Tracking
  PCONFIG          = 128 + 18,  // PCONFIG Instruction
  LBR              = 128 + 19,  // Architectural Last Branch Records
  CET_IBT          = 128 + 20,  // CET Indirect Branch Tracking
  AMX_BF16         = 128 + 22,  // AMX BFLOAT16
  AVX512_FP16      = 128 + 23,  // AVX-512 FP16
  AMX_TILE         = 128 + 24,  // AMX Tile Architecture
  AMX_INT8         = 128 + 25,  // AMX 8-bit Integer
  SPEC_CTRL        = 128 + 26,  // Speculation Control (IBRS/IBPB)
  STIBP            = 128 + 27,  // Single Thread Indirect Branch Predictors
  L1D_FLUSH        = 128 + 28,  // IA32_FLUSH_CMD MSR
  ARCH_CAPS        = 128 + 29,  // IA32_ARCH_CAPABILITIES MSR
  CORE_CAPS        = 128 + 30,  // IA32_CORE_CAPABILITIES MSR
  SSBD             = 128 + 31,  // Speculative Store Bypass Disable

  // Leaf 7, Subleaf 1, EAX
  SHA512   = 160 + 0,   // SHA512 Instructions
  SM3      = 160 + 1,   // SM3 Instructions
  SM4      = 160 + 2,   // SM4 Instructions
  FRED     = 160 + 17,  // Flexible Return and Event Delivery
  LKGS     = 160 + 18,  // Load "KerneL" GS Base
  WRMSRNS  = 160 + 19,  // Non-Serializing WRMSR
  AMX_FP16 = 160 + 21,  // AMX FP16
  HRESET   = 160 + 22,  // HRESET Instruction
  AVX_IFMA = 160 + 23,  // AVX-IFMA Instructions

  // Leaf 0x80000001, EDX
  SYSCALL   = 192 + 11,  // SYSCALL/SYSRET Instructions
  NX        = 192 + 20,  // No-Execute Bit (XD Bit on Intel)
  MMXEXT    = 192 + 22,  // AMD MMX Extensions
  FXSR_OPT  = 192 + 25,  // FXSAVE/FXRSTOR Optimizations
  GIGAPAGE  = 192 + 26,  // 1GB Large Page Support
  RDTSCP    = 192 + 27,  // RDTSCP Instruction
  LM        = 192 + 29,  // Long Mode (64-bit support)
  _3DNOWEXT = 192 + 30,  // Extended 3DNow! (AMD)
  _3DNOW    = 192 + 31,  // 3DNow! (AMD)

  // Leaf 0x80000001, ECX
  LAHF_LM        = 224 + 0,   // LAHF/SAHF in Long Mode
  CMP_LEGACY     = 224 + 1,   // Core Multi-Processing Legacy Mode
  SVM            = 224 + 2,   // Secure Virtual Machine (AMD-V)
  EXTAPIC        = 224 + 3,   // Extended APIC Space
  CR8_LEGACY     = 224 + 4,   // CR8 in 32-bit mode
  ABM            = 224 + 5,   // Advanced Bit Manipulation (LZCNT)
  SSE4A          = 224 + 6,   // SSE4a (AMD)
  MISALIGNSSE    = 224 + 7,   // Misaligned SSE Mode
  _3DNOWPREFETCH = 224 + 8,   // PREFETCH and PREFETCHW
  OSVW           = 224 + 9,   // OS Visible Workaround
  IBS            = 224 + 10,  // Instruction Based Sampling
  XOP            = 224 + 11,  // eXtended Operations
  SKINIT         = 224 + 12,  // SKINIT/STGI Instructions
  WDT            = 224 + 13,  // Watchdog Timer
  LWP            = 224 + 15,  // Lightweight Profiling
  FMA4           = 224 + 16,  // 4-Operand FMA
  TCE            = 224 + 17,  // Translation Cache Extension
  NODEID_MSR     = 224 + 19,  // NodeId MSR
  TBM            = 224 + 21,  // Trailing Bit Manipulation
  TOPOEXT        = 224 + 22,  // Topology Extensions
  PERFCTR_CORE   = 224 + 23,  // Core Performance Counter Extensions
  PERFCTR_NB     = 224 + 24,  // NB Performance Counter Extensions

  // Leaf 0x80000007, EDX
  TSC_EXTENDED      = 256 + 0,  // TS3 Temperature Sensor
  FID               = 256 + 1,  // Frequency ID Control
  VID               = 256 + 2,  // Voltage ID Control
  TTP               = 256 + 3,  // THERMTRIP
  TM_AMD            = 256 + 4,  // AMD Thermal Hardware Control
  STC               = 256 + 5,  // Software Thermal Control
  _100MHzSteps      = 256 + 6,  // 100 MHz Multiplier Control
  HwpState          = 256 + 7,  // Hardware P-State Control
  TSC_INVARIANT     = 256 + 8,  // Invariant TSC (Always runs at constant rate!)
  CPB               = 256 + 9,  // Core Performance Boost
  EffFreqRO         = 256 + 10,  // Read-only Effective Frequency Interface
  PROC_FEEDBACK     = 256 + 11,  // Processor Feedback Interface
  PROC_POWER_REP    = 256 + 12,  // Processor Power Reporting
  CONNECTED_STANDBY = 256 + 13,  // Connected Standby
  RAPL              = 256 + 14,  // Running Average Power Limit

  COUNT = 288
};

enum class KvmFeature : std::uint8_t {
  CLOCK_SOURCE         = 0,   // KVM_FEATURE_CLOCKSOURCE
  CLOCK_SOURCE2        = 3,   // KVM_FEATURE_CLOCKSOURCE2
  ASYNC_PAGE_FAULT     = 4,   // KVM_FEATURE_ASYNC_PF
  STEAL_TIME           = 5,   // KVM_FEATURE_STEAL_TIME
  PV_END_OF_INTERRUPT  = 6,   // KVM_FEATURE_PV_EOI P
  PV_UNHALT            = 7,   // KVM_FEATURE_PV_UNHALT
  PV_TLB_FLUSH         = 9,   // KVM_FEATURE_PV_TLB_FLUSH
  ASYNC_PAGE_FAULT_INT = 14,  // KVM_FEATURE_ASYNC_PF_INT
  PV_SCHED_YIELD       = 13   // KVM_FEATURE_PV_SCHED_YIELD
};

enum class HyperVFeature : std::uint8_t {
  // Leaf 0x40000003 - EAX
  VP_RUNTIME            = 0,  // Partition Reference Counter
  TIME_REFERENCE_COUNT  = 1,  // SynIC timers available
  SYN_IC_AVAILABLE      = 2,  // Synthetic Interrupt Controller
  SYNTHETIC_TIMER       = 3,  // Synthetic Timers
  APIC_MSRS             = 4,  // APIC access via MSRs
  HYPERCALL_MSRS        = 5,  // Hypercall MSRs available
  ACCESS_VP_INDEX       = 6,  // VP Index MSR available
  VIRTUAL_REFERENCE_TSC = 9   // Invariant TSC reference
};

enum class HyperVEnlightenment : std::uint8_t {
  // Leaf 0x40000004 - EAX
  USE_HYPERCALL_FOR_AS_ADDRESS_SPACE_SWITCH = 0,
  USE_HYPERCALL_FOR_LOCAL_FLUSH             = 1,
  USE_HYPERCALL_FOR_REMOTE_FLUSH            = 2,
  USE_RELAXED_TIMING                        = 5,
  USE_EXPROCESSOR_MASKS                     = 11
};

enum class CacheType : std::uint8_t { Null, Data, Instruction, Unified };

enum class TopologyLevelType : std::uint8_t {
  Invalid = 0,
  Smt,      // Hyper-thread
  Core,     // Phys core
  Module,   // P-core / e-core clusters
  Tile,     // Silicon Tile
  Die,      // Silicon Die
  DieGrp,   // Die Group,
  Package,  // Physical Socket
};

enum class CpuVendor : std::uint8_t { UNKNOWN = 0, INTEL, AMD };

enum class Microarchitecture : std::uint8_t {
  UNKNOWN,
  INTEL_NEHALEM,       // 1st Gen Core
  INTEL_WESTMERE,      // 1st Gen Shrink
  INTEL_SANDY_BRIDGE,  // 2nd Gen
  INTEL_IVY_BRIDGE,    // 3rd Gen
  INTEL_HASWELL,       // 4th Gen
  INTEL_BROADWELL,     // 5th Gen
  INTEL_SKY_LAKE,      // 6th-10th Gen
  INTEL_ICE_LAKE,      // 10th Gen Mobile
  INTEL_TIGER_LAKE,    // 11th Gen
  INTEL_ALDER_LAKE,    // 12th Gen
  INTEL_RAPTOR_LAKE,   // 13th/14th Gen
  INTEL_METEOR_LAKE,   // Core ultra 1st gen
  INTEL_LUNAR_LAKE,    // Core Ultra 2nd Gen (Mobile - Skymont/Lion Cove)
  INTEL_ARROW_LAKE,    // Core Ultra 2nd Gen (Desktop/HX - Skymont/Lion Cove)

  AMD_PHENOM,     // Family 10h (2007-2011)
  AMD_BULLDOZER,  // Family 15h (Bulldozer/Piledriver/Excavator)
  AMD_ZEN1,       // Family 17h (Ryzen 1000/2000)
  AMD_ZEN2,       // Family 17h (Ryzen 3000/4000)
  AMD_ZEN3,       // Family 19h (Ryzen 5000/6000)
  AMD_ZEN4,       // Family 19h (Ryzen 7000/8000)
  AMD_ZEN5,       // Family 1Ah (Ryzen 9000)
};

struct ProcessorIdentity {
  std::uint32_t family{0};
  std::uint32_t model{0};
  std::uint32_t stepping{0};
  std::uint32_t processor_type{0};
  Microarchitecture microarch{Microarchitecture::UNKNOWN};
};

enum class HypervisorVendor : std::uint8_t {
  NONE,
  KVM,
  VMWARE,
  HYPERV,
  XEN,
  BHYVE,
  UNKNOWN
};

struct HypervisorState {
  bool is_virtualized{false};
  HypervisorVendor vendor{HypervisorVendor::NONE};
  std::uint32_t max_leaf{0};
  char signature[13]{0};

  std::uint32_t kvm_features{0};
  std::uint32_t hyperv_features{0};
  std::uint32_t hyperv_enlightenments{0};

  __nodiscard bool has_kvm_feature(KvmFeature feature) const noexcept {
    return kvm_features & (1u << std::to_underlying(feature));
  }

  __nodiscard bool has_hyperv_feature(HyperVFeature feature) const noexcept {
    return hyperv_features & (1u << std::to_underlying(feature));
  }

  __nodiscard bool has_hyperv_enlightenment(
      HyperVEnlightenment enlightenment
  ) const noexcept {
    return hyperv_enlightenments & (1u << std::to_underlying(enlightenment));
  }
};

struct CacheInfo {
  CacheType type{CacheType::Null};
  std::uint8_t level{0};
  std::uint32_t size_bytes{0};
  std::uint32_t ways_of_associativity{0};
  std::uint32_t line_size{0};
  std::uint32_t sets{0};
  bool is_fully_inclusive{false};
};

struct TopologyLevel {
  TopologyLevelType type{TopologyLevelType::Invalid};
  std::uint8_t shift_mask{0};
  std::uint32_t logical_processors{0};
};

struct AddressLimits {
  std::uint8_t physical_bits{0};  // e.g. 39, 48, 52
  std::uint8_t virtual_bits{0};   // e.g., 48, 57
};

struct Frequencies {
  std::uint32_t base_mhz{0};
  std::uint32_t max_mhz;
  std::uint32_t bus_mhz;
};

class ProcessorState {
 private:
  static constexpr std::size_t FEATURE_COUNT =
      static_cast<std::size_t>(CpuFeature::COUNT);
  static constexpr std::size_t FEATURE_BLOCKS = FEATURE_COUNT / 32;
  static constexpr std::size_t BITSET_WORDS   = (FEATURE_COUNT + 63) / 64;

  std::array<std::uint64_t, BITSET_WORDS> m_feature_bitset{false};

  std::array<char, 13> m_vendor_string{0};
  std::array<char, 49> m_brand_string{0};
  std::size_t m_brand_len{0};

  std::uint32_t m_max_basic_leaf{0};
  std::uint32_t m_max_extended_leaf{0};
  CpuVendor m_vendor{CpuVendor::UNKNOWN};
  std::uint32_t m_x2apic_id{0};

  AddressLimits m_address_limits{};
  Frequencies m_frequencies{};

  std::array<CacheInfo, 8> m_caches{};
  std::size_t m_cache_count{0};

  std::array<TopologyLevel, 8> m_topology_levels{};
  std::size_t m_topology_level_count{0};

  ProcessorIdentity m_identity{};
  HypervisorState m_hypervisor{};

  __nodiscard static inline std::uint32_t
  select_registers(const CpuidRegs& regs, TargetRegister r) noexcept {
    switch (r) {
      case TargetRegister::EAX:
        return regs.eax;
      case TargetRegister::EBX:
        return regs.ebx;
      case TargetRegister::ECX:
        return regs.ecx;
      case TargetRegister::EDX:
        return regs.edx;
    }
  }

  __nodiscard static constexpr FeatureCoordinate get_feature_coordinate(
      std::size_t index
  ) noexcept {
    // Every 32 features correspond to a new CPUID register block
    const std::size_t block = index / 32;
    const std::uint8_t bit  = static_cast<std::uint8_t>(index % 32);

    switch (block) {
      case 0:
        return {0x1, 0, TargetRegister::EDX, bit};
      case 1:
        return {0x1, 0, TargetRegister::ECX, bit};
      case 2:
        return {0x7, 0, TargetRegister::EBX, bit};
      case 3:
        return {0x7, 0, TargetRegister::ECX, bit};
      case 4:
        return {0x7, 0, TargetRegister::EDX, bit};
      case 5:
        return {0x7, 1, TargetRegister::EAX, bit};
      case 6:
        return {0x80000001, 0, TargetRegister::EDX, bit};
      case 7:
        return {0x80000001, 0, TargetRegister::ECX, bit};
      case 8:
        return {0x80000007, 0, TargetRegister::EDX, bit};
      default:
        return {0, 0, TargetRegister::EAX, 0};
    }
  }

  void fetch_vendor_and_max_leafs() noexcept;
  void fetch_brand_string() noexcept;
  void fetch_features() noexcept;
  void fetch_address_limits() noexcept;
  void fetch_extended_topology() noexcept;
  void fetch_cache_hierarchy() noexcept;
  void fetch_frequencies() noexcept;
  void fetch_identity_and_microarch() noexcept;
  void fetch_hypervisor() noexcept;

 public:
  ProcessorState() = default;

  void initialize() noexcept {
    fetch_vendor_and_max_leafs();
    fetch_brand_string();
    fetch_features();
    fetch_hypervisor();
    fetch_identity_and_microarch();

    fetch_address_limits();
    fetch_extended_topology();
    fetch_cache_hierarchy();
    fetch_frequencies();
  }

  __nodiscard static inline CpuidRegs
  call_cpuid(std::uint32_t leaf, std::uint32_t subleaf) noexcept {
    CpuidRegs regs{};
    asm volatile(
        "cpuid"
        : "=a"(regs.eax), "=b"(regs.ebx), "=c"(regs.ecx), "=d"(regs.edx)
        : "a"(leaf), "c"(subleaf)
        : "memory"
    );
    return regs;
  }

  __nodiscard bool has_feature(CpuFeature feature) const noexcept;

  __nodiscard CpuVendor vendor_id() const noexcept {
    return m_vendor;
  }

  __nodiscard std::string_view vendor_string() const noexcept {
    return {m_vendor_string.data(), 12};
  }

  __nodiscard std::string_view brand_string() const noexcept {
    return {m_brand_string.data(), m_brand_len};
  }

  __nodiscard const AddressLimits& limits() const noexcept {
    return m_address_limits;
  }

  __nodiscard const Frequencies& frequencies() const noexcept {
    return m_frequencies;
  }

  __nodiscard const HypervisorState& hypervisor() const noexcept {
    return m_hypervisor;
  }

  __nodiscard const ProcessorIdentity& identity() const noexcept {
    return m_identity;
  }

  __nodiscard std::uint32_t x2apic_id() const noexcept {
    return m_x2apic_id;
  }

  __nodiscard std::uint32_t max_leaf() const noexcept {
    return m_max_basic_leaf;
  }

  __nodiscard std::uint32_t max_extended_leaf() const noexcept {
    return m_max_extended_leaf;
  }

  __nodiscard std::span<const CacheInfo> caches() const noexcept {
    return {m_caches.data(), m_cache_count};
  }

  __nodiscard std::span<const TopologyLevel> topology_levels() const noexcept {
    return {m_topology_levels.data(), m_topology_level_count};
  }
};

ProcessorState& get_current_state() noexcept;
}  // namespace cpu
}  // namespace x86_64
}  // namespace kernel

#endif