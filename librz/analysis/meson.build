# To define a plugin add its name in `analysis_plugins` and define:
# - `analysis_<pluginName>_sources`: an array of source files
# - `analysis_<pluginName>_headers`: an array of include directories (optional)
# - `analysis_<pluginName>_deps`: an array of meson dependencies

analysis_plugins = [
  '6502',
  '8051',
  'amd29k',
  'arc',
  'arm_cs',
  'arm_gnu',
  'avr',
  'bf',
  'chip8',
  'cr16',
  'cris',
  'dalvik',
  'ebc',
  'gb',
  'h8300',
  'hexagon',
  'i4004',
  'i8080',
  'java',
  'm68k_cs',
  'm680x_cs',
  'malbolge',
  'mcore',
  'mips_cs',
  'mips_gnu',
  'msp430',
  'nios2',
  'null',
  'or1k',
  'pic',
  'ppc_cs',
  'ppc_gnu',
  'propeller',
  'pyc',
  'riscv',
  'rsp',
  'sh',
  'snes',
  'sparc_cs',
  'sparc_gnu',
  'spc700',
  'sysz',
  'tms320',
  'tricore',
  'v810',
  'v850',
  'vax',
  'wasm',
  'ws',
  'x86_cs',
  'xap',
  'xcore_cs',
  'xtensa',
  'z80',
]

analysis_enabled_static_plugins = analysis_plugins
analysis_enabled_shared_plugins = []

rz_analysis_dependencies = [
  rz_util_dep,
  rz_crypto_dep,
  rz_reg_dep,
  rz_syscall_dep,
  rz_search_dep,
  rz_cons_dep,
  rz_flag_dep,
  rz_hash_dep,
  rz_parse_dep,
  rz_asm_dep,
  rz_bin_dep,
]

analysis_6502_sources = [
  'p/analysis_6502.c',
]

analysis_6502_headers = [
  '../asm/arch/6502/',
]

analysis_6502_cs_sources = [
  'p/analysis_6502_cs.c',
]

analysis_6502_cs_deps = [
  capstone_dep,
]

analysis_8051_sources = [
  'p/analysis_8051.c',
]

analysis_8051_headers = [
  '../asm/arch/8051/',
]

analysis_amd29k_sources = [
  'p/analysis_amd29k.c',
  '../asm/arch/amd29k/amd29k.c',
]

analysis_arc_sources = [
  'p/analysis_arc.c',
]

analysis_arm_cs_sources = [
  'p/analysis_arm_cs.c',
]

analysis_arm_cs_deps = [
  capstone_dep,
]

analysis_arm_gnu_sources = [
  'p/analysis_arm_gnu.c',
  '../asm/arch/arm/winedbg/be_arm.c',
]

analysis_arm_gnu_headers = [
  '../asm/arch/arm/',
]

analysis_avr_sources = [
  'p/analysis_avr.c',
  '../asm/arch/avr/avr_disasm.c',
  '../asm/arch/avr/format.c',
  '../asm/arch/avr/disasm.c',
]

analysis_bf_sources = [
  'p/analysis_bf.c',
]

analysis_chip8_sources = [
  'p/analysis_chip8.c',
]

analysis_cr16_sources = [
  'p/analysis_cr16.c',
  '../asm/arch/cr16/cr16_disas.c',
]

analysis_cr16_headers = [
  '../asm/arch/cr16/',
]

analysis_cris_sources = [
  'p/analysis_cris.c',
]

analysis_dalvik_sources = [
  'p/analysis_dalvik.c',
]

analysis_ebc_sources = [
  'p/analysis_ebc.c',
  '../asm/arch/ebc/ebc_disas.c',
]

analysis_ebc_headers = [
  '../asm/arch/ebc/',
]

analysis_gb_sources = [
  'p/analysis_gb.c',
]

analysis_gb_headers = [
  'arch/gb/',
  '../asm/arch/gb/',
]

analysis_h8300_sources = [
  'p/analysis_h8300.c',
  '../asm/arch/h8300/h8300_disas.c',
]

analysis_h8300_headers = [
  '../asm/arch/h8300/',
]

analysis_hexagon_sources = [
  'p/analysis_hexagon.c',
  'arch/hexagon/hexagon_analysis.c',
  '../asm/arch/hexagon/hexagon.c',
  '../asm/arch/hexagon/hexagon_disas.c',
]

analysis_hexagon_headers = [
  'arch/hexagon/',
  '../asm/arch/hexagon/',
]

analysis_i4004_sources = [
  'p/analysis_i4004.c',
]

analysis_i8080_sources = [
  'p/analysis_i8080.c',
]

analysis_java_sources = [
  'p/analysis_java.c',
  '../asm/arch/java/code.c',
  '../asm/arch/java/ops.c',
]

analysis_m68k_cs_sources = [
  'p/analysis_m68k_cs.c',
]

analysis_m68k_cs_deps = [
  capstone_dep,
]

analysis_m680x_cs_sources = [
  'p/analysis_m680x_cs.c',
]

analysis_m680x_cs_deps = [
  capstone_dep,
]

analysis_malbolge_sources = [
  'p/analysis_malbolge.c',
]

analysis_mcore_sources = [
  'p/analysis_mcore.c',
  '../asm/arch/mcore/mcore.c',
]

analysis_mips_cs_sources = [
  'p/analysis_mips_cs.c',
]

analysis_mips_cs_deps = [
  capstone_dep,
]

analysis_mips_gnu_sources = [
  'p/analysis_mips_gnu.c',
]

analysis_msp430_sources = [
  'p/analysis_msp430.c',
  '../asm/arch/msp430/msp430_disas.c',
]

analysis_msp430_headers = [
  '../asm/arch/msp430/',
]

analysis_nios2_sources = [
  'p/analysis_nios2.c',
]

analysis_null_sources = [
  'p/analysis_null.c',
]

analysis_or1k_sources = [
  'p/analysis_or1k.c',
  '../asm/arch/or1k/or1k_disas.c',
]

analysis_or1k_headers = [
  '../asm/arch/or1k/',
]

analysis_pic_sources = [
  'p/analysis_pic.c',
  '../asm/arch/pic/pic_midrange.c',
]

analysis_ppc_cs_sources = [
  'p/analysis_ppc_cs.c',
  '../asm/arch/ppc/libvle/vle.c',
]

analysis_ppc_cs_deps = [
  capstone_dep,
]

analysis_ppc_gnu_sources = [
  'p/analysis_ppc_gnu.c',
  '../asm/arch/ppc/libvle/vle.c',
]

analysis_propeller_sources = [
  'p/analysis_propeller.c',
  '../asm/arch/propeller/propeller_disas.c',
]

analysis_propeller_headers = [
  '../asm/arch/propeller/',
]

analysis_pyc_sources = [
  'p/analysis_pyc.c',
  '../asm/arch/pyc/opcode_10.c',
  '../asm/arch/pyc/opcode_11.c',
  '../asm/arch/pyc/opcode_12.c',
  '../asm/arch/pyc/opcode_13.c',
  '../asm/arch/pyc/opcode_14.c',
  '../asm/arch/pyc/opcode_15.c',
  '../asm/arch/pyc/opcode_16.c',
  '../asm/arch/pyc/opcode_20.c',
  '../asm/arch/pyc/opcode_21.c',
  '../asm/arch/pyc/opcode_22.c',
  '../asm/arch/pyc/opcode_23.c',
  '../asm/arch/pyc/opcode_24.c',
  '../asm/arch/pyc/opcode_25.c',
  '../asm/arch/pyc/opcode_26.c',
  '../asm/arch/pyc/opcode_27.c',
  '../asm/arch/pyc/opcode_2x.c',
  '../asm/arch/pyc/opcode_30.c',
  '../asm/arch/pyc/opcode_31.c',
  '../asm/arch/pyc/opcode_32.c',
  '../asm/arch/pyc/opcode_33.c',
  '../asm/arch/pyc/opcode_34.c',
  '../asm/arch/pyc/opcode_35.c',
  '../asm/arch/pyc/opcode_36.c',
  '../asm/arch/pyc/opcode_37.c',
  '../asm/arch/pyc/opcode_38.c',
  '../asm/arch/pyc/opcode_39.c',
  '../asm/arch/pyc/opcode_3x.c',
  '../asm/arch/pyc/opcode_analysis.c',
  '../asm/arch/pyc/opcode_arg_fmt.c',
  '../asm/arch/pyc/opcode.c',
  '../asm/arch/pyc/pyc_dis.c'
]

analysis_riscv_sources = [
  'p/analysis_riscv.c',
]

analysis_rsp_sources = [
  'p/analysis_rsp.c',
  '../asm/arch/rsp/rsp_idec.c',
]

analysis_sh_sources = [
  'p/analysis_sh.c',
]

analysis_snes_sources = [
  'p/analysis_snes.c',
]

analysis_sparc_cs_sources = [
  'p/analysis_sparc_cs.c',
]

analysis_sparc_cs_deps = [
  capstone_dep,
]

analysis_sparc_gnu_sources = [
  'p/analysis_sparc_gnu.c',
]

analysis_spc700_sources = [
  'p/analysis_spc700.c',
]

analysis_sysz_sources = [
  'p/analysis_sysz.c',
]

analysis_sysz_deps = [
  capstone_dep,
]

analysis_tms320_sources = [
  'p/analysis_tms320.c',
  'p/analysis_tms320_c55x_plus.c',
  '../asm/arch/tms320/tms320_dasm.c',
  '../asm/arch/tms320/c55x_plus/ins.c',
  '../asm/arch/tms320/c55x_plus/c55plus.c',
  '../asm/arch/tms320/c55x_plus/c55plus_decode.c',
  '../asm/arch/tms320/c55x_plus/decode_funcs.c',
  '../asm/arch/tms320/c55x_plus/hashtable.c',
  '../asm/arch/tms320/c55x_plus/utils.c',
]

analysis_tms320_deps = [
  capstone_dep,
]

analysis_tricore_sources = [
  'p/analysis_tricore.c',
]

analysis_v810_sources = [
  'p/analysis_v810.c',
  '../asm/arch/v810/v810_disas.c',
]

analysis_v810_headers = [
  '../asm/arch/v810/',
]

analysis_v850_sources = [
  'p/analysis_v850.c',
  '../asm/arch/v850/v850_disas.c',
]

analysis_v850_headers = [
  '../asm/arch/v850/',
]

analysis_vax_sources = [
  'p/analysis_vax.c',
]

analysis_wasm_sources = [
  'p/analysis_wasm.c',
  '../asm/arch/wasm/wasm.c',
]

analysis_ws_sources = [
  'p/analysis_ws.c',
]

analysis_x86_cs_sources = [
  'p/analysis_x86_cs.c',
]

analysis_x86_cs_deps = [
  capstone_dep,
]

analysis_xap_sources = [
  'p/analysis_xap.c',
]

analysis_xcore_cs_sources = [
  'p/analysis_xcore_cs.c',
]

analysis_xcore_cs_deps = [
  capstone_dep,
]

analysis_xtensa_sources = [
  'p/analysis_xtensa.c',
  '../asm/arch/xtensa/gnu/xtensa-dis.c',
  '../asm/arch/xtensa/gnu/elf32-xtensa.c',
  '../asm/arch/xtensa/gnu/xtensa-isa.c',
  '../asm/arch/xtensa/gnu/xtensa-modules.c',
]

analysis_z80_sources = [
  'p/analysis_z80.c',
]

rz_analysis_sources = [
  'analysis.c',
  'block.c',
  'function.c',
  'jmptbl.c',
  'cc.c',
  'class.c',
  'cond.c',
  'cycles.c',
  'data.c',
  'diff.c',
  'esil.c',
  'esil_stats.c',
  'esil_trace.c',
  'esil_interrupt.c',
  'esil_sources.c',
  'esil_cfg.c',
  'esil_dfg.c',
  'fcn.c',
  'flirt.c',
  'hint.c',
  'labels.c',
  'meta.c',
  'op.c',
  'pin.c',
  'reflines.c',
  'rtti.c',
  'rtti_msvc.c',
  'rtti_itanium.c',
  'sign.c',
  'switch.c',
  'type.c',
  'type_pdb.c',
  'dwarf_process.c',
  'value.c',
  'var.c',
  'vtable.c',
  'xrefs.c',
  'serialize_analysis.c',
]

rz_analysis_inc = [platform_inc]

# compile static plugins
rz_analysis_plugins_dep = []
foreach p : analysis_plugins
  c_files = get_variable('analysis_@0@_sources'.format(p))
  h_files = get_variable('analysis_@0@_headers'.format(p), [])
  analysis_plugin_deps = get_variable('analysis_@0@_deps'.format(p), [])

  h_files = include_directories([h_files, '../asm/arch/include/'])
  name = 'analysis_plugin_@0@'.format(p)
  analysis_plugin_inc = [h_files, platform_inc]

  if p in analysis_enabled_static_plugins
    analysis_plugin = static_library(name, c_files,
      include_directories: analysis_plugin_inc,
      dependencies: rz_analysis_dependencies + analysis_plugin_deps,
      c_args: library_cflags,
      install: false,
    )

    analysis_plugin_dep = declare_dependency(link_with: analysis_plugin, include_directories: analysis_plugin_inc)
    set_variable(name + '_dep', analysis_plugin_dep)
    rz_analysis_plugins_dep += [analysis_plugin_dep]
  endif
endforeach

rz_analysis = library('rz_analysis', rz_analysis_sources,
  include_directories: rz_analysis_inc,
  c_args: library_cflags,
  dependencies: rz_analysis_dependencies + rz_analysis_plugins_dep,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_analysis_dep = declare_dependency(link_with: rz_analysis,
                                include_directories: rz_analysis_inc)

pkgconfig_mod.generate(rz_analysis,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_analysis',
  filebase: 'rz_analysis',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
    'rz_crypto',
    'rz_reg',
    'rz_asm',
    'rz_parse',
    'rz_syscall',
    'rz_search',
    'rz_cons',
    'rz_bin',
    'rz_flag'
  ],
  description: 'rizin foundation libraries'
)

# compile shared plugins
foreach p : analysis_plugins
  c_files = get_variable('analysis_@0@_sources'.format(p))
  h_files = get_variable('analysis_@0@_headers'.format(p), [])
  analysis_plugin_deps = get_variable('analysis_@0@_deps'.format(p), [])

  h_files = include_directories([h_files, '../asm/arch/include/'])
  name = 'analysis_plugin_@0@'.format(p)
  analysis_plugin_inc = [h_files, platform_inc]

  if p in analysis_enabled_shared_plugins
    analysis_plugin = shared_library(name, c_files,
      include_directories: analysis_plugin_inc,
      dependencies: [rz_analysis_dependencies, analysis_plugin_deps, rz_analysis_dep],
      install: true,
      install_dir: rizin_plugins,
    )
  endif
endforeach
