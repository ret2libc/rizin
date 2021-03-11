parse_plugins = [
  '6502_pseudo',
  'arm_pseudo',
  'att2intel',
  'avr_pseudo',
  'chip8_pseudo',
  'tms320_pseudo',
  'dalvik_pseudo',
  'm68k_pseudo',
  'mips_pseudo',
  'ppc_pseudo',
  'sh_pseudo',
  'riscv_pseudo',
  'v850_pseudo',
  'wasm_pseudo',
  'x86_pseudo',
  'z80_pseudo'
]

parse_enabled_static_plugins = parse_plugins
parse_enabled_shared_plugins = []

rz_parse_dependencies = [
  rz_util_dep,
  rz_flag_dep,
  rz_syscall_dep,
  rz_reg_dep,
  rz_cons_dep,
  tcc_dep,
  mpc_dep
]

rz_parse_inc = [platform_inc]

parse_6502_pseudo_sources = [
  'p/parse_6502_pseudo.c',
]

parse_arm_pseudo_sources = [
  'p/parse_arm_pseudo.c',
]

parse_att2intel_sources = [
  'p/parse_att2intel.c',
]

parse_avr_pseudo_sources = [
  'p/parse_avr_pseudo.c',
]

parse_chip8_pseudo_sources = [
  'p/parse_chip8_pseudo.c',
]

parse_dalvik_pseudo_sources = [
  'p/parse_dalvik_pseudo.c',
]

parse_m68k_pseudo_sources = [
  'p/parse_m68k_pseudo.c',
]

parse_mips_pseudo_sources = [
  'p/parse_mips_pseudo.c',
]

parse_ppc_pseudo_sources = [
  'p/parse_ppc_pseudo.c',
]

parse_sh_pseudo_sources = [
  'p/parse_sh_pseudo.c',
]

parse_tms320_pseudo_sources = [
  'p/parse_tms320_pseudo.c',
]

parse_v850_pseudo_sources = [
  'p/parse_v850_pseudo.c',
]

parse_wasm_pseudo_sources = [
  'p/parse_wasm_pseudo.c',
]

parse_x86_pseudo_sources = [
  'p/parse_x86_pseudo.c',
]

parse_riscv_pseudo_sources = [
  'p/parse_riscv_pseudo.c',
]

parse_z80_pseudo_sources = [
  'p/parse_z80_pseudo.c'
]

# compile static plugins
rz_parse_plugins_dep = []
foreach p : parse_plugins
  c_files = get_variable('parse_@0@_sources'.format(p))
  h_files = get_variable('parse_@0@_headers'.format(p), [])
  parse_plugin_deps = get_variable('parse_@0@_deps'.format(p), [])

  h_files = include_directories([h_files])
  name = 'parse_plugin_@0@'.format(p)
  parse_plugin_inc = [h_files, rz_parse_inc]

  if p in parse_enabled_static_plugins
    parse_plugin = static_library(name, c_files,
      include_directories: parse_plugin_inc,
      dependencies: rz_parse_dependencies + parse_plugin_deps,
      c_args: library_cflags,
      install: false,
    )

    parse_plugin_dep = declare_dependency(link_with: parse_plugin, include_directories: parse_plugin_inc)
    set_variable(name + '_dep', parse_plugin_dep)
    rz_parse_plugins_dep += [parse_plugin_dep]
  endif
endforeach

rz_parse_sources = [
  'code.c',
  'filter.c',
  'parse.c',
  'ctype.c',
]

rz_parse = library('rz_parse', rz_parse_sources,
  include_directories: rz_parse_inc,
  c_args: library_cflags,
  dependencies: rz_parse_dependencies + rz_parse_plugins_dep,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_parse_dep = declare_dependency(link_with: rz_parse,
                                 include_directories: platform_inc)

pkgconfig_mod.generate(rz_parse,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_parse',
  filebase: 'rz_parse',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
    'rz_flag',
    'rz_cons',
    'rz_syscall',
    'rz_reg'
  ],
  description: 'rizin foundation libraries'
)

# compile shared plugins
foreach p : parse_plugins
  c_files = get_variable('parse_@0@_sources'.format(p))
  h_files = get_variable('parse_@0@_headers'.format(p), [])
  parse_plugin_deps = get_variable('parse_@0@_deps'.format(p), [])

  h_files = include_directories([h_files])
  name = 'parse_plugin_@0@'.format(p)
  parse_plugin_inc = [h_files, platform_inc]

  if p in parse_enabled_shared_plugins
    parse_plugin = shared_library(name, c_files,
      include_directories: parse_plugin_inc,
      dependencies: [rz_parse_dependencies, parse_plugin_deps, rz_parse_dep],
      install: true,
      install_dir: rizin_plugins,
    )
  endif
endforeach
