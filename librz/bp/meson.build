bp_plugins = [
  'arm',
  'bf',
  'mips',
  'ppc',
  'sh',
  'x86'
]

bp_enabled_static_plugins = []
bp_enabled_shared_plugins = bp_plugins

rz_bp_dependencies = [
  rz_util_dep,
]

bp_arm_sources = [
  'p/bp_arm.c',
]

bp_bf_sources = [
  'p/bp_bf.c',
]

bp_mips_sources = [
  'p/bp_mips.c',
]

bp_ppc_sources = [
  'p/bp_ppc.c',
]

bp_sh_sources = [
  'p/bp_sh.c',
]

bp_x86_sources = [
  'p/bp_x86.c'
]

# compile static plugins
rz_bp_plugins_dep = []
foreach p : bp_plugins
  c_files = get_variable('bp_@0@_sources'.format(p))
  h_files = get_variable('bp_@0@_headers'.format(p), [])
  bp_plugin_deps = get_variable('bp_@0@_deps'.format(p), [])

  h_files = include_directories(h_files)
  name = 'bp_plugin_@0@'.format(p)
  bp_plugin_inc = [h_files, platform_inc]

  if p in bp_enabled_static_plugins
    bp_plugin = static_library(name, c_files,
      include_directories: bp_plugin_inc,
      dependencies: rz_bp_dependencies + bp_plugin_deps,
      c_args: library_cflags,
      install: false,
    )

    bp_plugin_dep = declare_dependency(link_with: bp_plugin, include_directories: bp_plugin_inc)
    set_variable(name + '_dep', bp_plugin_dep)
    rz_bp_plugins_dep += [bp_plugin_dep]
  endif
endforeach

rz_bp_sources = [
  'bp.c',
  'bp_io.c',
  'bp_plugin.c',
  'bp_traptrace.c',
  'bp_watch.c',
]

rz_bp = library('rz_bp', rz_bp_sources,
  include_directories: [platform_inc],
  c_args: library_cflags,
  dependencies: rz_bp_dependencies + rz_bp_plugins_dep,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_bp_dep = declare_dependency(link_with: rz_bp,
                              include_directories: [platform_inc])

pkgconfig_mod.generate(rz_bp,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_bp',
  filebase: 'rz_bp',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util'
  ],
  description: 'rizin foundation libraries'
)

# compile shared plugins
foreach p : bp_plugins
  c_files = get_variable('bp_@0@_sources'.format(p))
  h_files = get_variable('bp_@0@_headers'.format(p), [])
  bp_plugin_deps = get_variable('bp_@0@_deps'.format(p), [])

  h_files = include_directories(h_files)
  name = 'bp_plugin_@0@'.format(p)
  bp_plugin_inc = [h_files, platform_inc]

  if p in bp_enabled_shared_plugins
    bp_plugin = shared_library(name, c_files,
      include_directories: bp_plugin_inc,
      dependencies: [rz_bp_dependencies, rz_bp_dep, bp_plugin_deps],
      install: true,
      install_dir: rizin_plugins,
    )
  endif
endforeach
