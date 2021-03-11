egg_plugins = [
  'exec',
  'xor'
]

egg_enabled_static_plugins = egg_plugins
egg_enabled_shared_plugins = []

rz_egg_dependencies = [
  rz_util_dep,
  rz_syscall_dep,
  rz_asm_dep,
  mpc_dep
]

rz_egg_inc = [platform_inc]

egg_exec_sources = [
  'p/egg_exec.c',
]

egg_xor_sources = [
  'p/egg_xor.c'
]

# compile static plugins
rz_egg_plugins_dep = []
foreach p : egg_plugins
  c_files = get_variable('egg_@0@_sources'.format(p))
  h_files = get_variable('egg_@0@_headers'.format(p), [])
  egg_plugin_deps = get_variable('egg_@0@_deps'.format(p), [])

  h_files = include_directories([h_files])
  name = 'egg_plugin_@0@'.format(p)
  egg_plugin_inc = [h_files, rz_egg_inc]

  if p in egg_enabled_static_plugins
    egg_plugin = static_library(name, c_files,
      include_directories: egg_plugin_inc,
      dependencies: rz_egg_dependencies + egg_plugin_deps,
      c_args: library_cflags,
      install: false,
    )

    egg_plugin_dep = declare_dependency(link_with: egg_plugin, include_directories: egg_plugin_inc)
    set_variable(name + '_dep', egg_plugin_dep)
    rz_egg_plugins_dep += [egg_plugin_dep]
  endif
endforeach

rz_egg_sources = [
  'egg.c',
  'egg_Cfile.c',
  'egg_lang.c',
  'emit_arm.c',
  'emit_trace.c',
  'emit_x64.c',
  'emit_x86.c',
]

rz_egg = library('rz_egg', rz_egg_sources,
  include_directories: rz_egg_inc,
  c_args: library_cflags,
  dependencies: rz_egg_dependencies + rz_egg_plugins_dep,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_egg_dep = declare_dependency(link_with: rz_egg,
                               include_directories: [platform_inc])

pkgconfig_mod.generate(rz_egg,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_egg',
  filebase: 'rz_egg',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
    'rz_asm',
    'rz_syscall'
  ],
  description: 'rizin foundation libraries'
)

# compile shared plugins
foreach p : egg_plugins
  c_files = get_variable('egg_@0@_sources'.format(p))
  h_files = get_variable('egg_@0@_headers'.format(p), [])
  egg_plugin_deps = get_variable('egg_@0@_deps'.format(p), [])

  h_files = include_directories([h_files])
  name = 'egg_plugin_@0@'.format(p)
  egg_plugin_inc = [h_files, platform_inc]

  if p in egg_enabled_shared_plugins
    egg_plugin = shared_library(name, c_files,
      include_directories: egg_plugin_inc,
      dependencies: [rz_egg_dependencies, egg_plugin_deps, rz_egg_dep],
      install: true,
      install_dir: rizin_plugins,
    )
  endif
endforeach
