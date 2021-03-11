debug_plugins = [
  'bf',
  'bochs',
  'esil',
  'gdb',
  'io',
  'native',
  'null',
  'qnx',
  'rap',
  'winkd'
]

if host_machine.system() == 'windows'
  debug_plugins += 'windbg'
endif

debug_enabled_static_plugins = debug_plugins
debug_enabled_shared_plugins = []

rz_debug_dependencies = [
  qnx_dep,
  gdb_dep,
  bochs_dep,
  winkd_dep,
  rz_util_dep,
  rz_cons_dep,
  rz_hash_dep,
  rz_io_dep,
  rz_reg_dep,
  rz_bp_dep,
  rz_syscall_dep,
  rz_egg_dep,
  rz_analysis_dep,
]

debug_bf_sources = [
  'p/debug_bf.c',
  'p/bfvm.c',
]

debug_bochs_sources = [
  'p/debug_bochs.c',
]

debug_esil_sources = [
  'p/debug_esil.c',
]

debug_gdb_sources = [
  'p/debug_gdb.c',
]

debug_io_sources = [
  'p/debug_io.c',
]

debug_native_sources = [
  'p/debug_native.c',
]
debug_native_headers = []
if host_machine.system() == 'linux' or host_machine.system() == 'android'
  debug_native_sources += ['p/native/linux/linux_debug.c']
endif
if host_machine.system() == 'linux'
  debug_native_sources += ['p/native/linux/linux_coredump.c']
  debug_native_headers += ['../bin/format/elf/']
endif
if host_machine.system() == 'darwin'
  debug_native_sources += ['p/native/xnu/xnu_debug.c']
endif
if ['netbsd', 'openbsd', 'freebsd', 'dragonfly'].contains(host_machine.system())
  debug_native_deps = cc.find_library('kvm', required: true, static: is_static_build)
  debug_native_sources += ['p/native/bsd/bsd_debug.c']
endif
if host_machine.system() == 'windows'
  debug_native_sources += [
    'p/native/windows/windows_debug.c',
    'p/native/maps/windows_maps.c',
  ]
  debug_native_deps = [w32dbg_wrap_dep]
else
  debug_native_sources += ['p/native/procfs.c']
endif

debug_null_sources = [
  'p/debug_null.c',
]

debug_qnx_sources = [
  'p/debug_qnx.c',
]

debug_rap_sources = [
  'p/debug_rap.c',
]

debug_winkd_sources = [
  'p/debug_winkd.c',
]

debug_windbg_sources = [
  'p/debug_windbg.c',
]

rz_debug_sources = [
  'arg.c',
  'ddesc.c',
  'debug.c',
  'dreg.c',
  'desil.c',
  'dmap.c',
  'pid.c',
  'plugin.c',
  'dsession.c',
  'dsignal.c',
  'snap.c',
  'trace.c',
]

if host_machine.system() == 'windows'
  rz_debug_sources += [
    'p/native/windows/windows_message.c',
  ]
endif

rz_debug_inc = [
  platform_inc,
]

# compile static plugins
rz_debug_plugins_dep = []
foreach p : debug_plugins
  c_files = get_variable('debug_@0@_sources'.format(p))
  h_files = get_variable('debug_@0@_headers'.format(p), [])
  debug_plugin_deps = get_variable('debug_@0@_deps'.format(p), [])

  h_files = include_directories([h_files])
  name = 'debug_plugin_@0@'.format(p)
  debug_plugin_inc = [h_files, rz_debug_inc]

  if p in debug_enabled_static_plugins
    debug_plugin = static_library(name, c_files,
      include_directories: debug_plugin_inc,
      dependencies: rz_debug_dependencies + debug_plugin_deps,
      c_args: library_cflags,
      install: false,
    )

    debug_plugin_dep = declare_dependency(link_with: debug_plugin, include_directories: debug_plugin_inc)
    set_variable(name + '_dep', debug_plugin_dep)
    rz_debug_plugins_dep += [debug_plugin_dep]
  endif
endforeach

rz_debug = library('rz_debug', rz_debug_sources,
  include_directories: rz_debug_inc,
  c_args: library_cflags,
  dependencies: rz_debug_dependencies + rz_debug_plugins_dep,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_debug_dep = declare_dependency(link_with: rz_debug,
                                 include_directories: rz_debug_inc)

pkgconfig_mod.generate(rz_debug,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_debug',
  filebase: 'rz_debug',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
    'rz_hash',
    'rz_reg',
    'rz_syscall',
    'rz_analysis',
    'rz_io',
    'rz_bp',
    'rz_cons',
    'rz_egg',
  ],
  description: 'rizin foundation libraries'
)

# compile shared plugins
foreach p : debug_plugins
  c_files = get_variable('debug_@0@_sources'.format(p))
  h_files = get_variable('debug_@0@_headers'.format(p), [])
  debug_plugin_deps = get_variable('debug_@0@_deps'.format(p), [])

  h_files = include_directories([h_files])
  name = 'debug_plugin_@0@'.format(p)
  debug_plugin_inc = [h_files, platform_inc]

  if p in debug_enabled_shared_plugins
    debug_plugin = shared_library(name, c_files,
      include_directories: debug_plugin_inc,
      dependencies: [rz_debug_dependencies, debug_plugin_deps, rz_debug_dep],
      install: true,
      install_dir: rizin_plugins,
    )
  endif
endforeach
