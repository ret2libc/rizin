core_plugins = [
  'java',
]

core_enabled_static_plugins = core_plugins
core_enabled_shared_plugins = []

rz_core_dependencies = [
  rz_util_dep,
  rz_magic_dep,
  rz_socket_dep,
  rz_flag_dep,
  rz_cons_dep,
  rz_lang_dep,
  rz_hash_dep,
  rz_crypto_dep,
  rz_io_dep,
  rz_reg_dep,
  rz_bp_dep,
  rz_syscall_dep,
  rz_parse_dep,
  rz_asm_dep,
  rz_egg_dep,
  rz_search_dep,
  rz_analysis_dep,
  rz_debug_dep,
  rz_config_dep,
  rz_bin_dep,
  platform_deps,
  gdb_dep,
  lrt,
  shell_parser_dep,
  libuv_dep,
]

rz_core_inc = []
if host_machine.system() != 'windows'
  rz_core_inc += ['../../shlr/heap/include']
else
  rz_core_inc += ['../../shlr/heap/include/rz_windows']
endif
rz_core_inc = [platform_inc, include_directories(rz_core_inc)]

core_java_sources = [
  'p/core_java.c',
  '../bin/format/java/json.c',
]

# compile static plugins
rz_core_plugins_dep = []
foreach p : core_plugins
  c_files = get_variable('core_@0@_sources'.format(p))
  h_files = get_variable('core_@0@_headers'.format(p), [])
  core_plugin_deps = get_variable('core_@0@_deps'.format(p), [])

  h_files = include_directories([h_files])
  name = 'core_plugin_@0@'.format(p)
  core_plugin_inc = [h_files, rz_core_inc]

  if p in core_enabled_static_plugins
    core_plugin = static_library(name, c_files,
      include_directories: core_plugin_inc,
      dependencies: rz_core_dependencies + core_plugin_deps,
      c_args: library_cflags,
      install: false,
    )

    core_plugin_dep = declare_dependency(link_with: core_plugin, include_directories: core_plugin_inc)
    set_variable(name + '_dep', core_plugin_dep)
    rz_core_plugins_dep += [core_plugin_dep]
  endif
endforeach

subdir('cmd_descs')

rz_core_sources = [
  'analysis_tp.c',
  'analysis_objc.c',
  'casm.c',
  'cagraph.c',
  'canalysis.c',
  'ctypes.c',
  'carg.c',
  'cautocmpl.c',
  'cbin.c',
  'cconfig.c',
  'cdebug.c',
  'cio.c',
  'cmd.c',
  cmd_descs_c,
  #'cmd_analysis.c',
  'cmd_api.c',
  #'cmd_cmp.c',
  #'cmd_debug.c',
  #'cmd_egg.c',
  #'cmd_eval.c',
  #'cmd_flag.c',
  #'cmd_hash.c',
  #'cmd_help.c',
  #'cmd_info.c',
  #'cmd_log.c',
  #'cmd_macro.c',
  #'cmd_magic.c',
  #'cmd_meta.c',
  #'cmd_open.c',
  #'cmd_print.c',
  #'cmd_project.c',
  #'cmd_quit.c',
  #'cmd_search.c',
  #'cmd_search_rop.c',
  #'cmd_seek.c',
  #'cmd_type.c',
  #'cmd_write.c',
  #'cmd_zign.c',
  'core.c',
  'disasm.c',
  'cfile.c',
  'fortune.c',
  'gdiff.c',
  'zdiff.c',
  'agraph.c',
  'hack.c',
  'libs.c',
  #'linux_heap_glibc.c',
  'panels.c',
  'cplugin.c',
  'project.c',
  'rtr.c',
  #'rtr_http.c',
  #'rtr_shell.c',
  'seek.c',
  'task.c',
  'vasm.c',
  'visual.c',
  'vmarks.c',
  'vmenus.c',
  'vmenus_graph.c',
  'vmenus_zigns.c',
  'yank.c',
  'cannotated_code.c',
  'serialize_core.c'
]

if host_machine.system() == 'windows'
  rz_core_sources += 'windows_heap.c'
endif

rz_core = library('rz_core', rz_core_sources,
  include_directories: rz_core_inc,
  c_args: library_cflags,
  dependencies: rz_core_dependencies + rz_core_plugins_dep,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_core_dep = declare_dependency(link_with: rz_core,
                                include_directories: rz_core_inc)

pkgconfig_mod.generate(
  rz_core,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_core',
  filebase: 'rz_core',
  libraries: pkgcfg_sanitize_libs,
  requires: pkgconfig_magic_requires + [
    'rz_util',
    'rz_reg',
    'rz_syscall',
    'rz_search',
    'rz_cons',
    'rz_analysis',
    'rz_socket',
    'rz_io',
    'rz_lang',
    'rz_hash',
    'rz_flag',
    'rz_parse',
    'rz_egg',
    'rz_debug',
    'rz_crypto',
    'rz_config',
    'rz_bin',
    'rz_asm',
    'rz_bp'
  ],
  description: 'rizin foundation libraries'
)

# compile shared plugins
foreach p : core_plugins
  c_files = get_variable('core_@0@_sources'.format(p))
  h_files = get_variable('core_@0@_headers'.format(p), [])
  core_plugin_deps = get_variable('core_@0@_deps'.format(p), [])

  h_files = include_directories([h_files])
  name = 'core_plugin_@0@'.format(p)
  core_plugin_inc = [h_files, platform_inc]

  if p in core_enabled_shared_plugins
    core_plugin = shared_library(name, c_files,
      include_directories: core_plugin_inc,
      dependencies: [rz_core_dependencies, core_plugin_deps, rz_core_dep],
      install: true,
      install_dir: rizin_plugins,
    )
  endif
endforeach
