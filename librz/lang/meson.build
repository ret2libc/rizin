lang_plugins = [
  'lib',
  'pipe',
  'rust',
  'vala',
  'zig',
  'spp',
]

if host_machine.system() != 'windows'
  lang_plugins += [
    'c',
    'cpipe'
  ]
endif

lang_enabled_static_plugins = lang_plugins
lang_enabled_shared_plugins = []

rz_lang_dependencies = [
  rz_util_dep,
  rz_cons_dep,
]

rz_lang_inc = [platform_inc]

lang_c_sources = [
  'p/c.c',
]

lang_cpipe_sources = [
  'p/cpipe.c',
  'p/pipe_common.c',
]

lang_lib_sources = [
  'p/lib.c',
]

lang_pipe_sources = [
  'p/pipe.c',
  'p/pipe_common.c',
]

lang_rust_sources = [
  'p/rust.c',
]

lang_vala_sources = [
  'p/vala.c',
]

lang_zig_sources = [
  'p/zig.c',
]

lang_spp_sources = [
  'p/spp.c',
]

lang_spp_deps = [
  spp_dep,
]

rz_lang_sources = [
  'lang.c',
]

# compile static plugins
rz_lang_plugins_dep = []
foreach p : lang_plugins
  c_files = get_variable('lang_@0@_sources'.format(p))
  h_files = get_variable('lang_@0@_headers'.format(p), [])
  lang_plugin_deps = get_variable('lang_@0@_deps'.format(p), [])

  h_files = include_directories([h_files])
  name = 'lang_plugin_@0@'.format(p)
  lang_plugin_inc = [h_files, rz_lang_inc]

  if p in lang_enabled_static_plugins
    lang_plugin = static_library(name, c_files,
      include_directories: lang_plugin_inc,
      dependencies: rz_lang_dependencies + lang_plugin_deps,
      c_args: library_cflags,
      install: false,
    )

    lang_plugin_dep = declare_dependency(link_with: lang_plugin, include_directories: lang_plugin_inc)
    set_variable(name + '_dep', lang_plugin_dep)
    rz_lang_plugins_dep += [lang_plugin_dep]
  endif
endforeach

rz_lang = library('rz_lang', rz_lang_sources,
  include_directories: rz_lang_inc,
  c_args: library_cflags,
  dependencies: rz_lang_dependencies + rz_lang_plugins_dep,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_lang_dep = declare_dependency(link_with: rz_lang,
                                include_directories: [platform_inc])

pkgconfig_mod.generate(rz_lang,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_lang',
  filebase: 'rz_lang',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
    'rz_cons'
  ],
  description: 'rizin foundation libraries'
)

# compile shared plugins
foreach p : lang_plugins
  c_files = get_variable('lang_@0@_sources'.format(p))
  h_files = get_variable('lang_@0@_headers'.format(p), [])
  lang_plugin_deps = get_variable('lang_@0@_deps'.format(p), [])

  h_files = include_directories([h_files])
  name = 'lang_plugin_@0@'.format(p)
  lang_plugin_inc = [h_files, platform_inc]

  if p in lang_enabled_shared_plugins
    lang_plugin = shared_library(name, c_files,
      include_directories: lang_plugin_inc,
      dependencies: [rz_lang_dependencies, lang_plugin_deps, rz_lang_dep],
      install: true,
      install_dir: rizin_plugins,
    )
  endif
endforeach
