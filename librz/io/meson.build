io_plugins = [
  'ar',
  'fd',
  'bfdbg',
  'bochs',
  'debug',
  'default',
  'gdb',
  'gprobe',
  'gzip',
  'http',
  'ihex',
  'mach',
  'malloc',
  'null',
  'procpid',
  'ptrace',
  'qnx',
  'rzk',
  'rzpipe',
  'rzweb',
  'rap',
  'self',
  'shm',
  'sparse',
  'tcp',
  'winkd',
  'winedbg',
  'zip'
]

if host_machine.system() == 'windows'
  io_plugins += [
    'windbg',
    'w32dbg',
    'w32',
  ]
endif

io_enabled_static_plugins = io_plugins
io_enabled_shared_plugins = []

rz_io_dependencies = [
  bochs_dep,
  gdb_dep,
  winkd_dep,
  qnx_dep,
  libzip_dep,
  ar_dep,
  pth,
  rz_util_dep,
  rz_socket_dep,
  rz_hash_dep,
  rz_crypto_dep,
  rz_cons_dep,
]

if host_machine.system() == 'windows'
  rz_io_dependencies += w32dbg_wrap_dep
endif

if use_ptrace_wrap
  rz_io_dependencies += ptrace_wrap_dep
endif

io_ar_sources = [
  'p/io_ar.c',
]

io_fd_sources = [
  'p/io_fd.c',
]

io_bfdbg_sources = [
  'p/io_bfdbg.c',
]

io_bochs_sources = [
  'p/io_bochs.c',
]

io_debug_sources = [
  'p/io_debug.c',
]

io_default_sources = [
  'p/io_default.c',
]

io_gdb_sources = [
  'p/io_gdb.c',
]

io_gprobe_sources = [
  'p/io_gprobe.c',
]

io_gzip_sources = [
  'p/io_gzip.c',
]

io_http_sources = [
  'p/io_http.c',
  'io_memory.c',
]

io_ihex_sources = [
  'p/io_ihex.c',
]

io_mach_sources = [
  'p/io_mach.c',
]

io_malloc_sources = [
  'p/io_malloc.c',
  'io_memory.c',
]

io_null_sources = [
  'p/io_null.c',
]

io_procpid_sources = [
  'p/io_procpid.c',
]

io_ptrace_sources = [
  'p/io_ptrace.c',
]

io_qnx_sources = [
  'p/io_qnx.c',
]

io_rzk_sources = [
  'p/io_rzk.c',
]
if host_machine.system() == 'linux' or host_machine.system() == 'android'
  io_rzk_sources += [
    'p/io_rzk_linux.c',
  ]
elif host_machine.system() == 'windows'
  io_rzk_sources += [
    'p/io_rzk_windows.c',
  ]
endif


io_rzpipe_sources = [
  'p/io_rzpipe.c',
]

io_rzweb_sources = [
  'p/io_rzweb.c',
]

io_rap_sources = [
  'p/io_rap.c',
]

io_self_sources = [
  'p/io_self.c',
]

io_shm_sources = [
  'p/io_shm.c',
]

io_sparse_sources = [
  'p/io_sparse.c',
]

io_tcp_sources = [
  'p/io_tcp.c',
  'io_memory.c',
]

io_w32_sources = [
  'p/io_w32.c',
]

io_w32dbg_sources = [
  'p/io_w32dbg.c',
]

io_winkd_sources = [
  'p/io_winkd.c',
]

io_windbg_sources = [
  'p/io_windbg.c',
]

io_winedbg_sources = [
  'p/io_winedbg.c',
]

io_zip_sources = [
  'p/io_zip.c',
]

# compile static plugins
rz_io_plugins_dep = []
foreach p : io_plugins
  c_files = get_variable('io_@0@_sources'.format(p))
  h_files = get_variable('io_@0@_headers'.format(p), [])
  io_plugin_deps = get_variable('io_@0@_deps'.format(p), [])

  h_files = include_directories([h_files])
  name = 'io_plugin_@0@'.format(p)
  io_plugin_inc = [h_files, platform_inc]

  if p in io_enabled_static_plugins
    io_plugin = static_library(name, c_files,
      include_directories: io_plugin_inc,
      dependencies: rz_io_dependencies + io_plugin_deps,
      c_args: library_cflags,
      install: false,
    )

    io_plugin_dep = declare_dependency(link_with: io_plugin, include_directories: io_plugin_inc)
    set_variable(name + '_dep', io_plugin_dep)
    rz_io_plugins_dep += [io_plugin_dep]
  endif
endforeach

rz_io_sources = [
  'io.c',
  'io_fd.c',
  'io_map.c',
  'io_cache.c',
  'io_desc.c',
  'io_plugin.c',
  'ioutils.c',
  'p_cache.c',
  'serialize_io.c',
]

rz_io = library('rz_io', rz_io_sources,
  include_directories: platform_inc,
  dependencies: rz_io_dependencies + rz_io_plugins_dep,
  c_args: library_cflags,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_io_dep = declare_dependency(link_with: rz_io,
                              include_directories: platform_inc)

pkgconfig_mod.generate(rz_io,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_io',
  filebase: 'rz_io',
  libraries: pkgcfg_sanitize_libs,
  requires: [
    'rz_util',
    'rz_socket'
  ],
  description: 'rizin foundation libraries'
)

# compile shared plugins
foreach p : io_plugins
  c_files = get_variable('io_@0@_sources'.format(p))
  h_files = get_variable('io_@0@_headers'.format(p), [])
  io_plugin_deps = get_variable('io_@0@_deps'.format(p), [])

  h_files = include_directories([h_files])
  name = 'io_plugin_@0@'.format(p)
  io_plugin_inc = [h_files, platform_inc]

  if p in io_enabled_shared_plugins
    io_plugin = shared_library(name, c_files,
      include_directories: io_plugin_inc,
      dependencies: [rz_io_dependencies, io_plugin_deps, rz_io_dep],
      install: true,
      install_dir: rizin_plugins,
    )
  endif
endforeach
