bin_plugins = [
  'any',
  'art',
  'avr',
  'bf',
  'bflt',
  'bios',
  'bootimg',
  'cgc',
  'coff',
  'dex',
  'dmp64',
  'dol',
  'dyldcache',
  'elf',
  'elf64',
  'java',
  'le',
  'mach0',
  'mach064',
  'mbn',
  'mdmp',
  'menuet',
  'mz',
  'ne',
  'nes',
  'nin3ds',
  'ninds',
  'ningb',
  'ningba',
  'nro',
  'nso',
  'omf',
  'qnx',
  'p9',
  'pe',
  'pe64',
  'pebble',
  'prg',
  'psxexe',
  'sfc',
  'smd',
  'sms',
  'spc700',
  'symbols',
  'te',
  'vsf',
  'wasm',
  'xbe',
  'xnu_kernelcache',
  'z64',
  'zimg',
]

bin_xtr_plugins = [
  'xtr_dyldcache',
  'xtr_fatmach0',
  'xtr_sep64',
]

bin_enabled_static_plugins = bin_plugins
bin_enabled_shared_plugins = []

bin_xtr_enabled_static_plugins = bin_xtr_plugins
bin_xtr_enabled_shared_plugins = []

rz_bin_dependencies = [
  lz4_dep,
  yxml_dep,
  rz_util_dep,
  rz_socket_dep,
  rz_magic_dep,
  rz_hash_dep,
  rz_syscall_dep,
  rz_cons_dep,
  rz_io_dep,
]

bin_any_sources = [
  'p/bin_any.c',
]

bin_art_sources = [
  'p/bin_art.c',
]

bin_avr_sources = [
  'p/bin_avr.c',
]

bin_bf_sources = [
  'p/bin_bf.c',
]

bin_bflt_sources = [
  'p/bin_bflt.c',
  'format/bflt/bflt.c',
]

bin_bios_sources = [
  'p/bin_bios.c',
]

bin_bootimg_sources = [
  'p/bin_bootimg.c',
]

bin_cgc_sources = [
  'p/bin_cgc.c',
  'p/bin_dbginfo_elf.c',
  'p/bin_write_elf.c',
  'format/elf/elf.c',
  'format/elf/elf_write.c',
]

bin_coff_sources = [
  'p/bin_coff.c',
  'format/coff/coff.c',
]

bin_dex_sources = [
  'p/bin_dex.c',
  'p/bin_dbginfo_dex.c',
  'format/dex/dex.c',
]

bin_dmp64_sources = [
  'p/bin_dmp64.c',
  'format/dmp/dmp64.c',
]

bin_dol_sources = [
  'p/bin_dol.c',
]

bin_dyldcache_sources = [
  'p/bin_dyldcache.c',
  'format/mach0/mach0.c',
  'format/mach0/mach064.c',
  'format/objc/mach064_classes.c',
  'format/objc/mach0_classes.c',
]

bin_elf_sources = [
  'p/bin_elf.c',
  'p/bin_dbginfo_elf.c',
  'p/bin_write_elf.c',
  'format/elf/elf.c',
  'format/elf/elf_write.c',
]

bin_elf64_sources = [
  'p/bin_elf64.c',
  'p/bin_dbginfo_elf64.c',
  'p/bin_write_elf64.c',
  'format/elf/elf64.c',
  'format/elf/elf64_write.c',
]

bin_java_sources = [
  'p/bin_java.c',
  'format/java/class.c',
  'format/java/print.c',
  'format/java/json.c',
]

bin_le_sources = [
  'p/bin_le.c',
  'format/le/le.c',
]

bin_mach0_sources = [
  'p/bin_mach0.c',
  'p/bin_write_mach0.c',
  'format/mach0/coresymbolication.c',
  'format/mach0/dyldcache.c',
  'format/mach0/fatmach0.c',
  'format/mach0/mach0.c',
  'format/objc/mach0_classes.c',
]

bin_mach064_sources = [
  'p/bin_mach064.c',
  'p/bin_write_mach064.c',
  'format/mach0/mach064.c',
  'format/objc/mach064_classes.c',
]

bin_mbn_sources = [
  'p/bin_mbn.c',
]

bin_mdmp_sources = [
  'p/bin_mdmp.c',
  'format/mdmp/mdmp.c',
  'format/mdmp/mdmp_pe.c',
  'format/mdmp/mdmp_pe64.c',
  'format/pe/pe.c',
  'format/pe/pe64.c',
]

bin_menuet_sources = [
  'p/bin_menuet.c',
]

bin_mz_sources = [
  'p/bin_mz.c',
  'format/mz/mz.c',
]

bin_ne_sources = [
  'p/bin_ne.c',
  'format/ne/ne.c',
]

bin_nes_sources = [
  'p/bin_nes.c',
]

bin_nin3ds_sources = [
  'p/bin_nin3ds.c',
]

bin_ninds_sources = [
  'p/bin_ninds.c',
]

bin_ningb_sources = [
  'p/bin_ningb.c',
]

bin_ningba_sources = [
  'p/bin_ningba.c',
]

bin_nro_sources = [
  'p/bin_nro.c',
  'format/nxo/nxo.c',
]

bin_nso_sources = [
  'p/bin_nso.c',
  'format/nxo/nxo.c',
]

bin_nso_headers = [
  'format/nxo/',
]

bin_omf_sources = [
  'p/bin_omf.c',
  'format/omf/omf.c',
]

bin_omf_headers = [
  'format/omf/',
]

bin_p9_sources = [
  'p/bin_p9.c',
  'format/p9/p9bin.c',
]

bin_pe_sources = [
  'p/bin_pe.c',
  'p/bin_write_pe.c',
  'format/pe/pe.c',
  'format/pe/pe_write.c',
  'format/pe/pemixed.c',
]

bin_pe64_sources = [
  'p/bin_pe64.c',
  'p/bin_write_pe64.c',
  'format/pe/pe64.c',
  'format/pe/pe64_write.c',
]

bin_pebble_sources = [
  'p/bin_pebble.c',
]

bin_prg_sources = [
  'p/bin_prg.c',
]

bin_psxexe_sources = [
  'p/bin_psxexe.c',
]

bin_pyc_sources = [
  'p/bin_pyc.c',
  'format/pyc/marshal.c',
  'format/pyc/pyc.c',
  'format/pyc/pyc_magic.c',
]

bin_qnx_sources = [
  'p/bin_qnx.c',
]

bin_qnx_headers = [
  'format/qnx/',
]

bin_sfc_sources = [
  'p/bin_sfc.c',
]

bin_smd_sources = [
  'p/bin_smd.c',
]

bin_sms_sources = [
  'p/bin_sms.c',
]

bin_spc700_sources = [
  'p/bin_spc700.c',
]

bin_symbols_sources = [
  'p/bin_symbols.c',
  'format/mach0/coresymbolication.c',
]

bin_te_sources = [
  'p/bin_te.c',
  'format/te/te.c',
]

bin_vsf_sources = [
  'p/bin_vsf.c',
]

bin_wasm_sources = [
  'p/bin_wasm.c',
  'format/wasm/wasm.c',
]

bin_xbe_sources = [
  'p/bin_xbe.c',
]

bin_xnu_kernelcache_sources = [
  'p/bin_xnu_kernelcache.c',
  'format/mach0/mach064.c',
  'format/xnu/rz_cf_dict.c',
]

bin_xtr_dyldcache_sources = [
  'p/bin_xtr_dyldcache.c',
  'format/mach0/dyldcache.c',
  'format/mach0/mach0.c',
]

bin_xtr_fatmach0_sources = [
  'p/bin_xtr_fatmach0.c',
  'format/mach0/fatmach0.c',
  'format/mach0/mach0.c',
]

bin_xtr_pemixed_sources = [
  'p/bin_xtr_pemixed.c',
]

bin_xtr_sep64_sources = [
  'p/bin_xtr_sep64.c',
  'format/mach0/mach064.c',
]

bin_z64_sources = [
  'p/bin_z64.c',
]

bin_zimg_sources = [
  'p/bin_zimg.c',
  'format/zimg/zimg.c',
]

# compile static plugins
rz_bin_plugins_dep = []
foreach p : bin_plugins + bin_xtr_plugins
  c_files = get_variable('bin_@0@_sources'.format(p))
  h_files = get_variable('bin_@0@_headers'.format(p), [])
  bin_plugin_deps = get_variable('bin_@0@_deps'.format(p), [])

  h_files = include_directories([h_files, 'format/'])
  name = 'bin_plugin_@0@'.format(p)
  bin_plugin_inc = [h_files, platform_inc]

  if p in bin_enabled_static_plugins or p in bin_xtr_enabled_static_plugins
    bin_plugin = static_library(name, c_files,
      include_directories: bin_plugin_inc,
      dependencies: rz_bin_dependencies + bin_plugin_deps,
      c_args: library_cflags,
      install: false,
    )

    bin_plugin_dep = declare_dependency(link_with: bin_plugin, include_directories: bin_plugin_inc)
    set_variable(name + '_dep', bin_plugin_dep)
    rz_bin_plugins_dep += [bin_plugin_dep]
  endif
endforeach

rz_bin_sources = [
  'bin.c',
  'bin_write.c',
  'dbginfo.c',
  'demangle.c',
  'dwarf.c',
  'blang.c',
  'filter.c',
  'bfile.c',
  'bobj.c',

  'mangling/cxx.c',
  'mangling/cxx/cp-demangle.c',
  'mangling/demangler.c',
  'mangling/rust.c',
  'mangling/java.c',
  'mangling/microsoft_demangle.c',
  'mangling/msvc.c',
  'mangling/objc.c',
  'mangling/swift-sd.c',
  'mangling/swift.c',

  'pdb/dbi.c',
  'pdb/fpo.c',
  'pdb/gdata.c',
  'pdb/omap.c',
  'pdb/pdb.c',
  'pdb/pdb_downloader.c',
  'pdb/stream_file.c',
  'pdb/stream_pe.c',
  'pdb/tpi.c'
]

rz_bin_inc = [platform_inc, include_directories('mangling', 'format')]

rz_bin = library('rz_bin', rz_bin_sources,
  include_directories: rz_bin_inc,
  c_args: ['-DRZ_API_BIN_ONLY=1'] + library_cflags,
  dependencies: rz_bin_dependencies + rz_bin_plugins_dep,
  install: true,
  implicit_include_directories: false,
  install_rpath: rpath_lib,
  soversion: rizin_libversion
)

rz_bin_dep = declare_dependency(link_with: rz_bin,
                               include_directories: rz_bin_inc)

pkgconfig_mod.generate(rz_bin,
  subdirs: 'librz',
  version: rizin_version,
  name: 'rz_bin',
  filebase: 'rz_bin',
  libraries: pkgcfg_sanitize_libs,
  requires: pkgconfig_magic_requires + [
    'rz_util',
    'rz_io',
    'rz_socket',
    'rz_syscall'
  ],
  description: 'rizin foundation libraries'
)

# compile shared plugins
foreach p : bin_plugins + bin_xtr_plugins
  c_files = get_variable('bin_@0@_sources'.format(p))
  h_files = get_variable('bin_@0@_headers'.format(p), [])
  bin_plugin_deps = get_variable('bin_@0@_deps'.format(p), [])

  h_files = include_directories([h_files, 'format/'])
  name = 'bin_plugin_@0@'.format(p)
  bin_plugin_inc = [h_files, platform_inc]

  if p in bin_enabled_shared_plugins or p in bin_xtr_enabled_shared_plugins
    bin_plugin = shared_library(name, c_files,
      include_directories: bin_plugin_inc,
      dependencies: [rz_bin_dependencies, rz_bin_dep, bin_plugin_deps],
      install: true,
      install_dir: rizin_plugins,
    )
  endif
endforeach
