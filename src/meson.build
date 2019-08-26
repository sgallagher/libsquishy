c = meson.get_compiler('c')

squishy_sources = [
  'checksum.c',
  'error.c',
  'squishy.c',
]

squishy_headers = [
  'checksum.h',
  'error.h',
  'squishy.h',
]

version_split = meson.project_version().split('.')
MAJOR_VERSION = version_split[0]
MINOR_VERSION = version_split[1]
MICRO_VERSION = version_split[2]

api_version = MAJOR_VERSION + '.0'

version_conf = configuration_data()
version_conf.set('VERSION', meson.project_version())
version_conf.set('MAJOR_VERSION', MAJOR_VERSION)
version_conf.set('MINOR_VERSION', MINOR_VERSION)
version_conf.set('MICRO_VERSION', MICRO_VERSION)

header_subdir = 'squishy-' + api_version

configure_file(
  input: 'squishy-version.h.in',
  output: 'squishy-version.h',
  configuration: version_conf,
  install_dir: join_paths(get_option('includedir'), header_subdir)
)

bzip2 = dependency('bzip2')
glib2 = dependency('glib-2.0')
libcrypto = dependency('libcrypto')
lzma = dependency('liblzma')
magic = c.find_library('magic')
zlib = dependency('zlib')
zstd = dependency('libzstd', required: false)

squishy_reqs = [
  bzip2,
  glib2,
  libcrypto,
  lzma,
  zlib,
]

if zstd.found()
  squishy_reqs += [ zstd ]
endif

squishy_deps = squishy_reqs + [magic]

squishy_lib = shared_library('squishy',
  squishy_sources,
  dependencies: squishy_deps,
  install: true,
  version: meson.project_version(),
)

install_headers(squishy_headers, subdir: header_subdir)

pkg = import('pkgconfig')

pkg.generate(
  description: 'A library for working with compressed files',
  libraries: squishy_lib,
  name: 'squishy',
  filebase: 'squishy-' + api_version,
  version: meson.project_version(),
  subdirs: header_subdir,
  requires_private: squishy_reqs,
)

