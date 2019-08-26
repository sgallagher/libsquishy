project('libsquishy', 'c',
        version: '1.0.0',
  meson_version: '>= 0.47.0',
)


config_h = configuration_data()
config_h.set_quoted('PACKAGE_VERSION', meson.project_version())
configure_file(
  output: 'squishy-config.h',
  configuration: config_h,
)
add_project_arguments([
  '-I' + meson.build_root(),
], language: 'c')

subdir('src')

