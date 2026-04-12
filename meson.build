project('gtk4-demo', 'c',
  version : '1.0.0',
  default_options : ['c_std=c11', 'warning_level=2']
)

gtk4_dep = dependency('gtk4')

executable('gtk4-demo',
  sources : ['main.c'],
  dependencies : [gtk4_dep],
  win_subsystem : 'windows',   # no console window on Windows
  install : true,
)
