import importlib.util

for name in ('panda', 'panda_file', 'ark', 'ark_disasm', 'abc2proto', 'capstone', 'lief', 'construct'):
    try:
        spec = importlib.util.find_spec(name)
        print(f'{name}: {spec.origin if spec else "NOT INSTALLED"}')
    except (ImportError, ModuleNotFoundError, ValueError) as exc:
        print(f'{name}: NOT INSTALLED ({type(exc).__name__})')
