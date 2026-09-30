import importlib.util
for name in ("capstone", "pefile", "lief", "unicorn", "r2pipe", "PIL"):
    print(f"{name}: {'available' if importlib.util.find_spec(name) else 'missing'}")
