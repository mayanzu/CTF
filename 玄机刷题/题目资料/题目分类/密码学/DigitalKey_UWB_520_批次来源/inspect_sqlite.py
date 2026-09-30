from pathlib import Path
import sqlite3
p = Path(__file__).parent / 'extracted' / 'digital_key_trace.sqlite'
uri = 'file:' + str(p).replace('\\', '/') + '?mode=ro'
con = sqlite3.connect(uri, uri=True)
con.row_factory = sqlite3.Row
print('database=', p)
for row in con.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name"):
    print('SCHEMA', dict(row))
    if row['type'] == 'table':
        cols = [r['name'] for r in con.execute(f"PRAGMA table_info(\"{row['name']}\")")]
        count = con.execute(f"SELECT COUNT(*) FROM \"{row['name']}\"").fetchone()[0]
        print('TABLE', row['name'], 'columns=', cols, 'rows=', count)
        for item in con.execute(f"SELECT * FROM \"{row['name']}\" LIMIT 100"):
            vals = {}
            for key in item.keys():
                val = item[key]
                vals[key] = {'hex': val.hex(), 'length': len(val)} if isinstance(val, bytes) else val
            print('ROW', vals)
con.close()
