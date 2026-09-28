"""W3 对照演示：同一个注入输入，字符串拼接 vs 参数化查询。

本脚本只操作内存中的 SQLite 数据库，复现 labs/web/app.py 的 notes 表结构。
用途：生成讲义截图 fig-web-10-param-fix（参数化修复后同样输入失效）。
运行：python -X utf8 figures/raw/fig-web-10-param-fix.py
"""
import sqlite3


def make_db():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE notes (title TEXT, body TEXT)")
    db.executemany(
        "INSERT INTO notes VALUES (?, ?)",
        [
            ("public", "Try searching for a note by its title."),
            ("staff", "flag{sql_parameters_matter}"),
        ],
    )
    return db


db = make_db()
title = "' OR 1=1 -- "  # 与题 W2 完全相同的输入

print("input title :", repr(title))
print()

# 1) 修复前：f-string 把输入拼进 SQL 语句结构（app.py 第 39 行的写法）
sql_bad = f"SELECT title, body FROM notes WHERE title = '{title}'"
print("fix BEFORE  :", sql_bad)
print("fix BEFORE  rows:", db.execute(sql_bad).fetchall())
print()

# 2) 修复后：参数化查询，输入只作为数据
sql_fix = "SELECT title, body FROM notes WHERE title = ?"
print("fix AFTER   :", sql_fix, "   with params", (title,))
print("fix AFTER   rows:", db.execute(sql_fix, (title,)).fetchall())
print()
print("normal title 'public' still works:",
      db.execute(sql_fix, ("public",)).fetchall())
