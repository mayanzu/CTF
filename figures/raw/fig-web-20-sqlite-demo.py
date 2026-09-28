"""fig-web-20 演示：字符串拼接把"数据"变成了"结构"。

只操作内存里的 SQLite 数据库，复现 labs/web/app.py 的 notes 表与第 39 行的拼接写法，
不启动任何网络服务（避免端口冲突）。同一个拼接位置，分别送入「正常标题」与
「注入输入」，让读者肉眼看到：数据里的单引号如何跑到字符串外面，变成 SQL 语法。

运行：
    python -X utf8 figures/raw/fig-web-20-sqlite-demo.py normal
    python -X utf8 figures/raw/fig-web-20-sqlite-demo.py inject
"""
import sqlite3
import sys


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


def show(mode):
    db = make_db()
    title = "public" if mode == "normal" else "' OR 1=1 -- "
    # 与 labs/web/app.py 第 39 行完全相同的拼接写法（故意不安全）
    sql = f"SELECT title, body FROM notes WHERE title = '{title}'"
    print("mode    :", mode)
    print("input   :", repr(title))
    print()
    print("--- 拼出来的 SQL（外部数据直接进入语句结构）---")
    print(sql)
    print()
    print("--- 数据库实际返回 ---")
    for row in db.execute(sql).fetchall():
        print(row)


if __name__ == "__main__":
    show(sys.argv[1] if len(sys.argv) > 1 else "normal")