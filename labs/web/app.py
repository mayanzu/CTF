"""Two intentionally vulnerable, localhost-only CTF exercises.

Use this only as a disposable lab. It listens on 127.0.0.1 by design.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
import sqlite3


def make_db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE notes (title TEXT, body TEXT)")
    db.executemany(
        "INSERT INTO notes VALUES (?, ?)",
        [
            ("public", "Try searching for a note by its title."),
            ("staff", "flag{sql_parameters_matter}"),
        ],
    )
    return db


DB = make_db()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = urlsplit(self.path)
        query = parse_qs(route.query)
        if route.path == "/":
            body = "Try /gate?role=guest and /notes?title=public\n"
        elif route.path == "/gate":
            role = query.get("role", ["guest"])[0]
            body = "flag{http_query_is_input}\n" if role == "admin" else "Access denied\n"
        elif route.path == "/notes":
            title = query.get("title", ["public"])[0]
            # Deliberately unsafe string interpolation for this lab.
            sql = f"SELECT title, body FROM notes WHERE title = '{title}'"
            try:
                rows = DB.execute(sql).fetchall()
                body = "\n".join(f"{name}: {note}" for name, note in rows) or "No note found"
                body += "\n"
            except sqlite3.Error as exc:
                body = f"SQL error: {exc}\n"
        else:
            self.send_error(404)
            return
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    print("Lab server: http://127.0.0.1:8765/", flush=True)
    server.serve_forever()
