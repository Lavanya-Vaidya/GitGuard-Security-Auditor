import pytest
from diffparse import should_skip_file, parse_numbered_diff


def test_should_skip_empty_or_binary():
    skip, reason = should_skip_file("test.py", None)
    assert skip is True
    assert "No patch" in reason

    skip, reason = should_skip_file("test.py", "")
    assert skip is True


def test_should_skip_lockfiles():
    lockfiles = [
        "package-lock.json",
        "yarn.lock",
        "poetry.lock",
        "Pipfile.lock",
        "go.sum",
        "Cargo.lock",
    ]
    for lf in lockfiles:
        skip, reason = should_skip_file(f"frontend/{lf}", "patch content")
        assert skip is True
        assert "Lockfile" in reason


def test_should_skip_binary_extensions():
    binaries = ["image.png", "logo.svg", "archive.zip", "font.woff2", "module.pyc"]
    for b in binaries:
        skip, reason = should_skip_file(f"assets/{b}", "some content")
        assert skip is True
        assert "Excluded file extension" in reason


def test_should_skip_minified_and_dist():
    assert should_skip_file("static/bundle.min.js", "patch")[0] is True
    assert should_skip_file("dist/app.js", "patch")[0] is True
    assert should_skip_file("build/main.css", "patch")[0] is True
    assert should_skip_file("src/client.generated.ts", "patch")[0] is True


def test_should_not_skip_standard_source_files():
    assert should_skip_file("src/app.py", "@@ -1,3 +1,3 @@")[0] is False
    assert should_skip_file("lib/auth.js", "@@ -10,5 +10,6 @@")[0] is False
    assert should_skip_file("internal/db/query.go", "@@ -20,2 +20,4 @@")[0] is False


def test_parse_numbered_diff_single_hunk():
    patch = """@@ -10,3 +15,4 @@
 def handle_login(user, password):
-    query = "SELECT * FROM users WHERE u = '" + user + "'"
+    # Sanitize input or use parameterized queries
+    query = "SELECT * FROM users WHERE u = %s"
+    cursor.execute(query, (user,))
     return cursor.fetchall()"""

    numbered_diff, added_lines = parse_numbered_diff(patch)

    assert added_lines == {16, 17, 18}
    assert "16: +     # Sanitize input or use parameterized queries" in numbered_diff
    assert "17: +     query = \"SELECT * FROM users WHERE u = %s\"" in numbered_diff
    assert "18: +     cursor.execute(query, (user,))" in numbered_diff
    assert "-     query = \"SELECT * FROM users WHERE u = '\" + user + \"'\"" in numbered_diff


def test_parse_numbered_diff_multiple_hunks():
    patch = """@@ -1,3 +1,4 @@
 import os
+import hashlib
 
 def a():
@@ -10,2 +11,3 @@
     pass
+    eval(user_input)
"""

    numbered_diff, added_lines = parse_numbered_diff(patch)

    assert added_lines == {2, 12}
    assert "   2: + import hashlib" in numbered_diff
    assert "  12: +     eval(user_input)" in numbered_diff
