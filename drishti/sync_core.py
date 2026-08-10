#!/usr/bin/env python3
"""
Keep the shared engine identical in both builds.

Drishti.py and Drishti_cli.py are deliberately standalone single files, so the
engine they share is physically duplicated: everything from the config section
down to the end of the AI layer. Edit one and the other silently goes stale.
This is the guard against that.

    python3 sync_core.py            report whether they match
    python3 sync_core.py --from-cli copy the CLI's engine into the web build
    python3 sync_core.py --from-web copy the web build's engine into the CLI
    python3 sync_core.py --diff     show what differs

Exit code is 0 when they match and 1 when they have drifted, so it drops into
a pre-commit hook or CI step.
"""

import difflib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(HERE, "Drishti_cli.py")
WEB = os.path.join(HERE, "Drishti.py")

MARK = "# ---------------------------------------------------------------- "
START = MARK + "config"
CLI_END = MARK + "render"   # the CLI's terminal renderer starts here
WEB_END = MARK + "page"     # the web build's HTML starts here


def slice_core(path, end_marker):
    """Return (before, core, after) for one file."""
    text = open(path).read()
    try:
        i = text.index(START)
        j = text.index(end_marker)
    except ValueError:
        raise SystemExit("%s: could not find the engine markers, has the file "
                         "structure changed?" % os.path.basename(path))
    if j < i:
        raise SystemExit("%s: markers are out of order" % os.path.basename(path))
    return text[:i], text[i:j], text[j:]


def cores():
    _, cli_core, _ = slice_core(CLI, CLI_END)
    _, web_core, _ = slice_core(WEB, WEB_END)
    return cli_core.rstrip() + "\n", web_core.rstrip() + "\n"


def write_core(path, end_marker, core):
    before, _old, after = slice_core(path, end_marker)
    with open(path, "w") as fh:
        fh.write(before + core.rstrip() + "\n\n\n" + after)


def main(argv):
    action = argv[1] if len(argv) > 1 else "--check"
    cli_core, web_core = cores()
    same = cli_core == web_core

    if action in ("--check", "-c"):
        if same:
            print("engine in sync, %d lines shared by both builds"
                  % cli_core.count("\n"))
            return 0
        print("ENGINE HAS DRIFTED between Drishti_cli.py and Drishti.py")
        print("run sync_core.py --diff to see it, then --from-cli or --from-web")
        return 1

    if action == "--diff":
        if same:
            print("no difference")
            return 0
        diff = difflib.unified_diff(
            cli_core.splitlines(True), web_core.splitlines(True),
            fromfile="Drishti_cli.py engine", tofile="Drishti.py engine")
        sys.stdout.writelines(diff)
        return 1

    if action == "--from-cli":
        if same:
            print("already in sync, nothing to do")
            return 0
        write_core(WEB, WEB_END, cli_core)
        print("copied the CLI engine into Drishti.py")
        return verify()

    if action == "--from-web":
        if same:
            print("already in sync, nothing to do")
            return 0
        write_core(CLI, CLI_END, web_core)
        print("copied the web engine into Drishti_cli.py")
        return verify()

    print(__doc__)
    return 2


def verify():
    """After a copy, both files must still parse and resolve every global."""
    import ast
    import builtins

    ok = True
    for path in (CLI, WEB):
        name = os.path.basename(path)
        src = open(path).read()
        try:
            tree = ast.parse(src)
        except SyntaxError as exc:
            print("  %s does not parse: %s" % (name, exc))
            ok = False
            continue

        defined = set(dir(builtins))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                defined.add(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        defined.add(target.id)
            elif isinstance(node, ast.Import):
                defined.update((a.asname or a.name.split(".")[0]) for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                defined.update((a.asname or a.name) for a in node.names)
            elif isinstance(node, ast.Try):
                for sub in node.body:
                    if isinstance(sub, ast.ImportFrom):
                        defined.update((a.asname or a.name) for a in sub.names)

        missing = set()
        # Only walk top level functions. Nested functions close over their
        # parent's names, so treating the whole subtree as one scope is what
        # keeps closure variables from reading as undefined.
        for fn in [n for n in tree.body if isinstance(n, ast.FunctionDef)]:
            local = set()
            for n in ast.walk(fn):
                if isinstance(n, ast.arg):
                    local.add(n.arg)
                elif isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                    local.add(n.id)
                elif isinstance(n, (ast.FunctionDef, ast.ClassDef)):
                    local.add(n.name)
                elif isinstance(n, ast.ExceptHandler) and n.name:
                    local.add(n.name)
                elif isinstance(n, (ast.Global, ast.Nonlocal)):
                    local.update(n.names)
                for comp in getattr(n, "generators", []):
                    for t in ast.walk(comp.target):
                        if isinstance(t, ast.Name):
                            local.add(t.id)
            for n in ast.walk(fn):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                    if n.id not in defined and n.id not in local:
                        missing.add(n.id)
        if missing:
            print("  %s references names it does not define: %s"
                  % (name, ", ".join(sorted(missing))))
            print("  the engine probably needs a constant or import that lives "
                  "above the config marker in the other file")
            ok = False
        else:
            print("  %s parses and every global resolves" % name)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
