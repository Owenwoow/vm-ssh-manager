from __future__ import annotations

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]


def add_file(archive: ZipFile, path: Path, arcname: str) -> None:
    if path.is_file():
        archive.write(path, arcname)


def add_tree(archive: ZipFile, folder: Path, prefix: str) -> None:
    if not folder.exists():
        return
    for path in sorted(folder.rglob("*")):
        if not path.is_file():
            continue
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        archive.write(path, f"{prefix}/{path.relative_to(folder).as_posix()}")


def create_source_archives() -> None:
    cli_path = ROOT / "01-CLI" / "VM-SSH-CLI-Source.zip"
    gui_path = ROOT / "02-GUI" / "VM-SSH-GUI-Source.zip"
    common = [ROOT / "pyproject.toml", ROOT / "requirements.txt", ROOT / "requirements-test.txt"]
    shared_parts = ["core", "utils"]

    with ZipFile(cli_path, "w", ZIP_DEFLATED) as archive:
        for path in common:
            add_file(archive, path, f"VM-SSH-CLI-Source/{path.name}")
        add_file(archive, ROOT / "requirements-cli.txt", "VM-SSH-CLI-Source/requirements-cli.txt")
        add_file(archive, ROOT / "README.md", "VM-SSH-CLI-Source/PROJECT-README.md")
        add_file(archive, ROOT / "01-CLI" / "README.md", "VM-SSH-CLI-Source/README.md")
        add_file(archive, ROOT / "04-Build" / "build_cli.bat", "VM-SSH-CLI-Source/04-Build/build_cli.bat")
        add_file(archive, ROOT / "src" / "vmssh" / "__init__.py", "VM-SSH-CLI-Source/src/vmssh/__init__.py")
        add_tree(archive, ROOT / "src" / "vmssh" / "cli", "VM-SSH-CLI-Source/src/vmssh/cli")
        for part in shared_parts:
            add_tree(archive, ROOT / "src" / "vmssh" / part, f"VM-SSH-CLI-Source/src/vmssh/{part}")
        add_tree(archive, ROOT / "tests", "VM-SSH-CLI-Source/tests")

    with ZipFile(gui_path, "w", ZIP_DEFLATED) as archive:
        for path in common:
            add_file(archive, path, f"VM-SSH-GUI-Source/{path.name}")
        add_file(archive, ROOT / "requirements-gui.txt", "VM-SSH-GUI-Source/requirements-gui.txt")
        add_file(archive, ROOT / "README.md", "VM-SSH-GUI-Source/PROJECT-README.md")
        add_file(archive, ROOT / "02-GUI" / "README.md", "VM-SSH-GUI-Source/README.md")
        add_file(archive, ROOT / "04-Build" / "build_gui.bat", "VM-SSH-GUI-Source/04-Build/build_gui.bat")
        add_file(archive, ROOT / "src" / "vmssh" / "__init__.py", "VM-SSH-GUI-Source/src/vmssh/__init__.py")
        add_tree(archive, ROOT / "src" / "vmssh" / "gui", "VM-SSH-GUI-Source/src/vmssh/gui")
        for part in shared_parts:
            add_tree(archive, ROOT / "src" / "vmssh" / part, f"VM-SSH-GUI-Source/src/vmssh/{part}")
        add_tree(archive, ROOT / "tests", "VM-SSH-GUI-Source/tests")


def create_complete_archive() -> Path:
    output = ROOT / "VM-SSH-Manager-v1.0.0-Complete.zip"
    excluded_dirs = {".git", ".venv", "__pycache__", ".pytest_cache", "build", "dist"}
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for path in sorted(ROOT.rglob("*")):
            if not path.is_file() or path == output:
                continue
            relative = path.relative_to(ROOT)
            if any(part in excluded_dirs for part in relative.parts):
                continue
            if path.suffix in {".pyc", ".pyo"}:
                continue
            archive.write(path, f"VM-SSH-Manager-v1.0.0/{relative.as_posix()}")
    return output


if __name__ == "__main__":
    create_source_archives()
    complete = create_complete_archive()
    print(f"Created: {ROOT / '01-CLI' / 'VM-SSH-CLI-Source.zip'}")
    print(f"Created: {ROOT / '02-GUI' / 'VM-SSH-GUI-Source.zip'}")
    print(f"Created: {complete}")
