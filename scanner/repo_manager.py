"""Repository handling: Git clone, archive extraction, and path validation."""

import os
import shutil
import subprocess
import tempfile
import zipfile
import re
from typing import Tuple, Optional
from urllib.parse import urlparse


def is_safe_zip_path(target_dir: str, member_path: str) -> bool:
    """Protect against Zip Slip vulnerability (CWE-29)."""
    target_abs = os.path.abspath(target_dir)
    member_abs = os.path.abspath(os.path.join(target_dir, member_path))
    return os.path.commonpath([target_abs]) == os.path.commonpath([target_abs, member_abs])


def extract_zip(zip_path: str, extract_to: str) -> Tuple[bool, str]:
    """Safely extract uploaded ZIP archive with Zip Slip protection."""
    try:
        os.makedirs(extract_to, exist_ok=True)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for member in zip_ref.namelist():
                if not is_safe_zip_path(extract_to, member):
                    return False, f"Zip Slip vulnerability detected in archive entry: {member}"
                zip_ref.extract(member, extract_to)
        return True, extract_to
    except Exception as e:
        return False, f"Failed to extract zip file: {str(e)}"


def clone_git_repo(repo_url: str, branch: Optional[str] = None, dest_dir: Optional[str] = None) -> Tuple[bool, str]:
    """Safely clone a remote git repository with depth=1."""
    # Validate git URL to prevent command injection and protocol abuse
    clean_url = repo_url.strip()
    if not clean_url:
        return False, "Repository URL cannot be empty."

    # Validate against basic URL formats (https://, http://, git@)
    if not (clean_url.startswith("https://") or clean_url.startswith("http://") or clean_url.startswith("git@")):
        return False, "Invalid Git URL. Must start with https://, http://, or git@."

    # Check for shell metacharacters
    if any(c in clean_url for c in [";", "&", "|", "`", "$", "\n", "\r"]):
        return False, "Illegal characters detected in repository URL."

    if not dest_dir:
        dest_dir = tempfile.mkdtemp(prefix="sentinel_repo_")

    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        clean_branch = re.sub(r"[^a-zA-Z0-9_\-\./]", "", branch.strip())
        if clean_branch:
            cmd.extend(["-b", clean_branch])
    cmd.extend([clean_url, dest_dir])

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120
        )
        if proc.returncode != 0:
            shutil.rmtree(dest_dir, ignore_errors=True)
            return False, f"Git clone failed: {proc.stderr.strip()}"
        return True, dest_dir
    except subprocess.TimeoutExpired:
        shutil.rmtree(dest_dir, ignore_errors=True)
        return False, "Git clone timed out after 120 seconds."
    except Exception as e:
        shutil.rmtree(dest_dir, ignore_errors=True)
        return False, f"Error cloning repository: {str(e)}"
