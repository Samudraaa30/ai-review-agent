from git import Repo
from pathlib import Path
import uuid

from pathlib import Path

REPOS_DIR = Path("repos")

REPOS_DIR.mkdir(
    parents=True,
    exist_ok=True
)

def clone_repository(repo_url):

    repo_id = str(uuid.uuid4())

    target_path = REPOS_DIR / repo_id

    Repo.clone_from(
        repo_url,
        target_path
    )

    return str(target_path)