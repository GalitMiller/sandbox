# -*- coding: utf-8 -*-
from __future__ import absolute_import

import os
import subprocess

from functools import partial
from git import Repo
from git.cmd import GitCommandError
from slugify import slugify


format_branch_name = partial(slugify, to_lower=True)


def is_branch_name_valid(name):
    with open(os.devnull, 'w') as devnull:
        process = subprocess.Popen(
            args=["git", "check-ref-format", "--branch", name],
            stdout=devnull,
            stderr=devnull,
        )
        exit_status = process.wait()
        return exit_status == 0


def get_repo(local_uri, remote_uri):
    return (Repo(local_uri)
            if os.path.exists(local_uri) else
            Repo.clone_from(remote_uri, local_uri))


def checkout_n_pull_branch(repo, remote, branch_name):
    try:
        branch = repo.branches[branch_name]
    except IndexError:
        branch = repo.create_head(branch_name)

    branch.checkout()

    try:
        repo.git.pull(remote.name, branch.name)
    except GitCommandError:
        remote.pull()

    return branch


def push_branch(repo, remote, branch):
    if branch.tracking_branch():
        return remote.push()
    else:
        return repo.git.push('--set-upstream', remote.name, branch.name)


def delete_branch(repo, remote, branch):
    repo.delete_head(branch)
    repo.git.push(remote.name, '--delete', branch.name)
    return remote.push()
