# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
import operator
import traceback

from isotopic_logging import autoprefix_injector, direct_injector
from unipath import Path, FILES

from app import celery
from app.config import RULES_REPO, SENSOR_COMMANDS
from app.db import db
from app.sensors.utils import connect_n_exec_sensor_command
from app.signatures.helpers import signatures_to_rules
from app.utils import git
from app.utils.encoding import smart_str
from app.utils.six.moves import map

from .exceptions import PolicyApplicationWarning, PolicyApplicationError
from .helpers import generate_policy_rules_filename


LOG = logging.getLogger(__name__)


class InvokePolicyApplicationGroupTask(celery.Task):

    def run(self, application_group_id, operation_prefix, *args, **kwargs):
        self.application_group_id = application_group_id

        with direct_injector(operation_prefix) as inj:
            LOG.info(inj.mark(
                "Invoking policy application group #{id}..."
                .format(id=application_group_id)))

            try:
                self._invoke_application_group()
            except PolicyApplicationWarning as w:
                LOG.warning(inj.mark(smart_str(w)))
            except PolicyApplicationError as e:
                LOG.error(inj.mark(
                    "Failed to invoke policy application group #{id}: {e}"
                    .format(id=application_group_id, e=e)))
            except Exception as e:
                LOG.error(inj.mark(
                    "Failed to invoke policy application group #{id}: {e}\n"
                    "{traceback}"
                    .format(id=application_group_id,
                            e=e,
                            traceback=traceback.format_exc())))
            else:
                LOG.info(inj.mark(
                    "Policies were successfully applied."))

    def _invoke_application_group(self):
        self._inject_application_group()
        self._inject_repo()
        self._inject_branch()

        try:
            self._cleanup_directory()
            self._flush_all_rules()
            self._upload_all_rules()
            self._update_policies_meta_data()
        finally:
            self.repo.branches.master.checkout()

    def _inject_application_group(self):
        from .models import PolicyApplicationGroup

        with autoprefix_injector() as inj:
            self.application_group = (PolicyApplicationGroup.query
                                      .get(self.application_group_id))

            if self.application_group:
                names = map(operator.attrgetter('policy.name'),
                            self.application_group.applications)
                names = map(lambda x: "'{0}'".format(x), names)
                names = ', '.join(names)
                LOG.debug(inj.mark(
                    "Policies to be applied: {0}.".format(names)))
            else:
                raise PolicyApplicationError(
                    "Policy application group #{id} does not exist"
                    .format(id=self.application_group_id))

    def _inject_repo(self):
        self.repo = git.get_repo(RULES_REPO.LOCAL.URI, RULES_REPO.REMOTE.URI)
        self.remote = self.repo.remote(RULES_REPO.REMOTE.NAME)
        self._ensure_repo_config()

        with autoprefix_injector() as inj:
            LOG.debug(inj.mark(
                "Working with local rules repo '{path}'"
                .format(path=self.repo.working_dir)))

    def _ensure_repo_config(self):
        config = self.repo.config_writer()
        config.set_value('user', 'name', RULES_REPO.USER.NAME)
        config.set_value('user', 'email', RULES_REPO.USER.EMAIL)

    def _inject_branch(self):
        with autoprefix_injector() as inj:
            interface = self.application_group.interface
            interface.ensure_git_branch_name()

            LOG.debug(inj.mark(
                "Checking out branch '{name}'"
                .format(name=interface.git_branch_name)))

            self.branch = git.checkout_n_pull_branch(
                self.repo, self.remote, interface.git_branch_name
            )

    def _cleanup_directory(self):
        with autoprefix_injector() as inj:
            paths = Path(self.repo.working_dir).listdir(filter=FILES)
            if paths:
                LOG.debug(inj.mark("Cleaning up working directory..."))

                tracked = map(operator.itemgetter(0),
                              self.repo.index.entries.keys())
                self.repo.index.remove(tracked)

                for path in paths:
                    LOG.debug(inj.mark(
                        "Removing file {filename}..."
                        .format(filename=path.name)))
                    path.remove()

    def _flush_all_rules(self):
        for application in self.application_group.applications:
            self._flush_policy_application_rules(application)

    def _flush_policy_application_rules(self, application):
        with autoprefix_injector() as inj:
            LOG.debug(inj.mark(
                "Processing policy '{name}' with action '{action}'..."
                .format(name=application.policy.name,
                        action=application.action)))

            self.application = application
            self._ensure_target_filename()

            LOG.debug(inj.mark(
                "Flushing rules to file '{name}'..."
                .format(name=application.target_filename)))

            file_path = Path(self.repo.working_dir).child(application.target_filename)
            rules = signatures_to_rules(application.policy.signatures)

            with open(file_path, 'w') as f:
                f.write("# ACTION {0}\n\n".format(application.action))

                for rule in rules:
                    f.write(rule)

                f.flush()

    def _ensure_target_filename(self):
        filename = generate_policy_rules_filename(self.application.policy)
        self.application.target_filename = filename
        db.session.add(self.application)
        db.session.commit()

    def _upload_all_rules(self):
        self._commit_changes()
        self._push_changes()
        self._pull_n_apply_rules_on_sensor()

    def _commit_changes(self):
        with autoprefix_injector() as inj:
            filenames = map(operator.attrgetter('target_filename'),
                            self.application_group.applications)
            self.repo.index.add(list(filenames))

            names = map(operator.attrgetter('policy.name'),
                        self.application_group.applications)
            names = map(lambda x: "'{0}'".format(x), names)
            names = ", ".join(names)
            commit_message = "Apply policies {0}.".format(names)

            LOG.debug(inj.mark(
                "Commiting with message '{message}'..."
                .format(message=commit_message)))

            commit = self.repo.index.commit(commit_message)
            LOG.debug(inj.mark(
                "Commit SHA: {sha}".format(sha=commit.hexsha)))

    def _push_changes(self):
        with autoprefix_injector() as inj:
            LOG.debug(inj.mark("Pushing to upstream..."))
            push_info = git.push_branch(self.repo, self.remote, self.branch)
            try:
                (push_info, ) = push_info
            except ValueError:
                summary = None
            else:
                summary = push_info.summary
            finally:
                if summary is None:
                    summary = "N/A"
                LOG.debug(inj.mark(
                    "Push summary: {summary}".format(summary=summary)))

    def _pull_n_apply_rules_on_sensor(self):
        interface = self.application_group.interface

        chunks = [
            "sudo -S",
            SENSOR_COMMANDS.SSH.PULL_N_APPLY_RULES.COMMAND,
        ]
        args = [
            interface.git_branch_name,
            interface.name,
        ]
        chunks.extend(map(lambda x: '"{0}"'.format(x), args))
        command = ' '.join(chunks)

        with autoprefix_injector() as inj:
            LOG.debug(inj.mark("Pulling and applying rules on sensor..."))
            connect_n_exec_sensor_command(
                interface.sensor,
                command,
                SENSOR_COMMANDS.SSH.PULL_N_APPLY_RULES.CONN_TIMEOUT,
                SENSOR_COMMANDS.SSH.PULL_N_APPLY_RULES.EXEC_TIMEOUT,
            )

    def _update_policies_meta_data(self):
        for app in self.application_group.applications:
            app.policy.last_applied_at = self.application_group.last_applied_at
            app.policy.last_applied_by = self.application_group.last_applied_by
            db.session.add(app.policy)

        db.session.commit()

invoke_policy_application_group = InvokePolicyApplicationGroupTask()
