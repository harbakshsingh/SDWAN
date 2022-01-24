import argparse
from typing import Union, Optional
from cisco_sdwan.__version__ import __doc__ as title
from cisco_sdwan.base.rest_api import Rest, RestAPIException
from cisco_sdwan.base.models_vmanage import EdgeCertificate, EdgeCertificateSync
from cisco_sdwan.tasks.utils import TaskOptions, existing_workdir_type, regex_type, default_workdir
from cisco_sdwan.tasks.common import regex_search, Task, WaitActionsException


@TaskOptions.register('certificate')
class TaskCertificate(Task):
    SAVINGS_FACTOR = 0.2

    @staticmethod
    def parser(task_args, target_address=None):
        task_parser = argparse.ArgumentParser(description=f'{title}\nCertificate task:')
        task_parser.prog = f'{task_parser.prog} certificate'
        task_parser.formatter_class = argparse.RawDescriptionHelpFormatter

        sub_tasks = task_parser.add_subparsers(title='certificate options')
        sub_tasks.required = True

        restore_parser = sub_tasks.add_parser('restore', help='restore certificate status from a backup')
        restore_parser.set_defaults(source_iter=TaskCertificate.restore_iter)
        restore_parser.add_argument('--workdir', metavar='<directory>', type=existing_workdir_type,
                                    default=default_workdir(target_address),
                                    help='restore source (default: %(default)s)')

        set_parser = sub_tasks.add_parser('set', help='set certificate status')
        set_parser.set_defaults(source_iter=TaskCertificate.set_iter)
        set_parser.add_argument('status', choices=['invalid', 'staging', 'valid'],
                                help='WAN edge certificate status')

        # Parameters common to all sub-tasks
        for sub_task in (restore_parser, set_parser):
            mutex = sub_task.add_mutually_exclusive_group()
            mutex.add_argument('--regex', metavar='<regex>', type=regex_type,
                               help='regular expression selecting devices to modify certificate status. Matches on '
                                    'the hostname or chassis/uuid. Use "^-$" to match devices without a hostname.')
            mutex.add_argument('--not-regex', metavar='<regex>', type=regex_type,
                               help='regular expression selecting devices NOT to modify certificate status. Matches on '
                                    'the hostname or chassis/uuid.')
            sub_task.add_argument('--dryrun', action='store_true',
                                  help='dry-run mode. List modifications that would be performed without pushing '
                                       'changes to vManage.')

        return task_parser.parse_args(task_args)

    @staticmethod
    def restore_iter(target_certs, parsed_args):
        saved_certs = EdgeCertificate.load(parsed_args.workdir)
        if saved_certs is None:
            raise FileNotFoundError('WAN edge certificates were not found in the backup')

        saved_certs_dict = {uuid: status for uuid, status in saved_certs}

        return (
            (uuid, status, hostname, saved_certs_dict[uuid])
            for uuid, status, hostname, chassis, serial, state in target_certs.extended_iter()
            if uuid in saved_certs_dict
        )

    @staticmethod
    def set_iter(target_certs, parsed_args):
        return (
            (uuid, status, hostname, parsed_args.status)
            for uuid, status, hostname, chassis, serial, state in target_certs.extended_iter()
        )

    def runner(self, parsed_args, api: Optional[Rest] = None) -> Union[None, list]:
        if parsed_args.source_iter is TaskCertificate.restore_iter:
            start_msg = f'Restore status from workdir: "{parsed_args.workdir}" -> vManage URL: "{api.base_url}"'
        else:
            start_msg = f'Set status to "{parsed_args.status}" -> vManage URL: "{api.base_url}"'
        self.log_info('Starting certificate%s: %s', ', DRY-RUN mode' if parsed_args.dryrun else '', start_msg)

        try:
            self.log_info('Loading WAN edge certificate list from target vManage')
            target_certs = EdgeCertificate.get_raise(api)

            regex = parsed_args.regex or parsed_args.not_regex
            matched_items = (
                (uuid, current_status, hostname, new_status)
                for uuid, current_status, hostname, new_status in parsed_args.source_iter(target_certs, parsed_args)
                if regex is None or regex_search(regex, hostname or '-', uuid, inverse=parsed_args.regex is None)
            )
            update_list = []
            self.log_info('Identifying items to be pushed')
            log_prefix = 'DRY-RUN: ' if parsed_args.dryrun else ''
            for uuid, current_status, hostname, new_status in matched_items:
                if current_status == new_status:
                    self.log_debug('%sSkipping %s, no changes', log_prefix, hostname or uuid)
                    continue

                self.log_info('%sWill update %s status: %s -> %s',
                              log_prefix, hostname or uuid, current_status, new_status)
                update_list.append((uuid, new_status))

            if len(update_list) > 0:
                self.log_info('%sPushing certificate status changes to vManage', log_prefix)
                if not parsed_args.dryrun:
                    api.post(target_certs.status_post_data(*update_list), EdgeCertificate.api_path.post)
                    action_worker = EdgeCertificateSync(api.post({}, EdgeCertificateSync.api_path.post))
                    self.wait_actions(api, [(action_worker, None)], 'certificate sync with controllers',
                                      raise_on_failure=True)
            else:
                self.log_info('%sNo certificate status updates to push', log_prefix)

        except (RestAPIException, FileNotFoundError, WaitActionsException) as ex:
            self.log_critical('Failed updating WAN edge certificate status: %s', ex)

        return
