import argparse
from typing import Union, Optional
from cisco_sdwan.__version__ import __doc__ as title
from cisco_sdwan.base.rest_api import Rest
from cisco_sdwan.base.catalog import catalog_iter, CATALOG_TAG_ALL
from cisco_sdwan.base.models_base import ExtendedTemplate
from cisco_sdwan.base.models_vmanage import EdgeCertificate
from cisco_sdwan.tasks.utils import (TaskOptions, TagOptions, existing_workdir_type, filename_type, regex_type,
                                     ext_template_type)
from cisco_sdwan.tasks.common import regex_search, Task, Table, export_json


@TaskOptions.register('list')
class TaskList(Task):
    @staticmethod
    def parser(task_args, target_address=None):
        task_parser = argparse.ArgumentParser(description=f'{title}\nList task:')
        task_parser.prog = f'{task_parser.prog} list'
        task_parser.formatter_class = argparse.RawDescriptionHelpFormatter

        sub_tasks = task_parser.add_subparsers(title='list options')
        sub_tasks.required = True

        config_parser = sub_tasks.add_parser('configuration', aliases=['config'], help='list configuration items')
        config_parser.set_defaults(subtask_handler=TaskList.config_table)
        config_parser.set_defaults(subtask_info='configuration')
        config_parser.add_argument('tags', metavar='<tag>', nargs='+', type=TagOptions.tag,
                                   help='one or more tags for selecting groups of items. Multiple tags should be '
                                        f'separated by space. Available tags: {TagOptions.options()}. Special tag '
                                        f'"{CATALOG_TAG_ALL}" selects all items.')
        config_mutex = config_parser.add_mutually_exclusive_group()
        config_mutex.add_argument('--regex', metavar='<regex>', type=regex_type,
                                  help='regular expression selecting items to list. Match on item names or IDs.')
        config_mutex.add_argument('--not-regex', metavar='<regex>', type=regex_type,
                                  help='regular expression selecting items NOT to list. Match on item names or IDs.')

        cert_parser = sub_tasks.add_parser('certificate', aliases=['cert'], help='list device certificate information')
        cert_parser.set_defaults(subtask_handler=TaskList.cert_table)
        cert_parser.set_defaults(subtask_info='certificate')
        cert_mutex = cert_parser.add_mutually_exclusive_group()
        cert_mutex.add_argument('--regex', metavar='<regex>', type=regex_type,
                                help='regular expression selecting devices to list. Match on hostname or '
                                     'chassis/uuid. Use "^-$" to match devices without a hostname.')
        cert_mutex.add_argument('--not-regex', metavar='<regex>', type=regex_type,
                                help='regular expression selecting devices NOT to list. Match on hostname or '
                                     'chassis/uuid.')

        xform_parser = sub_tasks.add_parser('transform',
                                            help='list name transformations performed by a name-regex against '
                                                 'existing item names')
        xform_parser.set_defaults(subtask_handler=TaskList.xform_table)
        xform_parser.set_defaults(subtask_info='transform')
        xform_parser.add_argument('tags', metavar='<tag>', nargs='+', type=TagOptions.tag,
                                  help='one or more tags for selecting groups of items. Multiple tags should be '
                                       f'separated by space. Available tags: {TagOptions.options()}. Special tag '
                                       f'"{CATALOG_TAG_ALL}" selects all items.')
        xform_parser.add_argument('name_regex', metavar='<name-regex>', type=ext_template_type,
                                  help='name-regex used to transform an existing item name. Variable {name} is '
                                       'replaced with the original template name. Sections of the original template '
                                       'name can be selected using the {name <regex>} format. Where <regex> is a '
                                       'regular expression that must contain at least one capturing group. Capturing '
                                       'groups identify sections of the original name to keep.')
        xform_mutex = xform_parser.add_mutually_exclusive_group()
        xform_mutex.add_argument('--regex', metavar='<regex>', type=regex_type,
                                 help='regular expression selecting items to list, match on original item names.')
        xform_mutex.add_argument('--not-regex', metavar='<regex>', type=regex_type,
                                 help='regular expression selecting items NOT to list, match on original item names.')

        # Parameters common to all sub-tasks
        for sub_task in (config_parser, cert_parser, xform_parser):
            sub_task.add_argument('--workdir', metavar='<directory>', type=existing_workdir_type,
                                  help='list will read from the specified directory instead of target vManage')
            sub_task.add_argument('--save-csv', metavar='<filename>', type=filename_type,
                                  help='export table as CSV-formatted file')
            sub_task.add_argument('--save-json', metavar='<filename>', type=filename_type,
                                  help='export table as JSON-formatted file')

        return task_parser.parse_args(task_args)

    @staticmethod
    def is_api_required(parsed_args) -> bool:
        return parsed_args.workdir is None

    def runner(self, parsed_args, api: Optional[Rest] = None) -> Union[None, list]:
        source_info = f'Local workdir: "{parsed_args.workdir}"' if api is None else f'vManage URL: "{api.base_url}"'
        self.log_info('Starting list %s: %s', parsed_args.subtask_info, source_info)

        result_table = parsed_args.subtask_handler(self, parsed_args, api)
        self.log_info('List criteria matched %s items', len(result_table))
        if not result_table:
            return

        if parsed_args.save_csv is not None:
            result_table.save(parsed_args.save_csv)
            self.log_info(f"Table exported as CSV file '{parsed_args.save_csv}'")

        if parsed_args.save_json is not None:
            export_json([result_table], parsed_args.save_json)
            self.log_info(f"Table exported as JSON file '{parsed_args.save_json}'")

        return [result_table] if (parsed_args.save_csv is None and parsed_args.save_json is None) else None

    def config_table(self, parsed_args, api: Optional[Rest]) -> Table:
        backend = api or parsed_args.workdir
        # Only perform version-based filtering if backend is api
        version = None if api is None else api.server_version

        table = Table('Name', 'ID', 'Tag', 'Type')
        regex = parsed_args.regex or parsed_args.not_regex
        table.extend(
            (item_name, item_id, tag, info)
            for tag, info, index, item_cls in self.index_iter(backend, catalog_iter(*parsed_args.tags, version=version))
            for item_id, item_name in index
            if regex is None or regex_search(regex, item_name, item_id, inverse=parsed_args.regex is None)
        )

        return table

    def cert_table(self, parsed_args, api: Optional[Rest]) -> Table:
        if api is None:
            certs = EdgeCertificate.load(parsed_args.workdir)
            if certs is None:
                raise FileNotFoundError('WAN edge certificates were not found in the backup')
        else:
            certs = EdgeCertificate.get_raise(api)

        table = Table('Hostname', 'Chassis', 'Serial', 'State',  'Status')
        regex = parsed_args.regex or parsed_args.not_regex
        table.extend(
            (hostname or '-', chassis, serial, EdgeCertificate.state_str(state), status)
            for uuid, status, hostname, chassis, serial, state in certs.extended_iter()
            if regex is None or regex_search(regex, hostname or '-', uuid, inverse=parsed_args.regex is None)
        )

        return table

    def xform_table(self, parsed_args, api: Optional[Rest]) -> Table:
        backend = api or parsed_args.workdir
        # Only perform version-based filtering if backend is api
        version = None if api is None else api.server_version

        name_regex = ExtendedTemplate(parsed_args.name_regex)

        table = Table('Name', 'Transformed', 'Tag', 'Type')
        regex = parsed_args.regex or parsed_args.not_regex
        table.extend(
            (item_name,  name_regex(item_name), tag, info)
            for tag, info, index, item_cls in self.index_iter(backend, catalog_iter(*parsed_args.tags, version=version))
            for item_id, item_name in index
            if regex is None or regex_search(regex, item_name, inverse=parsed_args.regex is None)
        )

        return table
