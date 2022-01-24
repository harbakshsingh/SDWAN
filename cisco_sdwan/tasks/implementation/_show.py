import argparse
from typing import Tuple, List, Any, NamedTuple, Type, Union, Optional, Sequence
from pathlib import Path
from functools import partial
from concurrent import futures
from datetime import datetime, timedelta, timezone
from cisco_sdwan.__version__ import __doc__ as title
from cisco_sdwan.base.rest_api import Rest
from cisco_sdwan.base.catalog import CATALOG_TAG_ALL, op_catalog_iter, OpType
from cisco_sdwan.base.models_base import OperationalItem, RealtimeItem, BulkStatsItem, BulkStateItem, filename_safe
from cisco_sdwan.base.models_vmanage import Device
from cisco_sdwan.tasks.utils import (TaskOptions, regex_type, ipv4_type, site_id_type, filename_type, int_type,
                                     OpCmdOptions, RTCmdSemantics, StateCmdSemantics, StatsCmdSemantics)
from cisco_sdwan.tasks.common import regex_search, Task, Table, export_json


THREAD_POOL_SIZE = 10
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"


class DeviceInfo(NamedTuple):
    hostname: str
    system_ip: str
    site_id: str
    state: str
    device_type: str
    model: str


def retrieve_rt_task(api_obj: Rest, rt_cls: Type[RealtimeItem], device: DeviceInfo) -> Tuple[DeviceInfo, Any]:
    return device, rt_cls.get(api_obj, device.system_ip)


def table_fields(op_cls: Type[OperationalItem], detail: bool) -> tuple:
    if detail and op_cls.fields_ext is not None:
        return op_cls.fields_std + op_cls.fields_ext
    else:
        return op_cls.fields_std


@TaskOptions.register('show')
class TaskShow(Task):
    SAVINGS_FACTOR = 2
    STATS_AVG_INTERVAL_SECS = 300  # 5min window for statistics averages
    STATS_QUERY_RANGE_MINS = 120   # Statistics queries are from t to t - 2h

    @staticmethod
    def parser(task_args, target_address=None):
        task_parser = argparse.ArgumentParser(description=f'{title}\nShow task:')
        task_parser.prog = f'{task_parser.prog} show'
        task_parser.formatter_class = argparse.RawDescriptionHelpFormatter

        sub_tasks = task_parser.add_subparsers(title='show options')
        sub_tasks.required = True

        dev_parser = sub_tasks.add_parser('devices', aliases=['dev'], help='device list')
        dev_parser.set_defaults(subtask_handler=TaskShow.devices)
        dev_parser.set_defaults(subtask_info='devices')

        rt_parser = sub_tasks.add_parser('realtime', aliases=['rt'],
                                         help='realtime commands. Slower, but up-to-date data. vManage collect data '
                                              'from devices in realtime.')
        rt_parser.set_defaults(subtask_handler=TaskShow.realtime)
        rt_parser.set_defaults(subtask_info='realtime')

        state_parser = sub_tasks.add_parser('state', aliases=['st'],
                                            help='state commands. Faster and up-to-date synced state data.')
        state_parser.set_defaults(subtask_handler=TaskShow.bulk_state)
        state_parser.set_defaults(subtask_info='state')

        stats_parser = sub_tasks.add_parser('statistics', aliases=['stats'],
                                            help='statistics commands. Faster, but data is 30 min or more old. '
                                                 'Allows historical data queries.')
        stats_parser.set_defaults(subtask_handler=TaskShow.bulk_stats)
        stats_parser.set_defaults(subtask_info='statistics')
        stats_parser.add_argument('--days', metavar='<days>', type=partial(int_type, 0, 9999), default=0,
                                  help='query statistics from <days> ago (default: %(default)s, i.e. now)')
        stats_parser.add_argument('--hours', metavar='<hours>', type=partial(int_type, 0, 9999), default=0,
                                  help='query statistics from <hours> ago (default: %(default)s, i.e. now)')

        for sub_task, cmd_action, op_type in ((rt_parser, RTCmdSemantics, OpType.RT),
                                              (state_parser, StateCmdSemantics, OpType.STATE),
                                              (stats_parser, StatsCmdSemantics, OpType.STATS)):
            sub_task.add_argument('cmd', metavar='<cmd>', nargs='+', action=cmd_action,
                                  help='group of, or specific command to execute. '
                                       f'Group options: {OpCmdOptions.tags(op_type)}. '
                                       f'Command options: {OpCmdOptions.commands(op_type)}. '
                                       f'Group "{CATALOG_TAG_ALL}" selects all commands.')
            sub_task.add_argument('--detail', action='store_true', help='detailed output')

        for sub_task in (rt_parser, state_parser, stats_parser, dev_parser):
            mutex = sub_task.add_mutually_exclusive_group()
            mutex.add_argument('--regex', metavar='<regex>', type=regex_type,
                               help='regular expression matching device name, type or model to display.')
            mutex.add_argument('--not-regex', metavar='<regex>', type=regex_type,
                               help='regular expression matching device name, type or model NOT to display.')
            sub_task.add_argument('--reachable', action='store_true', help='display only reachable devices')
            sub_task.add_argument('--site', metavar='<id>', type=site_id_type, help='filter by site ID')
            sub_task.add_argument('--system-ip', metavar='<ipv4>', type=ipv4_type, help='filter by system IP')
            sub_task.add_argument('--save-csv', metavar='<directory>', type=filename_type,
                                  help='export results as CSV files under the specified directory')
            sub_task.add_argument('--save-json', metavar='<filename>', type=filename_type,
                                  help='export results as JSON-formatted file')

        return task_parser.parse_args(task_args)

    def runner(self, parsed_args, api: Optional[Rest] = None) -> Union[None, list]:
        self.log_info(f'Starting show {parsed_args.subtask_info}: vManage URL: "{api.base_url}"')
        regex = parsed_args.regex or parsed_args.not_regex
        matched_items = [
            DeviceInfo(name, system_ip, site_id, state, d_type, model)
            for _, name, system_ip, site_id, state, d_type, model in Device.get_raise(api).extended_iter(default='-')
            if ((regex is None or regex_search(regex, name, d_type, model, inverse=parsed_args.regex is None)) and
                (not parsed_args.reachable or state == 'reachable') and
                (parsed_args.site is None or site_id == parsed_args.site) and
                (parsed_args.system_ip is None or system_ip == parsed_args.system_ip))
        ]
        self.log_info(f'Selection criteria matched {len(matched_items)} devices')

        result_tables = parsed_args.subtask_handler(self, parsed_args, api, matched_items)
        if not result_tables:
            return

        if parsed_args.save_csv is not None:
            Path(parsed_args.save_csv).mkdir(parents=True, exist_ok=True)
            for table in result_tables:
                filename_tokens = [parsed_args.subtask_info]
                if table.name is not None:
                    filename_tokens.append(filename_safe(table.name, lower=True).replace(' ', '_'))
                table.save(Path(parsed_args.save_csv, f"{'_'.join(filename_tokens)}.csv"))
            self.log_info(f"Tables exported as CSV files under directory '{parsed_args.save_csv}'")

        if parsed_args.save_json is not None:
            export_json(result_tables, parsed_args.save_json)
            self.log_info(f"Tables exported as JSON file '{parsed_args.save_json}'")

        return result_tables if (parsed_args.save_csv is None and parsed_args.save_json is None) else None

    def realtime(self, parsed_args, api: Rest, devices: Sequence[DeviceInfo]) -> List[Table]:
        pool_size = max(min(len(devices), THREAD_POOL_SIZE), 1)

        result_tables = []
        for info, rt_cls in op_catalog_iter(OpType.RT, *parsed_args.cmd, version=api.server_version):
            devices_in_scope = [dev_info for dev_info in devices if rt_cls.is_in_scope(dev_info.model)]
            if not devices_in_scope:
                self.log_debug(f"Skipping {info.lower()}, not applicable to any of the devices selected")
                continue

            self.log_info(f'Retrieving {info.lower()} for {len(devices_in_scope)} devices')
            with futures.ThreadPoolExecutor(pool_size) as executor:
                job_result_iter = executor.map(partial(retrieve_rt_task, api, rt_cls), devices_in_scope)

            table = None
            fields = table_fields(rt_cls, parsed_args.detail)
            for device, rt_obj in job_result_iter:
                if rt_obj is None:
                    self.log_error(f'Failed to retrieve {info.lower()} from {device.hostname}')
                    continue

                if table is None:
                    table = Table('Device', *rt_obj.field_info(*fields), name=info)

                table.extend(
                    (device.hostname, *row_values)
                    for row_values in rt_obj.field_value_iter(*fields, **rt_cls.field_conversion_fns)
                )
                table.add_marker()

            if table:
                result_tables.append(table)

        return result_tables

    def bulk_state(self, parsed_args, api: Rest, devices: Sequence[DeviceInfo]) -> List[Table]:
        result_tables = []
        for info, op_cls in op_catalog_iter(OpType.STATE, *parsed_args.cmd, version=api.server_version):
            self.log_info(f'Retrieving {info.lower()} for {len(devices)} devices')

            op_obj: BulkStateItem = op_cls.get(api, count=10000)
            if op_obj is None:
                self.log_error(f'Failed to retrieve {info.lower()}')
                continue

            fields = table_fields(op_cls, parsed_args.detail)
            node_data_dict = {}
            for node_id, *node_data_sample in op_obj.field_value_iter(
                    op_cls.field_node_id, *fields, **op_cls.field_conversion_fns):
                node_data_dict.setdefault(node_id, []).append(node_data_sample)

            table = self.build_table(info, op_obj.field_info(*fields), devices, node_data_dict)
            if table:
                result_tables.append(table)

        return result_tables

    def bulk_stats(self, parsed_args, api: Rest, devices: Sequence[DeviceInfo]) -> List[Table]:
        end_time = datetime.now(tz=timezone.utc) - timedelta(days=parsed_args.days, hours=parsed_args.hours)
        start_time = end_time - timedelta(minutes=self.STATS_QUERY_RANGE_MINS)
        query_params = {
            "endDate": end_time.strftime(TIME_FORMAT),
            "startDate": start_time.strftime(TIME_FORMAT),
            "count": 10000,
            "timeZone": "UTC"
        }
        self.log_info(f'Query timestamp: {end_time:%Y-%m-%d %H:%M:%S %Z}')

        result_tables = []
        for info, op_cls in op_catalog_iter(OpType.STATS, *parsed_args.cmd, version=api.server_version):
            self.log_info(f'Retrieving {info.lower()} for {len(devices)} devices')

            op_obj: BulkStatsItem = op_cls.get(api, **query_params)
            if op_obj is None:
                self.log_error(f'Failed to retrieve {info.lower()}')
                continue

            fields = table_fields(op_cls, parsed_args.detail)
            node_data_dict = {}
            for node_id, *node_data_sample in op_obj.aggregated_value_iter(
                    self.STATS_AVG_INTERVAL_SECS, op_cls.field_node_id, *fields, **op_cls.field_conversion_fns):
                node_data_dict.setdefault(node_id, []).append(node_data_sample)

            table = self.build_table(info, op_obj.field_info(*fields), devices, node_data_dict)
            if table:
                result_tables.append(table)

        return result_tables

    def devices(self, parsed_args, api: Rest, devices: Sequence[DeviceInfo]) -> List[Table]:
        result_tables = []

        table = Table('Name', 'System IP', 'Site ID', 'Reachability', 'Type', 'Model')
        table.extend(devices)
        if table:
            result_tables.append(table)

        return result_tables

    def build_table(self, name: str, headers: Sequence[str], devices: Sequence[DeviceInfo], device_data: dict) -> Table:
        table = Table('Device', *headers, name=name)
        for device in devices:
            device_row_values = device_data.get(device.system_ip)
            if device_row_values is None:
                self.log_info(f'{name} missing for {device.hostname}')
                continue

            table.extend((device.hostname, *row_values) for row_values in device_row_values)
            table.add_marker()

        return table
