import argparse
import json
import re
import yaml
from datetime import date
from difflib import unified_diff, HtmlDiff
from typing import Union, Optional, Iterator, List, Dict, Any, NamedTuple, Type, Tuple, Callable
from pydantic import BaseModel, ValidationError, validator
from cisco_sdwan.__version__ import __doc__ as title
from cisco_sdwan.base.rest_api import Rest
from cisco_sdwan.base.catalog import CATALOG_TAG_ALL, ordered_tags
from cisco_sdwan.tasks.utils import TaskOptions, existing_workdir_type, filename_type, existing_file_type
from cisco_sdwan.tasks.common import Task, Table, TaskException
from cisco_sdwan.tasks.models import (TaskArgs, ShowArgs, ShowRealtimeArgs, ShowStateArgs, ShowStatisticsArgs, ListArgs,
                                      ListConfigArgs, ShowTemplateArgs, ShowTemplateRefArgs, validate_existing_file,
                                      validate_filename, validate_workdir, validate_json)
from ._list import TaskList
from ._show_template import TaskShowTemplate
from ._show import TaskShow


# Models for the report specification
class SectionModel(BaseModel):
    description: str
    task: str
    args: Optional[Dict[str, Any]] = None
    inherit_globals: bool = True

    @validator('task')
    def validate_task(cls, v):
        if tuple(v.split()) not in section_catalog:
            raise ValueError(f"'{v}' is not a valid section task")
        return v

    @property
    def task_label(self) -> Tuple[str, ...]:
        return tuple(self.task.split())


class ReportContentModel(BaseModel):
    globals: Optional[Dict[str, Any]] = None
    sections: List[SectionModel]


# Report specification used as default if user did not provide a custom one
DEFAULT_SECTIONS_1: List[Dict[str, Any]] = [
    {'description': f'List configuration {tag}', 'task': 'list configuration', 'args': {'tags': [tag]}}
    for tag in ordered_tags(CATALOG_TAG_ALL)
]
DEFAULT_CONTENT_SPEC = {
    'sections':  DEFAULT_SECTIONS_1 + [
        {'description': 'List certificate', 'task': 'list certificate'},
        {'description': 'Show-template values', 'task': 'show-template values'},
        {'description': 'Show-template references', 'task': 'show-template references'},
        {'description': 'Show devices', 'task': 'show devices'},
        {'description': 'Show state', 'task': 'show state', 'args': {'cmd': ['all']}},
    ]
}


# Metadata about tasks available to be included in a report
class TaskMeta(NamedTuple):
    task_cls: Type[Task]
    task_args_cls: Type[TaskArgs]
    private_args: Dict[str, Any]


section_catalog: Dict[Tuple[str, ...], TaskMeta] = {
    ('show', 'devices'): TaskMeta(
        TaskShow, ShowArgs, {'subtask_info': 'devices', 'subtask_handler': TaskShow.devices},
    ),
    ('show', 'realtime'): TaskMeta(
        TaskShow, ShowRealtimeArgs, {'subtask_info': 'realtime', 'subtask_handler': TaskShow.realtime},
    ),
    ('show', 'state'): TaskMeta(
        TaskShow, ShowStateArgs, {'subtask_info': 'state', 'subtask_handler': TaskShow.bulk_state},
    ),
    ('show', 'statistics'): TaskMeta(
        TaskShow, ShowStatisticsArgs, {'subtask_info': 'statistics', 'subtask_handler': TaskShow.bulk_stats},
    ),
    ('list', 'certificate'): TaskMeta(
        TaskList, ListArgs, {'subtask_info': 'certificate', 'subtask_handler': TaskList.cert_table},
    ),
    ('list', 'configuration'): TaskMeta(
        TaskList, ListConfigArgs, {'subtask_info': 'configuration', 'subtask_handler': TaskList.config_table},
    ),
    ('show-template', 'values'): TaskMeta(
       TaskShowTemplate, ShowTemplateArgs, {'subtask_info': 'values', 'subtask_handler': TaskShowTemplate.values_table},
    ),
    ('show-template', 'references'): TaskMeta(
        TaskShowTemplate, ShowTemplateRefArgs, {'subtask_info': 'references',
                                                'subtask_handler': TaskShowTemplate.references_table},
    ),
}


def load_yaml_file(filename: str) -> dict:
    with open(filename) as yaml_file:
        return yaml.safe_load(yaml_file)


def load_content_spec(spec_file: Optional[str], spec_json: Optional[str]) -> dict:
    if spec_file:
        return load_yaml_file(spec_file)
    if spec_json:
        return json.loads(spec_json)
    return DEFAULT_CONTENT_SPEC


class Report:
    DEFAULT_SUB_BLOCK_LABEL = "Default"

    def __init__(self, filename: str, block_dict: Optional[dict] = None) -> None:
        self.block_dict = {} if block_dict is None else block_dict
        self.filename = filename

    def add_block(self, block_label: str, sub_block_list: list) -> None:
        for sub_block in sub_block_list:
            if isinstance(sub_block, Table):
                sub_block_label = sub_block.name or Report.DEFAULT_SUB_BLOCK_LABEL
                sub_block_lines = list(sub_block.pretty_iter())
            else:
                sub_block_label = Report.DEFAULT_SUB_BLOCK_LABEL
                sub_block_lines = [str(sub_block)]

            self.block_dict.setdefault(block_label, {}).setdefault(sub_block_label, []).extend(sub_block_lines)

    def render(self) -> Iterator[str]:
        for block_seq, (block_label, sub_block_dict) in enumerate(self.block_dict.items()):
            if block_seq != 0:
                yield ''

            yield f"### {block_label} ###"
            for sub_block in sub_block_dict.values():
                yield ''
                yield from sub_block
            yield ''

    def __str__(self) -> str:
        return '\n'.join(self.render())

    def save(self) -> None:
        with open(self.filename, 'w') as f:
            f.write(str(self))

    @classmethod
    def load(cls, filename: str):
        try:
            with open(filename) as report_f:
                report_data = report_f.read()
        except FileNotFoundError as ex:
            raise FileNotFoundError(f"Failed to load report file: {ex}") from None

        p_block_label = re.compile(r"###(?P<block_label>[^#]+)###$")
        p_sub_block_label = re.compile(r"\*{3}(?P<sub_block_label>[^*]+)\*{3}$")

        block_dict = {}
        block_label, sub_block_label = None, None
        for line in report_data.splitlines():
            if not line.strip():
                continue

            m_block_label = p_block_label.match(line)
            if m_block_label:
                block_label = m_block_label.group('block_label').strip()
                sub_block_label = Report.DEFAULT_SUB_BLOCK_LABEL
                continue

            if block_label is None or sub_block_label is None:
                continue

            m_sub_block_label = p_sub_block_label.match(line)
            if m_sub_block_label:
                sub_block_label = m_sub_block_label.group('sub_block_label').strip()

            block_dict.setdefault(block_label, {}).setdefault(sub_block_label, []).append(line)

        return cls(filename, block_dict)


@TaskOptions.register('report')
class TaskReport(Task):
    @staticmethod
    def parser(task_args, target_address=None):
        task_parser = argparse.ArgumentParser(description=f'{title}\nReport task:')
        task_parser.prog = f'{task_parser.prog} report'
        task_parser.formatter_class = argparse.RawDescriptionHelpFormatter

        sub_tasks = task_parser.add_subparsers(title='report options')
        sub_tasks.required = True

        create_parser = sub_tasks.add_parser('create', help='create a report')
        create_parser.set_defaults(subtask_handler=TaskReport.subtask_create)
        create_parser.add_argument('--file', metavar='<filename>', type=filename_type,
                                   default=f'report_{date.today():%Y%m%d}.txt',
                                   help='report filename (default: %(default)s)')
        create_parser.add_argument('--workdir', metavar='<directory>', type=existing_workdir_type,
                                   help='report from the specified directory instead of target vManage')
        mutex = create_parser.add_mutually_exclusive_group()
        mutex.add_argument('--spec-file', metavar='<filename>', type=existing_file_type,
                           help='load custom report specification from YAML file')
        mutex.add_argument('--spec-json', metavar='<json>',
                           help='load custom report specification from JSON-formatted string')
        create_parser.add_argument('--diff', metavar='<filename>', type=existing_file_type,
                                   help='generate diff between the specified previous report and the current report')

        diff_parser = sub_tasks.add_parser('diff', help='generate diff between two reports')
        diff_parser.set_defaults(subtask_handler=TaskReport.subtask_diff)
        diff_parser.add_argument('report_a', metavar='<report a>', type=existing_file_type,
                                 help='report a filename (from)')
        diff_parser.add_argument('report_b', metavar='<report b>', type=existing_file_type,
                                 help='report b filename (to)')
        diff_parser.add_argument('--save-html', metavar='<filename>', type=filename_type,
                                 help='save report diff as html file')
        diff_parser.add_argument('--save-txt', metavar='<filename>', type=filename_type,
                                 help='save report diff as text file')

        return task_parser.parse_args(task_args)

    @staticmethod
    def is_api_required(parsed_args) -> bool:
        return parsed_args.subtask_handler is TaskReport.subtask_create and parsed_args.workdir is None

    def runner(self, parsed_args, api: Optional[Rest] = None) -> Union[None, list]:
        return parsed_args.subtask_handler(self, parsed_args, api)

    def subtask_create(self, parsed_args, api: Optional[Rest]) -> Union[None, list]:
        source_info = f'Local workdir: "{parsed_args.workdir}"' if api is None else f'vManage URL: "{api.base_url}"'
        self.log_info(f'Starting report create: {source_info} -> "{parsed_args.file}"')
        try:
            self.log_info("Loading report specification")
            content_spec = ReportContentModel(**load_content_spec(parsed_args.spec_file, parsed_args.spec_json))
        except FileNotFoundError as ex:
            raise FileNotFoundError(f'Could not load report specification file: {ex}') from None
        except ValidationError as ex:
            raise TaskException(f'Invalid report specification: {ex}') from None

        report = Report(parsed_args.file)
        for description, task_cls, task_args in self.section_iter(content_spec, api is not None, parsed_args.workdir):
            try:
                task_output = task_cls().runner(task_args, api)
                if task_output:
                    report.add_block(description, task_output)
            except (TaskException, FileNotFoundError) as ex:
                self.log_error(f'Task {task_cls.__name__} error: {ex}')

        result = None
        if parsed_args.diff:
            self.log_info(f'Starting diff from "{parsed_args.diff}" to "{parsed_args.file}"')
            previous_report = Report.load(parsed_args.diff)
            self.log_info(f'Loaded previous report "{parsed_args.diff}"')
            result = [diff_txt(previous_report, report)]
            self.log_info('Completed diff')

        # Saving current report after running the diff in case the previous report had the same filename
        report.save()
        self.log_info(f'Report saved as "{parsed_args.file}"')

        return result

    def subtask_diff(self, parsed_args, api: Optional[Rest]) -> Union[None, list]:
        self.log_info(f'Starting report diff: "{parsed_args.report_a}" -> "{parsed_args.report_b}"')
        report_a = Report.load(parsed_args.report_a)
        self.log_info(f'Loaded report "{parsed_args.report_a}"')
        report_b = Report.load(parsed_args.report_b)
        self.log_info(f'Loaded report "{parsed_args.report_b}"')

        result = None
        if parsed_args.save_html:
            with open(parsed_args.save_html, 'w') as f:
                f.write(diff_html(report_a, report_b))
            self.log_info(f'HTML report diff saved as "{parsed_args.save_html}"')

        if parsed_args.save_txt:
            with open(parsed_args.save_txt, 'w') as f:
                f.write(diff_txt(report_a, report_b))
            self.log_info(f'Text report diff saved as "{parsed_args.save_txt}"')

        if not parsed_args.save_html and not parsed_args.save_txt:
            result = [diff_txt(report_a, report_b)]

        return result

    def section_iter(self, report_spec: ReportContentModel,
                     has_api_session: bool,
                     workdir: Optional[str]) -> Iterator[Tuple[str, Type[Task], TaskArgs]]:
        """
        An iterator over the different sections of the report, including task and arguments for the task.
        :param report_spec: report specification to use for generating this report
        :param has_api_session: whether the report is running with a vManage session or offline (i.e. off a backup)
        :param workdir: workdir value, if provided to the report task.
        :return: an iterator of (<description>, <task class>, <task args>)
        """
        spec_global_args = report_spec.globals or {}

        for section_num, section in enumerate(report_spec.sections):
            task_meta: TaskMeta = section_catalog[section.task_label]

            # Resolving task args
            # Merge args provided by the spec, first global then section args.
            # Finally, merge with private args to ensure that private args cannot be overwritten
            spec_section_args = section.args or {}
            spec_args = {**spec_global_args, **spec_section_args} if section.inherit_globals else spec_section_args

            try:
                task_args = task_meta.task_args_cls(**spec_args, **task_meta.private_args)
            except ValidationError as ex:
                self.log_error(f"Invalid report specification: {section.description} (sections -> {section_num}): {ex}")
                continue

            if workdir is not None and hasattr(task_args, 'workdir') and task_args.workdir is None:
                task_args.workdir = workdir

            if task_meta.task_cls.is_api_required(task_args) and not has_api_session:
                # Skip report sections that require an api session when report is run offline
                self.log_debug(f"Skipping: {section.description} (sections -> {section_num}): report in offline mode")
                continue

            yield section.description, task_meta.task_cls, task_args


def diff_html(a: Report, b: Report) -> str:
    diff = HtmlDiff()
    return diff.make_file(list(a.render()), list(b.render()), fromdesc=a.filename, todesc=b.filename, context=False)


def diff_txt(a: Report, b: Report) -> str:
    return '\n'.join(diff_txt_iter(a, b))


def diff_txt_iter(a: Report, b: Report) -> Iterator[str]:
    def spaced_line(line: str) -> Iterator[str]:
        yield ""
        yield line

    def sub_block_lines(sub_block_iter: Iterator[str]) -> List[str]:
        lines = []
        for sub_block in sub_block_iter:
            lines.extend(sub_block.splitlines())
        return lines

    yield from spaced_line(f"### Report Diff - a/{a.filename} <-> b/{b.filename} ###")

    # Find blocks that were on a but not on b
    for a_block_label in set(a.block_dict) - set(b.block_dict):
        yield from spaced_line(f"deleted a/{a_block_label.lower()}")

    # Diff each block
    for block_label, b_sub_block_dict in b.block_dict.items():
        a_sub_block_dict = a.block_dict.get(block_label)
        if a_sub_block_dict is None:
            yield from spaced_line(f"new b/{block_label.lower()}")
            continue

        # Find sub-blocks that were on a but not on b
        for a_sub_block_label in set(a_sub_block_dict) - set(b_sub_block_dict):
            yield from spaced_line(f"deleted a/{a_sub_block_label.lower()}")

        # Diff each sub-block
        for sub_block_label, b_sub_blocks in b_sub_block_dict.items():
            a_sub_blocks = a_sub_block_dict.get(sub_block_label)
            if a_sub_blocks is None:
                yield from spaced_line(f"new b/{sub_block_label.lower()}")
                continue

            diff_info = [block_label.lower()]
            if sub_block_label != Report.DEFAULT_SUB_BLOCK_LABEL:
                diff_info.append(sub_block_label.lower())

            is_first = True
            for diff_line in unified_diff(sub_block_lines(a_sub_blocks), sub_block_lines(b_sub_blocks),
                                          fromfile=f"a/{a.filename}", tofile=f"b/{b.filename}", lineterm='', n=1):
                if is_first:
                    yield from spaced_line(f"changed {', '.join(diff_info)}")
                    is_first = False

                yield diff_line

    yield from spaced_line("### End Report Diff ###")


class ReportCreateArgs(TaskArgs):
    subtask_handler: Callable = TaskReport.subtask_create
    file: Optional[str] = None
    workdir: Optional[str] = None
    spec_file: Optional[str] = None
    spec_json: Optional[str] = None
    diff: Optional[str] = None

    # Validators
    _validate_workdir = validator('workdir', allow_reuse=True)(validate_workdir)
    _validate_existing_file = validator('spec_file', 'diff', allow_reuse=True)(validate_existing_file)
    _validate_json = validator('spec_json', allow_reuse=True)(validate_json)

    @validator('file', pre=True, always=True)
    def validate_report_file(cls, v):
        filename = v or f'report_{date.today():%Y%m%d}.txt'
        return validate_filename(filename)


class ReportDiffArgs(TaskArgs):
    subtask_handler: Callable = TaskReport.subtask_diff
    report_a: Optional[str] = None
    report_b: Optional[str] = None
    save_html: Optional[str] = None
    save_txt: Optional[str] = None

    # Validators
    _validate_existing_file = validator('report_a', 'report_b', allow_reuse=True)(validate_existing_file)
    _validate_filename = validator('save_html', 'save_txt', allow_reuse=True)(validate_filename)
