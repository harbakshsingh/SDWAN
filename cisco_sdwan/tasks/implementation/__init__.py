"""
 Sastre - Automation Tools for Cisco SD-WAN Powered by Viptela

 cisco_sdwan.tasks.implementation
 This module contains the implementation of user-facing tasks
"""
from ._backup import TaskBackup
from ._restore import TaskRestore
from ._delete import TaskDelete
from ._migrate import TaskMigrate
from ._attach_detach import TaskAttach, TaskDetach
from ._certificate import TaskCertificate
from ._list import TaskList
from ._show_template import TaskShowTemplate
from ._report import TaskReport, ReportCreateArgs, ReportDiffArgs
from ._show import TaskShow


__all__ = [
    'TaskBackup',
    'TaskRestore',
    'TaskDelete',
    'TaskMigrate',
    'TaskAttach',
    'TaskDetach',
    'TaskCertificate',
    'TaskList',
    'TaskShowTemplate',
    'TaskReport',
    'TaskShow',
    'ReportCreateArgs',
    'ReportDiffArgs'
]
