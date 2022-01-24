import unittest
from cisco_sdwan.base.rest_api import Rest
from cisco_sdwan.tasks.common import TaskArgs
from cisco_sdwan.tasks.implementation import TaskShow


VMANAGE_INFO = ("https:/198.18.1.10:443", "admin", "admin")


class TestTasks(unittest.TestCase):
    api: Rest = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.api = Rest(*VMANAGE_INFO, timeout=120)

    def test_task_show_rt(self) -> None:
        params = TaskArgs(detail=False, site=None, system_ip=None, cmds=["system", "status"],
                          subtask_handler=TaskShow.realtime, subtask_info='realtime', regex=None, reachable=False)
        task_output = []
        task = TaskShow()
        task.runner(params, self.api, task_output=task_output)

        table_is_consistent = len(task_output) > 0 and "|" in task_output[0]

        self.assertEqual(task.outcome("succeeded", "failed"), "succeeded", msg="Task execution failed")
        self.assertTrue(table_is_consistent, msg="Task output is not valid")

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.api is not None:
            cls.api.logout()
            cls.api.session.close()


if __name__ == '__main__':
    unittest.main()
