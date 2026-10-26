import os
import subprocess
import sys
import unittest
from cfai.process import ChildJob


@unittest.skipUnless(os.name=='nt','Windows kernel process-lifetime contract')
class ProcessTests(unittest.TestCase):
    def test_closing_job_terminates_only_owned_child(self):
        job=ChildJob()
        process=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        try:
            job.attach(process)
            job.close()
            process.wait(timeout=5)
            self.assertIsNotNone(process.returncode)
        finally:
            job.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
