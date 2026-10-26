import unittest
from unittest.mock import patch
from cfai.speed import Budget, Cancelled, download


class Response:
    def __init__(self, total=100000, fail_at=None, code=200, location=None):
        self.total=total
        self.read=0
        self.requests=[]
        self.fail_at=fail_at
        self.status=code
        self.location=location
        self.fp=None
    def read1(self,size):
        self.requests.append(size)
        if self.fail_at is not None and self.read>=self.fail_at: raise OSError('fixture')
        count=min(size,self.total-self.read)
        self.read+=count
        return b'x'*count
    def getheader(self,key,default=None): return self.location if key=='Location' else default


class Connection:
    def __init__(self,response):
        self.response=response
        self.sock=None
        self.closed=False
    def set_tunnel(self,*a): pass
    def request(self,*a,**kw): pass
    def getresponse(self): return self.response
    def close(self): self.closed=True


class DownloadTests(unittest.TestCase):
    def test_oversized_server_response_is_hard_capped(self):
        response=Response(total=1_000_000)
        connection=Connection(response)
        b=Budget(1000)
        with patch('cfai.speed.http.client.HTTPSConnection',return_value=connection):
            result=download(1,'https://download.example.org/data',1000,5,b)
        self.assertTrue(result['ok'])
        self.assertEqual(response.read,1000)
        self.assertEqual(b.used,1000)
        self.assertEqual(b.reserved,0)
        self.assertTrue(connection.closed)

    def test_failed_partial_body_counts_toward_budget(self):
        response=Response(fail_at=16384)
        b=Budget(50000)
        with patch('cfai.speed.http.client.HTTPSConnection',return_value=Connection(response)):
            result=download(1,'https://download.example.org/data',50000,5,b)
        self.assertFalse(result['ok'])
        self.assertEqual(b.used,16384)
        self.assertEqual(b.reserved,0)

    def test_redirect_does_not_read_unbounded_body(self):
        redirect=Response(code=302,location='https://other.example.org/data')
        body=Response(total=1000)
        with patch('cfai.speed.http.client.HTTPSConnection',side_effect=[Connection(redirect),Connection(body)]):
            b=Budget(1000)
            self.assertTrue(download(1,'https://download.example.org/data',1000,5,b)['ok'])
        self.assertEqual(redirect.read,0)
        self.assertEqual(b.used,1000)

    def test_cancel_releases_budget_and_stops(self):
        b=Budget(1000)
        with self.assertRaises(Cancelled):
            download(1,'https://download.example.org/data',1000,5,b,lambda:True)
        self.assertEqual((b.used,b.reserved),(0,0))


if __name__=='__main__': unittest.main()
