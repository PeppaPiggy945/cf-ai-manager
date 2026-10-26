"""Windows per-socket physical-interface binding; never falls back to TUN routes."""
import http.client
import ipaddress
import json
import os
import socket
import ssl
import struct
import subprocess


def select_interface(rows):
    valid=[]
    for row in rows:
        try:
            address=ipaddress.IPv4Address(row['ip'])
            gateway=ipaddress.IPv4Address(row['gateway'])
            index=int(row['index'])
            label=(row.get('name','')+' '+row.get('description','')).lower()
            if (address.is_loopback or address.is_link_local or address.is_unspecified
                    or gateway.is_unspecified or not 0<index<2**24 or not row['name']
                    or any(word in label for word in ('tunnel','tailscale','vmware','wintun','loopback','meta tunnel'))):
                continue
            valid.append(row)
        except (KeyError,ValueError,TypeError):
            continue
    if not valid:
        raise ValueError('No connected physical IPv4 interface with a default gateway')
    return min(valid,key=lambda row:(int(row.get('metric',9999)),int(row['index'])))


class DirectNetwork:
    def __init__(self,interface):
        self.interface=select_interface([interface])

    @classmethod
    def discover(cls):
        if os.name!='nt':
            raise OSError('Physical TUN bypass is implemented for Windows only')
        script=r'''
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$ErrorActionPreference='Stop'
$taskConfigs=@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True')
$taskRows=@(foreach($taskAdapter in @(Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetAdapter -Filter 'HardwareInterface=TRUE' | Where-Object InterfaceOperationalStatus -eq 1)) {
  $taskConfig=$taskConfigs | Where-Object InterfaceIndex -eq $taskAdapter.InterfaceIndex | Select-Object -First 1
  $taskIp=@($taskConfig.IPAddress | Where-Object {$_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notlike '169.254.*'}) | Select-Object -First 1
  $taskGateway=@($taskConfig.DefaultIPGateway | Where-Object {$_ -match '^\d+\.\d+\.\d+\.\d+$'}) | Select-Object -First 1
  if($taskIp -and $taskGateway) {
    [PSCustomObject]@{name=$taskAdapter.Name;index=[int]$taskAdapter.InterfaceIndex;
      ip=$taskIp;gateway=$taskGateway;guid=$taskAdapter.InterfaceGuid;
      description=$taskAdapter.InterfaceDescription;metric=[int]$taskConfig.IPConnectionMetric}
  }
})
ConvertTo-Json -InputObject @($taskRows) -Compress
'''
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],
            capture_output=True,timeout=20,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if result.returncode:
            raise OSError('Physical interface discovery failed')
        rows=json.loads(result.stdout.decode('utf-8-sig'))
        if not isinstance(rows,list):
            raise ValueError('Invalid physical interface response')
        return cls(select_interface(rows))

    @property
    def identity(self):
        return tuple(self.interface.get(key) for key in ('guid','index','ip','gateway'))

    def connect(self,address,timeout=2):
        # Address must already be IPv4 so no implicit DNS or IPv6 fallback can
        # route through a virtual interface.
        ipaddress.IPv4Address(address[0])
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.setsockopt(socket.IPPROTO_IP,31,struct.pack('!I',int(self.interface['index'])))
            if sock.getsockopt(socket.IPPROTO_IP,31)!=int(self.interface['index']):
                raise OSError('Outgoing interface binding did not take effect')
            sock.bind((self.interface['ip'],0))
            sock.connect(address)
            if sock.getsockname()[0]!=self.interface['ip']:
                raise OSError('Unexpected source interface')
            return sock
        except Exception:
            sock.close()
            raise

    def verify(self,api=None,probe_ip='104.17.154.105',port=443):
        """Require real TLS traffic, physical source, and absence from main TUN."""
        raw=self.connect((probe_ip,port),timeout=5)
        local=raw.getsockname()
        try:
            with ssl.create_default_context().wrap_socket(raw,server_hostname='www.cloudflare.com') as stream:
                stream.sendall(b'GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: keep-alive\r\n\r\n')
                response=http.client.HTTPResponse(stream)
                response.begin()
                if response.status!=200:
                    raise OSError('Bound physical HTTPS probe failed')
                # Read a complete small CF response to ensure a lazy TUN proxy
                # would have established its connection before inspecting API.
                body=response.read(8192)
                if b'ip=' not in body or b'colo=' not in body:
                    raise OSError('Unexpected CF trace response')
                rows=api.request('GET','/connections',timeout=3).get('connections',[]) if api else []
                if any(str(row.get('metadata',{}).get('sourcePort'))==str(local[1]) for row in rows):
                    raise OSError('Bound verification traffic was intercepted by main TUN')
        finally:
            raw.close()
        return {'verified':True,'interface':self.interface['name'],'index':self.interface['index'],
                'physical_source':True,'main_tun_intercepted':False if api else None}
