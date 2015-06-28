from .http import HttpEnumeration
from .ftp import FtpEnumeration
from .nbt import NbtEnumeration
from .ssh import SshEnumeration
from .rpc import RpcEnumeration
from .mysql import MysqlEnumeration
from .smtp import SmtpEnumeration
from .snmp import SnmpEnumeration
from .vnc import VncEnumeration
from .rdp import RdpEnumeration
from .ssl import SslEnumeration
from .smb import SmbEnumeration

http = HttpEnumeration()
ftp = FtpEnumeration()
nbt = NbtEnumeration()
ssh = SshEnumeration()
rpc = RpcEnumeration()
mysql = MysqlEnumeration()
smtp = SmtpEnumeration()
snmp = SnmpEnumeration()
vnc = VncEnumeration()
rdp = RdpEnumeration()
ssl = SslEnumeration()
smb = SmbEnumeration()

service_modules = [http, ftp, nbt, ssh, rpc, mysql, smtp, snmp, vnc, rdp, ssl, smb]
