from typing import List

VNODED: str = "vnoded"
VCMD: str = "vcmd"
SYSCTL: str = "sysctl"
IP: str = "ip"
ETHTOOL: str = "ethtool"
TC: str = "tc"
MOUNT: str = "mount"
UMOUNT: str = "umount"
OVS_VSCTL: str = "ovs-vsctl"
NFTABLES: str = "nft"

COMMON_REQUIREMENTS: List[str] = [SYSCTL, IP, ETHTOOL, TC, NFTABLES, MOUNT, UMOUNT]
VCMD_REQUIREMENTS: List[str] = [VNODED, VCMD]
OVS_REQUIREMENTS: List[str] = [OVS_VSCTL]
