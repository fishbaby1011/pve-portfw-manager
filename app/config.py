from .models import EXTERNAL_INTERFACE, INTERNAL_GATEWAY, INTERNAL_INTERFACE, INTERNAL_SUBNET, PROTECTED_PORTS_TEXT, PUBLIC_IP
from portfw.policy import Settings


def panel_settings() -> Settings:
    return Settings(publicIp=PUBLIC_IP, externalInterface=EXTERNAL_INTERFACE,
                    internalInterface=INTERNAL_INTERFACE, internalSubnet=INTERNAL_SUBNET,
                    gateway=INTERNAL_GATEWAY, protectedPorts=PROTECTED_PORTS_TEXT)
