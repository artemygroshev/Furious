# Copyright (C) 2024–present  Loren Eteval & contributors <loren.eteval@proton.me>
#
# This file is part of Furious.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from __future__ import annotations

from Furious.Frozenlib import *
from Furious.Interface import *
from Furious.Library import *
from Furious.Qt import *
from Furious.Core.CoreProcessWorker import *
from Furious.Core.XrayCore import *
from Furious.Core.Hysteria1 import *
from Furious.Core.Hysteria2 import *
from Furious.Core.Tun2socks import *

from typing import Callable, Tuple, Union

import os
import uuid
import logging
import tempfile
import functools
import subprocess
import ipaddress
import shlex

__all__ = ['cleanRoutingRule', 'configureLinuxTunAnyDeskBypass', 'CoreManager']

logger = logging.getLogger(__name__)

ROCKYRAY_ANYDESK_DOMAIN = 'domain:net.anydesk.com'
ROCKYRAY_ANYDESK_OUTBOUND_TAG = 'rockyray-anydesk-direct'
ROCKYRAY_ANYDESK_RULE_TAG = 'rockyray-anydesk-direct'
ROCKYRAY_DIRECT_SOURCE_IP = '169.254.252.82'
ROCKYRAY_SPLIT_ROUTING_HELPER = '/usr/local/sbin/rockyray-split-routing'


def resolveSplitRoutingHelper() -> str:
    localProjectHelper = os.path.normpath(
        os.path.join(
            os.path.dirname(__file__), '..', '..', 'tools', 'rockyray-split-routing'
        )
    )

    if (
        os.path.exists(localProjectHelper)
        and os.path.isfile(localProjectHelper)
        and os.access(localProjectHelper, os.X_OK)
    ):
        return localProjectHelper

    return ROCKYRAY_SPLIT_ROUTING_HELPER


def validateLinuxTunRoutingPrerequisites(interface: str, gateway: str) -> tuple[bool, str]:
    helper = resolveSplitRoutingHelper()

    if not isinstance(interface, str) or not interface:
        return False, 'empty network interface selected for TUN routing'

    if not isValidIPAddress(gateway):
        return False, f'invalid default gateway for TUN routing: {gateway!r}'

    missingCommands = SystemRoutingTable.linuxRouteToolkitMissingCommands()

    if missingCommands:
        return (
            False,
            f"missing Linux routing tools: {', '.join(missingCommands)}",
        )

    if not os.path.exists(helper):
        return False, f'split-routing helper not found: {helper!r}'

    if not os.access(helper, os.X_OK):
        return False, f'split-routing helper is not executable: {helper!r}'

    return True, ''


def fixLogObjectPath(config: ConfigFactory, attr: str, value: str, log=True):
    try:
        path = config['log'][attr]
    except Exception:
        # Any non-exit exceptions

        config['log'][attr] = path = ''

    if not isinstance(path, str) and not isinstance(path, bytes):
        config['log'][attr] = path = ''

    if path == '':
        if SystemRuntime.isPythonw() and ProcessOutputRedirector.TemporaryDir.isValid():
            # Redirect implementation for pythonw environment
            config['log'][attr] = ProcessOutputRedirector.TemporaryDir.filePath(value)
    else:
        # Relative path fails if booting on start up
        # on Windows, when packed using nuitka...

        # Fix relative path if needed. User cannot feel this operation.
        config['log'][attr] = absolutePath(path)

    result = config['log'][attr]

    if result:
        try:
            # Create a new file
            with open(result, 'x', encoding='utf-8'):
                pass
        except FileExistsError:
            pass
        except Exception:
            # Any non-exit exceptions

            pass

    if log:
        logger.info(
            f'{XrayCore.name()}: {attr} log is specified as \'{path}\'. '
            f'Fixed to \'{result}\''
        )


def cleanRoutingRule(rule: dict):
    if not isinstance(rule, dict):
        return None

    result = {
        'type': 'field',
        'outboundTag': str(rule.get('outboundTag', 'proxy')).strip() or 'proxy',
    }

    for key in [
        'domain',
        'ip',
        'sourceIP',
        'localIP',
        'user',
        'protocol',
        'inboundTag',
        'process',
    ]:
        value = rule.get(key, [])

        if isinstance(value, list):
            value = list(str(item).strip() for item in value if str(item).strip())

            if value:
                result[key] = value

    for key in [
        'port',
        'sourcePort',
        'localPort',
        'network',
        'vlessRoute',
        'balancerTag',
        'ruleTag',
    ]:
        value = str(rule.get(key, '')).strip()

        if value:
            result[key] = value

    if len(result) <= 2:
        return None

    return result


def customRoutingObjectFromSettings(routing: str):
    prefix = 'Custom:'

    if not isinstance(routing, str) or not routing.startswith(prefix):
        return None

    unique = routing[len(prefix) :]
    routingProfile = Storage.UserRoutings().get(unique)

    if not isinstance(routingProfile, dict):
        logger.warning(f'custom routing profile {routing!r} is unavailable')
        return None

    if not routingProfile.get('enabled', True):
        logger.warning(
            f'custom routing profile {routing!r} is disabled, fallback to global routing'
        )
        return None

    domainStrategy = routingProfile.get('domainStrategy', 'AsIs')

    if domainStrategy not in ['AsIs', 'IPIfNonMatch', 'IPOnDemand']:
        domainStrategy = 'AsIs'

    rawRules = routingProfile.get('rules', [])
    if not isinstance(rawRules, list):
        logger.warning(
            f'custom routing profile {routing!r} has invalid rules type '
            f'({type(rawRules)}), ignoring them'
        )
        rawRules = []

    rules = list(
        filter(
            lambda rule: rule is not None,
            list(cleanRoutingRule(rule) for rule in rawRules),
        )
    )

    return {
        'domainStrategy': domainStrategy,
        'domainMatcher': 'hybrid',
        'rules': rules,
    }


def routingObjectHasDirectRule(routingObject: dict) -> bool:
    try:
        return any(
            rule.get('outboundTag') == 'direct'
            for rule in routingObject.get('rules', [])
            if isinstance(rule, dict)
        )
    except Exception:
        # Any non-exit exceptions

        return False


def configureLinuxTunAnyDeskBypass(
    config: dict,
    routingObject: dict,
    sourceIP: str,
) -> bool:
    """Route AnyDesk outside the Linux TUN without granting Xray capabilities."""

    try:
        sourceAddress = ipaddress.ip_address(sourceIP)
    except (TypeError, ValueError):
        return False

    if sourceAddress.version != 4:
        return False

    inbounds = config.get('inbounds')
    outbounds = config.get('outbounds')

    if (
        not isinstance(inbounds, list)
        or not isinstance(outbounds, list)
        or not isinstance(routingObject, dict)
    ):
        return False

    socksInbound = next(
        (
            inbound
            for inbound in inbounds
            if isinstance(inbound, dict) and inbound.get('protocol') == 'socks'
        ),
        None,
    )

    if socksInbound is None:
        return False

    sniffing = socksInbound.get('sniffing')

    if sniffing is None:
        sniffing = {}
    elif not isinstance(sniffing, dict):
        return False

    destOverride = sniffing.get('destOverride')

    if destOverride is None:
        destOverride = []
    elif not isinstance(destOverride, list):
        return False

    if not all(isinstance(item, str) for item in destOverride):
        return False

    rules = routingObject.get('rules')

    if rules is None:
        rules = []
    elif not isinstance(rules, list):
        return False

    # Keep this outbound dedicated to AnyDesk. Binding a local source address
    # does not require CAP_NET_ADMIN; the system policy rule installed by
    # rockyray-split-routing sends that source through the physical gateway.
    anydeskOutbound = {
        'tag': ROCKYRAY_ANYDESK_OUTBOUND_TAG,
        'protocol': 'freedom',
        'sendThrough': str(sourceAddress),
        'settings': {
            'domainStrategy': 'UseIPv4',
        },
    }

    outbounds[:] = list(
        outbound
        for outbound in outbounds
        if not (
            isinstance(outbound, dict)
            and outbound.get('tag') == ROCKYRAY_ANYDESK_OUTBOUND_TAG
        )
    )
    outbounds.append(anydeskOutbound)

    sniffing = dict(sniffing)
    sniffing['enabled'] = True
    sniffing['destOverride'] = list(
        dict.fromkeys([*destOverride, 'http', 'tls'])
    )
    # The sniffed name must replace the original IP. Otherwise any process
    # could present an AnyDesk SNI while retaining an arbitrary destination
    # and inherit the physical-route bypass.
    sniffing['metadataOnly'] = False
    sniffing['routeOnly'] = False
    sniffing['domainsExcluded'] = []
    sniffing['ipsExcluded'] = []
    socksInbound['sniffing'] = sniffing

    rules = list(
        rule
        for rule in rules
        if not (
            isinstance(rule, dict)
            and rule.get('ruleTag') == ROCKYRAY_ANYDESK_RULE_TAG
        )
    )
    rules.insert(
        0,
        {
            'type': 'field',
            'ruleTag': ROCKYRAY_ANYDESK_RULE_TAG,
            'domain': [ROCKYRAY_ANYDESK_DOMAIN],
            'outboundTag': ROCKYRAY_ANYDESK_OUTBOUND_TAG,
        },
    )

    routingObject.setdefault('domainStrategy', 'AsIs')
    routingObject.setdefault('domainMatcher', 'hybrid')
    routingObject['rules'] = rules

    return True


def getUserTUNSettings(*args, **kwargs):
    return Storage.UserTUNSettings().get(*args, **kwargs)


(
    userPrimaryAdapterInterfaceName,
    userPrimaryAdapterInterfaceIP,
    userDefaultPrimaryGatewayIP,
    userTunAdapterInterfaceDNS,
    userBypassTUNAdapterInterfaceIP,
    userDisablePrimaryAdapterInterfaceDNS,
    userTcpSendBufferSize,
    userTcpReceiveBufferSize,
    userTcpAutoTuning,
) = (
    functools.partial(getUserTUNSettings, 'primaryAdapterInterfaceName', ''),
    functools.partial(getUserTUNSettings, 'primaryAdapterInterfaceIP', ''),
    functools.partial(getUserTUNSettings, 'defaultPrimaryGatewayIP', ''),
    functools.partial(getUserTUNSettings, 'tunAdapterInterfaceDNS', ''),
    functools.partial(getUserTUNSettings, 'bypassTUNAdapterInterfaceIP', ''),
    functools.partial(getUserTUNSettings, 'disablePrimaryAdapterInterfaceDNS', 'True'),
    functools.partial(getUserTUNSettings, 'tcpSendBufferSize', 1),
    functools.partial(getUserTUNSettings, 'tcpReceiveBufferSize', 1),
    functools.partial(getUserTUNSettings, 'tcpAutoTuning', 'False'),
)


class CoreManager(Mixins.CleanupOnExit):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.uniqueCleanup = False
        self.processesPool = list()

    @functools.singledispatchmethod
    def _startCore(
        self,
        config,
        routing,
        exitCallback=None,
        msgCallback=None,
        proxyModeOnly=False,
        log=True,
        **kwargs,
    ) -> Tuple[Union[CoreProcessWorker, None], bool]:
        return None, False

    @_startCore.register(ConfigXray)
    def _(
        self,
        config,
        routing,
        exitCallback=None,
        msgCallback=None,
        proxyModeOnly=False,
        log=True,
        **kwargs,
    ):
        linuxTunDirectSourceIP = kwargs.pop('linuxTunDirectSourceIP', '')
        customRoutingObject = customRoutingObjectFromSettings(routing)

        if config.get('log') is None or not isinstance(config['log'], dict):
            config['log'] = {
                'access': '',
                'error': '',
                'loglevel': 'warning',
            }

        logRedirectValue = str(uuid.uuid4())

        # Fix logObject
        for attr in ['access', 'error']:
            fixLogObjectPath(config, attr, logRedirectValue, log)

        if routing == AppBuiltinRouting.BypassMainlandChina.value:
            # TUN Mode handling
            if not proxyModeOnly and SystemRuntime.isTUNMode():
                showMBoxDirectRulesNotAllowed()

                return None, False

            routingObject = {
                'domainStrategy': 'IPIfNonMatch',
                'domainMatcher': 'hybrid',
                'rules': [
                    {
                        'type': 'field',
                        'domain': [
                            'geosite:category-ads-all',
                        ],
                        'outboundTag': 'block',
                    },
                    {
                        'type': 'field',
                        'domain': [
                            'geosite:cn',
                        ],
                        'outboundTag': 'direct',
                    },
                    {
                        'type': 'field',
                        'ip': [
                            'geoip:private',
                            'geoip:cn',
                        ],
                        'outboundTag': 'direct',
                    },
                    {
                        'type': 'field',
                        'port': '0-65535',
                        'outboundTag': 'proxy',
                    },
                ],
            }
        elif routing == AppBuiltinRouting.Global.value:
            routingObject = {}
        elif customRoutingObject is not None:
            if (
                not proxyModeOnly
                and SystemRuntime.isTUNMode()
                and routingObjectHasDirectRule(customRoutingObject)
            ):
                logger.warning(
                    f'custom routing profile {routing!r} contains direct rules, disallowed '
                    'under TUN mode'
                )
                showMBoxDirectRulesNotAllowed()

                return None, False

            routingObject = customRoutingObject
        elif routing == AppBuiltinRouting.Custom.value:
            routingObject = config.get('routing', {})
            if not isinstance(routingObject, dict):
                logger.warning(
                    f'custom routing configuration for {XrayCore.name()} is not a dict: '
                    f'{type(routingObject)}'
                )
                routingObject = {}
        else:
            if isinstance(routing, str) and routing.startswith('Custom:'):
                logger.warning(
                    f'custom routing profile {routing!r} is unavailable; '
                    'using global routing'
                )

            routingObject = {}

        if linuxTunDirectSourceIP and not configureLinuxTunAnyDeskBypass(
            config,
            routingObject,
            linuxTunDirectSourceIP,
        ):
            logger.error('failed to configure the Linux TUN AnyDesk bypass')

            return None, False

        if log:
            logger.info(f'core {XrayCore.name()} configured')
            logger.info(f'routing is {routing}')
            logger.info(f'RoutingObject: {routingObject}')

        config['routing'] = routingObject

        process = XrayCore(exitCallback=exitCallback, msgCallback=msgCallback)
        success = process.start(config, **kwargs)

        return process, success

    @_startCore.register(ConfigHysteria1)
    def _(
        self,
        config,
        routing,
        exitCallback=None,
        msgCallback=None,
        proxyModeOnly=False,
        log=True,
        **kwargs,
    ):
        if routing == AppBuiltinRouting.BypassMainlandChina.value:
            # TUN Mode handling
            if not proxyModeOnly and SystemRuntime.isTUNMode():
                showMBoxDirectRulesNotAllowed()

                return None, False

            routingObject = {
                'rule': DATA_DIR / 'hysteria' / 'bypass-mainland-China.acl',
                'mmdb': DATA_DIR / 'hysteria' / 'country.mmdb',
            }
        elif routing == AppBuiltinRouting.Global.value:
            routingObject = {
                'rule': '',
                'mmdb': '',
            }
        elif routing == AppBuiltinRouting.Custom.value:
            routingObject = {
                'rule': config.get('acl', ''),
                'mmdb': config.get('mmdb', ''),
            }
        else:
            routingObject = {
                'rule': '',
                'mmdb': '',
            }

        if log:
            logger.info(f'core {Hysteria1.name()} configured')
            logger.info(f'routing is {routing}')
            logger.info(f'RoutingObject: {routingObject}')

        process = Hysteria1(exitCallback=exitCallback, msgCallback=msgCallback)
        success = process.start(
            config,
            Hysteria1.rule(routingObject.get('rule', '')),
            Hysteria1.mmdb(routingObject.get('mmdb', '')),
            **kwargs,
        )

        return process, success

    @_startCore.register(ConfigHysteria2)
    def _(
        self,
        config,
        routing,
        exitCallback=None,
        msgCallback=None,
        proxyModeOnly=False,
        log=True,
        **kwargs,
    ):
        if log:
            logger.info(f'core {Hysteria2.name()} configured')

        process = Hysteria2(exitCallback=exitCallback, msgCallback=msgCallback)
        success = process.start(config, **kwargs)

        return process, success

    @staticmethod
    def waitForTUNDeviceBroughtUp(func: Callable[[str], bool], deviceName: str) -> bool:
        for counter in range(0, 10000, 100):
            if func(deviceName):
                logger.info(
                    f'find TUN device \'{deviceName}\' success. Counter: {counter}'
                )

                return True

            PySide6Legacy.eventLoopWait(100)

        logger.error(f'find TUN device \'{deviceName}\' failed')

        return False

    def start(
        self,
        config: ConfigFactory,
        routing: str,
        exitCallback=None,
        msgCallbackCore=None,
        msgCallbackTUN_=None,
        deepcopy=True,
        proxyModeOnly=False,
        log=True,
        **kwargs,
    ) -> bool:
        if deepcopy:
            configcopy = config.deepcopy()
        else:
            configcopy = config

        def abortStart(message: str = ''):
            if message:
                logger.error(message)

            self.stopAll()

            return False

        if (
            isinstance(configcopy, ConfigXray)
            and PLATFORM == 'Linux'
            and not proxyModeOnly
            and SystemRuntime.isTUNMode()
        ):
            kwargs['linuxTunDirectSourceIP'] = ROCKYRAY_DIRECT_SOURCE_IP

        process, success = self._startCore(
            configcopy,
            routing,
            exitCallback,
            msgCallbackCore,
            proxyModeOnly,
            log,
            **kwargs,
        )

        if process is not None:
            self.processesPool.append(process)

        if not success:
            if isinstance(process, CoreProcessWorker):
                logger.error(f'core {process.name()} start failed')

            self.stopAll()

            return False

        # TUN Mode handling
        if not proxyModeOnly and SystemRuntime.isTUNMode():
            if PLATFORM == 'Windows':
                # cleanup first
                SystemRoutingTable.delete('0.0.0.0', APPLICATION_TUN_GATEWAY_ADDRESS)

            # Handle user defined settings
            userGateway, userInterfaceIP = (
                userDefaultPrimaryGatewayIP(),
                userPrimaryAdapterInterfaceIP(),
            )

            if userGateway and userInterfaceIP:
                logger.info(
                    f'got user defined TUN settings. '
                    f'\'DefaultPrimaryGatewayIP\': {userGateway}. '
                    f'\'PrimaryAdapterInterfaceIP\': {userInterfaceIP}'
                )

                gateway, interface = userGateway, userInterfaceIP
            else:
                logger.info(
                    f'automatically fetching TUN settings: '
                    f'\'DefaultPrimaryGatewayIP\' and \'PrimaryAdapterInterfaceIP\''
                )

                defaultGateway = SystemRoutingTable.getDefaultGateway()

                if PLATFORM == 'Darwin':
                    # Need this?
                    defaultGateway = list(
                        # Filter TUN Gateway
                        filter(
                            lambda x: x != APPLICATION_TUN_GATEWAY_ADDRESS,
                            defaultGateway,
                        )
                    )

                if PLATFORM == 'Windows':
                    if len(defaultGateway) == 0:
                        return abortStart(f'bad default gateway: {defaultGateway}')

                    if len(defaultGateway) > 1:
                        logger.warning(
                            f'multiple Windows default gateways found: {defaultGateway}'
                        )

                    gateway, interface = defaultGateway[0]
                elif PLATFORM == 'Linux':
                    if not isinstance(defaultGateway, list):
                        defaultGateway = list(defaultGateway)

                    defaultGatewayList = list(
                        item
                        for item in defaultGateway
                        if isinstance(item, (list, tuple))
                        and len(item) == 2
                    )

                    if not defaultGatewayList:
                        return abortStart(f'bad default gateway: {defaultGateway}')

                    linuxCandidates = list(
                        item
                        for item in defaultGatewayList
                        if item[1] != APPLICATION_TUN_DEVICE_NAME
                        and item[1] != 'lo'
                        and item[0] != APPLICATION_TUN_GATEWAY_ADDRESS
                    )

                    if linuxCandidates:
                        if len(linuxCandidates) > 1:
                            logger.warning(
                                'multiple Linux default gateways found, selecting first '
                                'non-TUN candidate'
                            )

                        gateway, interface = linuxCandidates[0]
                    else:
                        if len(defaultGatewayList) > 1:
                            logger.warning(
                                'all Linux default gateways are TUN/loopback candidates, '
                                f'using first: {defaultGatewayList}'
                            )

                        gateway, interface = defaultGatewayList[0]
                elif PLATFORM == 'Darwin':
                    gateway, interface = defaultGateway[0], None
                else:
                    return abortStart(f'unrecognized platform: {PLATFORM}')

            if PLATFORM == 'Linux':
                canRoute, reason = validateLinuxTunRoutingPrerequisites(interface, gateway)

                if not canRoute:
                    return abortStart(reason)

            tun = Tun2socks(exitCallback=exitCallback, msgCallback=msgCallbackTUN_)
            self.processesPool.append(tun)

            tcpSendBufferSize, tcpReceiveBufferSize, tcpAutoTuning = (
                userTcpSendBufferSize(),
                userTcpReceiveBufferSize(),
                userTcpAutoTuning(),
            )

            if tcpSendBufferSize != 1:
                logger.info(
                    f'got user defined TUN settings. TcpSendBufferSize: {tcpSendBufferSize}'
                )

            if tcpReceiveBufferSize != 1:
                logger.info(
                    f'got user defined TUN settings. TCPReceiveBufferSize: {tcpReceiveBufferSize}'
                )

            if tcpAutoTuning == 'False':
                tcpAutoTuning = False
            elif tcpAutoTuning == 'True':
                tcpAutoTuning = True

                logger.info(
                    f'got user defined TUN settings. TcpAutoTuning: {tcpAutoTuning}'
                )
            else:
                tcpAutoTuning = False

            if PLATFORM != 'Linux':
                interfaceArg = APPLICATION_TUN_NETWORK_INTERFACE_NAME
            else:
                interfaceArg = interface

            startTUN = functools.partial(
                tun.start,
                APPLICATION_TUN_DEVICE_NAME,
                interfaceArg,
                'error',
                f'socks5://{configcopy.socksProxy()}',
                '',
                f'{tcpSendBufferSize}MB',
                f'{tcpReceiveBufferSize}MB',
                tcpAutoTuning,
            )

            if PLATFORM != 'Linux':
                # Windows & macOS: bring up TUN first
                if not startTUN():
                    return abortStart(f'core {Tun2socks.name()} start failed')

            # Handle user defined settings
            bypassTUN = userBypassTUNAdapterInterfaceIP()

            if bypassTUN:
                try:
                    bypassSplit = bypassTUN.split(',')
                except Exception as ex:
                    # Any non-exit exceptions

                    logger.error(
                        f'error when processing user TUN bypass settings: {ex}'
                    )

                    SystemRoutingTable.Relations.clear()

                    return abortStart('invalid user-defined TUN bypass settings')
                else:
                    for bypass in bypassSplit:
                        if isValidIPAddress(bypass):
                            logger.info(f'processing user TUN bypass IP: {bypass}')

                            SystemRoutingTable.Relations.append([bypass, gateway])
                        else:
                            logger.error(
                                f'invalid IP address when processing '
                                f'user TUN bypass settings: {bypass}'
                            )

                            SystemRoutingTable.Relations.clear()

                            return abortStart(f'invalid IP in TUN bypass list: {bypass}')
            else:
                logger.info(
                    f'automatically fetching TUN settings: '
                    f'\'BypassTUNAdapterInterfaceIP\''
                )

                address = configcopy.itemAddress

                if not isValidIPAddress(address):
                    DNSResolver.configureHttpProxy(configcopy.httpProxy())

                    error, resolved = DNSResolver.resolve(address)

                    if error:
                        SystemRoutingTable.Relations.clear()

                        return abortStart(f'DNS resolution failed: {address}')
                    else:
                        for address in resolved:
                            SystemRoutingTable.Relations.append([address, gateway])
                else:
                    SystemRoutingTable.Relations.append([address, gateway])

            # Platform specific implementation
            if PLATFORM == 'Windows':
                if not self.waitForTUNDeviceBroughtUp(
                    SystemRoutingTable.WIN32IpconfigFindContent,
                    APPLICATION_TUN_DEVICE_NAME,
                ):
                    return abortStart('TUN interface failed to come up on Windows')

                # Handle user defined settings
                userInterfaceName = userPrimaryAdapterInterfaceName()

                if userInterfaceName:
                    logger.info(
                        f'got user defined TUN settings. '
                        f'\'PrimaryAdapterInterfaceName\': {userInterfaceName}'
                    )

                    alias = userInterfaceName
                else:
                    logger.info(
                        f'automatically fetching TUN settings: '
                        f'\'PrimaryAdapterInterfaceName\''
                    )

                    alias = SystemRoutingTable.WIN32GetInterfaceAliasByIP(interface)

                if alias:

                    def _windowsCleanup(_alias):
                        SystemRoutingTable.WIN32SetInterfaceDNS(_alias)
                        SystemRoutingTable.WIN32FlushDNSCache()

                    tun.cleanup = functools.partial(_windowsCleanup, alias)

                    # Handle user defined settings
                    userDisableInterfaceDNS = userDisablePrimaryAdapterInterfaceDNS()

                    logger.info(
                        f'DisablePrimaryInterfaceDNS: {userDisableInterfaceDNS}'
                    )

                    if userDisableInterfaceDNS != 'False':
                        SystemRoutingTable.WIN32SetInterfaceDNS(
                            alias, '127.0.0.1', False
                        )

                # Handle user defined settings
                userTunInterfaceDNS = userTunAdapterInterfaceDNS()

                if userTunInterfaceDNS == '':
                    userTunInterfaceDNS = APPLICATION_TUN_INTERFACE_DNS_ADDRESS
                else:
                    logger.info(
                        f'got user defined TUN settings. '
                        f'TunAdapterInterfaceDNS: {userTunInterfaceDNS}'
                    )

                SystemRoutingTable.addRelations()
                SystemRoutingTable.WIN32SetInterfaceDNS(
                    APPLICATION_TUN_DEVICE_NAME,
                    userTunInterfaceDNS,
                    False,
                )
                SystemRoutingTable.setDeviceGateway(
                    APPLICATION_TUN_DEVICE_NAME,
                    APPLICATION_TUN_IP_ADDRESS,
                    APPLICATION_TUN_GATEWAY_ADDRESS,
                )
                SystemRoutingTable.WIN32FlushDNSCache()

            # Platform specific implementation
            if PLATFORM == 'Darwin':
                for address in [
                    *list(f'{2 ** (8 - x)}.0.0.0/{x}' for x in range(8, 0, -1)),
                    '198.18.0.0/15',
                ]:
                    SystemRoutingTable.Relations.append(
                        [address, APPLICATION_TUN_GATEWAY_ADDRESS]
                    )

                servers = SystemRoutingTable.DarwinGetDNSServers()

                def _darwinCleanup(_servers):
                    for _service, _dnsserver in _servers:
                        SystemRoutingTable.DarwinSetDNSServers(_service, _dnsserver)

                tun.cleanup = functools.partial(_darwinCleanup, servers)

                # Handle user defined settings
                userTunInterfaceDNS = userTunAdapterInterfaceDNS()

                if userTunInterfaceDNS == '':
                    userTunInterfaceDNS = APPLICATION_TUN_INTERFACE_DNS_ADDRESS
                else:
                    logger.info(
                        f'got user defined TUN settings. '
                        f'TunAdapterInterfaceDNS: {userTunInterfaceDNS}'
                    )

                for service, dnsserver in servers:
                    SystemRoutingTable.DarwinSetDNSServers(
                        service,
                        userTunInterfaceDNS,
                    )

                SystemRoutingTable.setDeviceGateway(
                    APPLICATION_TUN_DEVICE_NAME,
                    APPLICATION_TUN_IP_ADDRESS,
                    APPLICATION_TUN_GATEWAY_ADDRESS,
                )
                SystemRoutingTable.addRelations()

            # Platform specific implementation
            if PLATFORM == 'Linux':

                def _linuxCleanup():
                    try:
                        result = subprocess.run(
                            [
                                'sudo',
                                '-n',
                                resolveSplitRoutingHelper(),
                                'down',
                            ],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            check=False,
                        )

                        if result.returncode != 0:
                            logger.warning(
                                'RockyRay split routing cleanup failed: '
                                + result.stderr.decode(
                                    'utf-8',
                                    'replace',
                                ).strip()
                            )
                    except Exception as ex:
                        logger.warning(
                            f'RockyRay split routing cleanup failed: {ex}'
                        )

                    SystemRoutingTable.LinuxDeleteTUNDevice(
                        APPLICATION_TUN_DEVICE_NAME
                    )

                tun.cleanup = functools.partial(_linuxCleanup)

                if SystemRoutingTable.LinuxFindTUNDevice(APPLICATION_TUN_DEVICE_NAME):
                    logger.info(
                        f'find TUN device {APPLICATION_TUN_DEVICE_NAME} success. '
                        f'Will not try to bring up TUN device again'
                    )

                    commandBringUpTUN = ''
                else:
                    logger.info(
                        f'find TUN device {APPLICATION_TUN_DEVICE_NAME} failed. '
                        f'Will try to bring up TUN device'
                    )

                    commandBringUpTUN = (
                        f'ip tuntap add mode tun dev {APPLICATION_TUN_DEVICE_NAME}\n'
                        f'ip addr add 10.10.10.10/24 dev {APPLICATION_TUN_DEVICE_NAME}\n'
                        f'ip link set dev {APPLICATION_TUN_DEVICE_NAME} up'
                    )

                commandSplitRouting = ' '.join(
                    shlex.quote(str(argument))
                    for argument in (
                        resolveSplitRoutingHelper(),
                        'up',
                        gateway,
                        interface,
                    )
                )

                commandAddDefaultRoute = (
                    f'ip route add default dev {APPLICATION_TUN_DEVICE_NAME} metric 5'
                )

                def route(source, destination) -> str:
                    return f'{source} via {destination} dev {interface}'

                iproute = SystemRoutingTable.LinuxGetIpRoute()

                commandBypass = '\n'.join(
                    list(
                        f'ip route add {route(sourceIP, destinationIP)}'
                        for sourceIP, destinationIP in SystemRoutingTable.Relations
                        if iproute.find(route(sourceIP, destinationIP)) == -1
                    )
                )

                if SystemRuntime.flatpakID():
                    tempdir = os.environ.get('TMPDIR')
                else:
                    tempdir = None

                with tempfile.NamedTemporaryFile(
                    mode='w', encoding='utf-8', suffix='.sh', dir=tempdir, delete=True
                ) as file:
                    content = '\n'.join(
                        filter(
                            lambda x: x != '',
                            [
                                commandBringUpTUN,
                                commandSplitRouting,
                                commandAddDefaultRoute,
                                commandBypass,
                            ],
                        )
                    )

                    file.write(content)
                    file.flush()

                    if not SystemRoutingTable.LinuxExecutePrivilegedScript(
                        file.name, shell='bash'
                    ):
                        return abortStart('failed to apply split-routing rules')

                    if not self.waitForTUNDeviceBroughtUp(
                        SystemRoutingTable.LinuxFindTUNDevice,
                        APPLICATION_TUN_DEVICE_NAME,
                    ):
                        return abortStart('failed to bring TUN device up')

                # Now bring up TUN
                if not startTUN():
                    return abortStart(f'core {Tun2socks.name()} start failed')

        return True

    def allRunning(self) -> bool:
        return all(process.isAlive() for process in self.processesPool)

    def anyRunning(self) -> bool:
        return any(process.isAlive() for process in self.processesPool)

    def stopAll(self):
        try:
            for process in list(self.processesPool):
                if not isinstance(process, CoreProcessFactory):
                    continue

                try:
                    process.stop()
                except Exception as ex:
                    logger.error(f'error stopping core process: {ex}')
        finally:
            self.processesPool.clear()

    def cleanup(self):
        self.stopAll()
