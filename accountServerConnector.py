import asyncio
import datetime
import json
import os
from enum import Enum
from typing import Dict, List, Optional
from aiohttp import web
import aiohttp

import mapadroid.plugins.pluginBase
from plugins.accountServerConnector.endpoints import register_custom_plugin_endpoints
from mapadroid.utils.collections import Login_PTC
from mapadroid.mapping_manager.MappingManagerDevicemappingKey import \
    MappingManagerDevicemappingKey

try:
    # always keep this line first as it's our indicator on whether account_handling is present or not
    from mapadroid.account_handler.AbstractAccountHandler import AbstractAccountHandler, AccountPurpose, BurnType
    from mapadroid.db.DbWrapper import DbWrapper
    from mapadroid.db.helper.SettingsDeviceHelper import SettingsDeviceHelper
    from mapadroid.db.model import SettingsDevice, SettingsPogoauth
    from mapadroid.utils.collections import Location
    from mapadroid.utils.global_variables import (MAINTENANCE_COOLDOWN_HOURS,
                                                  MIN_LEVEL_IV, MIN_LEVEL_RAID,
                                                  QUEST_WALK_SPEED_CALCULATED)
except Exception as e:
    pass


class accountServerConnector(mapadroid.plugins.pluginBase.Plugin):
    """accountServerConnector plugin
    """

    def _file_path(self) -> str:
        return os.path.dirname(os.path.abspath(__file__))

    async def patch_get_strategy(self):
        self.logger.info("try to patch get_strategy")
        old_get_strategy = self.strategy_factory.get_strategy
        async def new_get_strategy(worker_type, area_id, communicator, walker_settings, worker_state):
            async def new_get_next_account(origin=worker_state.origin):
                return await self.request_account(origin)
            strategy = await old_get_strategy(worker_type, area_id, communicator, walker_settings, worker_state)
            logintype = await self.mm.get_devicesetting_value_of_device(worker_state.origin,
                                                                        MappingManagerDevicemappingKey.LOGINTYPE)
            if logintype == "ptc" and strategy._word_to_screen_matching.get_next_account != new_get_next_account:
                self.logger.info(f"patch get_next_account for {worker_state.origin} using PTC accounts")
                strategy._word_to_screen_matching.get_next_account = new_get_next_account
            elif strategy._word_to_screen_matching.get_next_account == new_get_next_account:
                self.logger.warning(f"already patched for {worker_state.origin}")
            else:
                self.logger.info(f"not patching for {worker_state.origin} - logintype is {logintype}")
            return strategy
        self.strategy_factory.get_strategy = new_get_strategy
        self.logger.success("patched get_strategy / get_next_account!")

    def check_for_account_handler(self):
        try:
            _ = AbstractAccountHandler()
        except TypeError:
            self.new_mode = True

            # define our own AccountHandler class when AbstractAccountHandler is available, indicated by TypeError
            global ServerConnectorAccountHandler
            class ServerConnectorAccountHandler(AbstractAccountHandler):
                _assignment_lock: asyncio.Lock

                def __init__(self, db_wrapper: DbWrapper, session, logger, request_account):
                    self._assignment_lock = asyncio.Lock()
                    self._db_wrapper = db_wrapper
                    self.session = session
                    self.logger = logger
                    self.request_account = request_account
                    self.logger.debug("custom init of ServerConnectorAccountHandler ran through!")

                async def get_name_from_device_id(self, device_id):
                    async with self._db_wrapper as session, session:
                        device_entry: Optional[SettingsDevice] = await SettingsDeviceHelper.get(session,
                                                                                                self._db_wrapper.get_instance_id(),
                                                                                                device_id)
                    if not device_entry:
                        logger.warning("Invalid device ID {} passed to fetch an account for it", device_id)
                        return None
                    return device_entry.name

                async def request_to_server(self, url):
                    try:
                        async with self.session.get(url) as r:
                            content = await r.content.read()
                            content = content.decode()
                            if r.ok:
                                self.logger.info(f"Request ok, response: {content}")
                                return content
                            else:
                                self.logger.warning(f"Request NOT ok, response: {content}")
                                return content
                    except Exception as e:
                        self.logger.exception(f"Exception in request to {url}: {e}")
                        return None

                async def get_account(self, device_id: int, purpose: AccountPurpose,
                                      location_to_scan: Optional[Location],
                                      including_google: bool = True) -> Optional[SettingsPogoauth]:
                    self.logger.debug("get_account called")
                    name = await self.get_name_from_device_id(device_id)
                    if not name:
                        return None

                    # default to MIN_LEVEL_IV - usually the highest and thus safest
                    level: int = MIN_LEVEL_IV
                    if purpose == AccountPurpose.MON_RAID:
                        # No IV scanning or just raids
                        level = MIN_LEVEL_RAID
                    elif purpose in [AccountPurpose.IV, AccountPurpose.IV_QUEST, AccountPurpose.QUEST]:
                        level = MIN_LEVEL_IV
                    elif purpose == AccountPurpose.LEVEL:
                        level: int = 1

                    username, password = await self.request_account(name, level=level)

                    ret = SettingsPogoauth()
                    ret.login_type = "ptc"
                    ret.username = username
                    ret.password = password
                    ret.level = level

                    return ret

                async def mark_burnt(self, device_id: int, burn_type: Optional[BurnType]) -> None:
                    self.logger.debug("mark_burnt called")
                    name = await self.get_name_from_device_id(device_id)
                    if not name:
                        return None
                    url = f"http://{self.server_host}:{self.server_port}/set/burned/by-device/{name}"
                    self.logger.info(f"Try to mark as burned: {url}")
                    await self.request_to_server(url)

                async def set_level(self, device_id: int, level: int) -> None:
                    self.logger.debug("set_level called")
                    name = await self.get_name_from_device_id(device_id)
                    if not name:
                        return None
                    url = f"http://{self.server_host}:{self.server_port}/set/level/by-device/{name}"
                    self.logger.info(f"Try to set level: {url}")
                    await self.request_to_server(url)

                async def get_assigned_username(self, device_id: int) -> Optional[str]:
                    self.logger.debug("get_assigned_username called")
                    name = await self.get_name_from_device_id(device_id)
                    if not name:
                        return None
                    url = f"http://{self.server_host}:{self.server_port}/get-current/{name}"
                    response = await self.request_to_server(url)
                    return response.get("data", {}).get("username", None)

                async def set_last_softban_action(self, device_id: int, time_of_action: datetime.datetime,
                                                              location_of_action: Location) -> None:
                    self.logger.warning("set_last_softban_action called - doing nothing")
                    pass

                async def notify_logout(self, device_id: int) -> None:
                    self.logger.warning("notify_logout called - doing nothing")
                    pass

                async def is_burnt(self, *args, **kwargs) -> bool:
                    # always return True: if MAD wants to know the burn status, we always want to make it call the
                    # account server, so the server can handle the burn states (return new or same account)
                    self.logger.warning("is_burnt called - always return True")
                    return True

        except Exception as e:
            self.new_mode = False

    def __init__(self, subapp_to_register_to: web.Application, mad_parts: Dict):
        super().__init__(subapp_to_register_to, mad_parts)

        self._rootdir = os.path.dirname(os.path.abspath(__file__))
        self._mad = self._mad_parts
        self.logger = self._mad['logger']
        self.mm = self._mad['mapping_manager']
        self.strategy_factory = self._mad['ws_server']._WebsocketServer__strategy_factory

        statusname = self._mad["args"].status_name
        self.logger.info("Got statusname: {}", statusname)
        if os.path.isfile(self._rootdir + "/plugin-" + statusname + ".ini"):
            self._pluginconfig.read(self._rootdir + "/plugin-" + statusname + ".ini")
            self.logger.info("loading instance-specific config for {}", statusname)
        else:
            self._pluginconfig.read(self._rootdir + "/plugin.ini")
            self.logger.info("loading standard plugin.ini")

        self._versionconfig.read(self._rootdir + "/version.mpl")
        self.author = self._versionconfig.get("plugin", "author", fallback="unknown")
        self.url = self._versionconfig.get("plugin", "url", fallback="https://www.maddev.eu")
        self.description = self._versionconfig.get("plugin", "description", fallback="unknown")
        self.version = self._versionconfig.get("plugin", "version", fallback="unknown")
        self.pluginname = self._versionconfig.get("plugin", "pluginname", fallback="https://www.maddev.eu")
        self.staticpath = self._rootdir + "/static/"
        self.templatepath = self._rootdir + "/template/"

        # plugin specific
        self.server_host = self._pluginconfig.get(statusname, "server_host", fallback="127.0.0.1")
        self.server_port = self._pluginconfig.getint(statusname, "server_port", fallback=9008)
        global_auth_username = self._pluginconfig.get("plugin", "auth_username", fallback=None)
        global_auth_password = self._pluginconfig.get("plugin", "auth_password", fallback=None)
        self.auth_username = self._pluginconfig.get(statusname, "auth_username", fallback=global_auth_username)
        self.auth_password = self._pluginconfig.get(statusname, "auth_password", fallback=global_auth_password)

        if self.auth_username and self.auth_password:
            auth = aiohttp.BasicAuth(self.auth_username, self.auth_password)
        else:
            auth = None
        self.session = aiohttp.ClientSession(auth=auth)

        # linking pages
        self._hotlink = [
            ("accountServerConnector Manual", "accountserver_manual", "accountServerConnector Manual"),
        ]

        if self._pluginconfig.getboolean("plugin", "active", fallback=False):
            register_custom_plugin_endpoints(self._plugin_subapp)

            for name, link, description in self._hotlink:
                self._mad_parts['madmin'].add_plugin_hotlink(name, link.replace("/", ""),
                                                       self.pluginname, self.description, self.author, self.url,
                                                       description, self.version)

    async def _perform_operation(self):
        if not self._pluginconfig.getboolean("plugin", "active", fallback=False):
            return False
        self.check_for_account_handler()
        if self.new_mode:
            ah = ServerConnectorAccountHandler(self._mad["db_wrapper"], self.session, self.logger, self.request_account)
            self.mm._MappingManager__account_handler = ah
            # I hope that's all places to patch ...
            self._mad['ws_server']._WebsocketServer__strategy_factory._StrategyFactory__account_handler = ah
            self._mad['mitm_receiver']._account_handler = ah
            self._mad['mitm_data_processor_manager']._account_handler = ah
            self.logger.success("New mode activated!")
        else:
            await self.patch_get_strategy()
            self.logger.warning("Old mode activated!")
        return True

    async def request_account(self, origin, level=None):
        if level:
            url = f"http://{self.server_host}:{self.server_port}/get/{origin}/{int(level)}"
        else:
            url = f"http://{self.server_host}:{self.server_port}/get/{origin}"
        self.logger.info(f"Try to get account from: {url}")
        try:
            async with self.session.get(url) as r:
                content = await r.content.read()
                content = content.decode()
                if r.ok:
                    self.logger.info(f"Request ok, response: {content}")
                    j = json.loads(content)
                    username = j["data"]["username"]
                    password = j["data"]["password"]
                    return Login_PTC(username, password)
                else:
                    self.logger.warning(f"Request NOT ok, response: {content}")
                    return False
        except Exception as e:
            self.logger.exception(f"Exception trying to request account from account server: {e}")
            return False
