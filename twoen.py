import math

import icecream as ic
import requests
import urllib3
from requests.auth import HTTPDigestAuth


class Device:

    def __init__(self, ip: str, uname: str, pwd: str, timeout=5):
        """
        Creates an instance of a 2N OS device.
        """
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.session = requests.Session()

        self.ip = ip
        self.auth_id = HTTPDigestAuth(uname, pwd)
        self.timeout = timeout
        self.failure = None

        self.online = False
        self.uptime = math.inf
        self.model = "unknown"
        self.name = "unknown"
        self.fw_version = "unknown"
        self.build_type = "unknown"
        self.switches = ["uninitialized"]
        self.capabilities = "unknown"

    def padding(self, text:str) -> str:
        """
        Pads the given text with periods to make logging output more readable.
        """
        return text + (32 - len(text))*"."

    def offline_check(self, e: Exception) -> None:
        """
        Checks whether the given Exception is of the ConnectTimeout meaning the
        device does not respond at all.
        """
        if e.__class__.__name__ == "ConnectTimeout":
            self.online = False
            self.uptime = math.inf

    def logit(self, func, message, logging, verbose=False) -> None:
        """
        Basic logging to the command line.
        """
        if logging and verbose:
            ic.ic(func, message)
        elif logging:
            ic.ic(func)

    def info(self, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves basic information about the device (model, name, fw version
        and build type).
        """
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/system/info"
                ),
                timeout=self.timeout,
                verify=False
            )
            self.online = True
            self.model = command.json()["result"]["variant"]
            self.name = command.json()["result"]["deviceName"]
            self.fw_version = command.json()["result"]["swVersion"]
            self.build_type = command.json()["result"]["buildType"]
            self.logit(self.padding("info:") + "success", command.text, logging, verbose_success)
            self.failure = None
            return True
        except Exception as e:
            self.offline_check(e)
            self.logit(self.padding("info:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def status(self, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves uptime of the device.
        """
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/system/status"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            self.online = True
            if command.json()["success"]:
                self.logit("status: success", command.text, logging, verbose_success)
                self.uptime = int(command.json()["result"]["upTime"])
            else:
                self.logit(self.padding("status:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            self.offline_check(e)
            self.logit(self.padding("status:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def switch_caps(self, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves number of switches and their basic settings.
        """
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/switch/caps?"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            self.online = True
            if command.json()["success"]:
                self.logit(self.padding("switch_caps:") + "success", command.text, logging, verbose_success)
                self.switches = []
                for sw in command.json()["result"]["switches"]:
                    self.switches.append(sw)
            else:
                self.logit(self.padding("switch_caps:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            self.offline_check(e)
            self.logit(self.padding("switch_caps:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def switch_ctrl(self, idx, action, hold_timeout=0, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Controls the device switch (get available switches using device.switches).
        Available actions:
        - on: switch it on (monostable for the configured duration)
        - off: switch it off (monostable - shorten the duration)
        - trigger: toggle the state of bistable switch, trigger monostable for the configured duration
        - lock: lock the switch (cannot be activated)
        - unlock: release the switch lock
        - hold: activate the switch indefinitely (or with defined hold_timeout)
        - release: release the switch hold
        """
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/switch/ctrl?"
                    + "switch=" + str(idx)
                    + "&action=" + action
                    + "&timeout=" + str(hold_timeout)
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            self.online = True
            if command.json()["success"]:
                self.logit(self.padding("switch_ctrl " + str(idx) + " " + action + ":") + "success", command.text, logging, verbose_success)
            else:
                self.logit(self.padding("switch_ctrl:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            self.offline_check(e)
            self.logit(self.padding("switch_ctrl:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def config(self, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves the configuration file.
        XML is returned in case of success.
        """
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/config"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            self.online = True
            if command.headers["content-type"] == "application/xml":
                self.logit(self.padding("config:") + "success", "XML received", logging, verbose_success)
            else:
                self.logit(self.padding("config:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return command.content
        except Exception as e:
            self.offline_check(e)
            self.logit(self.padding("config:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def upload_config(self, xml, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Uploads XML configuration file.
        """
        try:
            command = self.session.put(
                (
                    "https://"
                    + self.ip
                    + "/api/config"
                ),
                timeout=self.timeout,
                verify=False,
                headers={"Content-Type": "application/xml"},
                data=xml,
                auth=self.auth_id
            )

            if type(xml) != "bytes":
                self.logit(self.padding("upload_config:") + "data error", "Configuration must be in \"bytes\".", logging, verbose_failure)
                self.failure = "Configuration must be in \"bytes\"."
                return False
            elif command.json()["success"]:
                self.logit(self.padding("upload_config") + "success", command.text, logging, verbose_success)
            else:
                self.logit(self.padding("upload_config:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            self.offline_check(e)
            self.logit(self.padding("upload_config:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def restart(self, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Restarts the device.
        """
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/system/restart"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("restart:") + "success", command.text, logging, verbose_success)
            else:
                self.logit(self.padding("restart:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            self.offline_check(e)
            self.logit(self.padding("restart:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def caps(self, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves the capabilities of the device.
        """
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/system/caps"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("caps:") + "success", command.text, logging, verbose_success)
                self.capabilities = command.json()["result"]["options"]
            else:
                self.logit(self.padding("caps:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            self.offline_check(e)
            self.logit(self.padding("caps:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def get_time(self, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves the device time and its settings.
        Time and its settings are returned as a directory:
        "utcTime":   int
        "source":    string
        "automatic": bool
        """
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/system/time"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("get_time:") + "success", command.text, logging, verbose_success)
            else:
                self.logit(self.padding("get_time:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return command.json()["result"]
        except Exception as e:
            self.offline_check(e)
            self.logit(self.padding("get_time:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def set_time(self, time=None, automatic=None, server=None, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves the device time and its settings.
        Time and its settings are returned as a directory:
        "utcTime":   int
        "source":    string (URL)
        "automatic": int (0, 1)
        """
        payload = ""
        if time is not None:
            payload += "utcTime=" + str(time)
        if automatic is not None:
            if payload:
                payload += "&"
            payload += "automatic=" + str(automatic)
        if server is not None:
            if payload:
                payload += "&"
            payload += "server=" + str(server)
        try:
            if not payload:
                raise Exception("At least one parameter time, automatic or server is mandatory.")
            if (automatic == 1 and time is not None) or (self.get_time(False)["automatic"] and (automatic == 1 or automatic is None) and time is not None):
                raise Exception("Time mode is automatic. Switch it to manual before setting the time.")
            command = self.session.put(
                (
                    "https://"
                    + self.ip
                    + "/api/system/time?"
                    + payload
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id,
            )

            if command.json()["success"]:
                self.logit(self.padding("set_time:") + "success", command.text, logging, verbose_success)
            else:
                self.logit(self.padding("set_time:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            self.offline_check(e)
            self.logit(self.padding("set_time:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False
