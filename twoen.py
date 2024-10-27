import math

import icecream as ic
import requests
import urllib3
from requests.auth import HTTPDigestAuth


class Device:

    def __init__(self, ip: str, uname: str, pwd: str, timeout=5, assertion=False):
        """
        Creates an instance of a 2N OS device.
        """
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.session = requests.Session()
        self.assertion = not assertion

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
        self.phone_accounts = ["uninitialized"]
        self.phone_sessions = ["uninitialized"]

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

    def info_get(self, logging=True, verbose_success=False, verbose_failure=True) -> bool:
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
            self.logit(self.padding("info_get:") + "success", command.text, logging, verbose_success)
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("info_get:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def status_get(self, logging=True, verbose_success=False, verbose_failure=True) -> bool:
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
                self.logit("status_get: success", command.text, logging, verbose_success)
                self.uptime = int(command.json()["result"]["upTime"])
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("status_get:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("status_get:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def switches_get(self, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves number of switches, their states, operation mode and basic settings.
        swich - int, indicates number of the switch (indexed from 1, corresponds to the order in the list)
        enabled - bool, if the the switch is disabled, it cannot be used and controlled
        mode - string, monostable or bistable indicating the switch mode (None if the switch is disabled)
        switchOnDuration - int, number of seconds the switch is activated (None if the switch is disabled)
        type - string, normal, inverted, security (type of output control) (None if the switch is disabled)
        active - bool, switch state
        locked - bool, switch operation locked
        held - bool, switch operation held
        """
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/switch/caps"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            command2 = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/switch/status"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            self.online = True
            if command.json()["success"]:
                self.logit(self.padding("switches_get:") + "success", command.text + "|" + command2.text, logging, verbose_success)
                self.switches = []
                for sw_cap, sw_status in zip(command.json()["result"]["switches"], command2.json()["result"]["switches"]):
                    self.switches.append(sw_cap)
                    for key in sw_status.keys():
                        self.switches[-1][key] = sw_status[key]
                    for key in ["mode", "switchOnDuration", "type"]:
                        self.switches[-1][key] = self.switches[-1].get(key)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("switches_get:") + "api error", command.text + "|" + command2.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("switches_get:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def switches_set(self, idx, action, hold_timeout=0, logging=True, verbose_success=False, verbose_failure=True) -> bool:
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
                self.logit(self.padding("switches_set " + str(idx) + " " + action + ":") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("switches_set:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("switches_set:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def config_download(self, logging=True, verbose_success=False, verbose_failure=True) -> bool:
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
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("config:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return command.content
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("config:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def config_upload(self, xml, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Uploads XML configuration file.
        """
        if type(xml) is not bytes:
            if not self.assertion:
                raise Exception("assetion is enabled and the script failed with api error: Configuration must be in \"bytes\".")
            self.logit(self.padding("upload_config:") + "data error", "Configuration must be in \"bytes\".", logging, verbose_failure)
            self.failure = "Configuration must be in \"bytes\"."
            return False
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

            if command.json()["success"]:
                self.logit(self.padding("upload_config") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("upload_config:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
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
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("restart:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("restart:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def caps_get(self, logging=True, verbose_success=False, verbose_failure=True) -> bool:
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
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("caps:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("caps:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def time_get(self, logging=True, verbose_success=False, verbose_failure=True) -> bool:
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
                self.logit(self.padding("time_get:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("time_get:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return command.json()["result"]
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("time_get:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def time_set(self, time=None, automatic=None, server=None, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Sets the device time and its settings.
        Time and its settings are entered as URL params:
        utcTime=int
        source=string (URL)
        automatic=int (0, 1)
        At least one parameter is mandatory.
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
            if (automatic == 1 and time is not None) or (self.time_get(False)["automatic"] and (automatic == 1 or automatic is None) and time is not None):
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
                self.logit(self.padding("time_set:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("time_set:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("time_set:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def timezone_caps_get(self, logging=True, verbose_success=False, verbose_failure=True) -> list:
        """
        Retrieves the device's list of supported standard timezones. A list is returned.
        """
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/system/timezone/caps"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("timezone_caps_get:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("timezone_caps_get:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return command.json()["result"]["timezones"]
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("timezone_caps_get:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def timezone_get(self, logging=True, verbose_success=False, verbose_failure=True) -> dict:
        """
        Retrieves the device's timezone settings.
        "automatic": boolean
        "zone": string
        "custom": string (None if the zone is not custom)
        """
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/system/timezone"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("timezone_get:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("timezone_get:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            tz_dataset = command.json()["result"]
            tz_dataset["custom"] = tz_dataset.get("custom")
            return tz_dataset
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("timezone_get:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def timezone_set(self, automatic=1, zone=None, custom=None, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Sets the device timezone and its settings.
        Timezone and its settings are entered as URL params:
        automatic=int (0, 1)
        zone=string (zone name, use timezone_caps_get for the list of names)
        custom=string (definition string of custom timezone, e.g., UTC0)
        Call the method without any parameters to set the automatic timezone mode.
        Call the method with zone (and custom) parameter to set manual timezone (timezone mode is automatically se to Manual, regardless of the automatic parameter)
        """
        payload = ""
        if zone is None:
            payload += "automatic=" + str(automatic)
        elif zone != "custom":
            payload += "automatic=0&zone=" + zone
        else:
            payload += "automatic=0&zone=" + zone + "&custom=" + custom

        try:
            if (zone != "custom" and custom is not None):
                raise Exception("To configure custom rule the timezone needs to be set to \"custom\".")
            if (zone == "custom" and custom is None):
                raise Exception("Custom rule needs to be defined when the timezone is set to \"custom\".")
            command = self.session.put(
                (
                    "https://"
                    + self.ip
                    + "/api/system/timezone?"
                    + payload
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id,
            )

            if command.json()["success"]:
                self.logit(self.padding("timezone_set:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("timezone_set:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("timezone_set:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def firmware_upload(self, fw, direct=True, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Uploads firmware binary file. Use direct to apply the firmware immediately (by default True).
        If direct=False => fwid, version, downgrade and upgrade warning is returned in a dict for individual handling.
        fwid - identifier of the version used for confirmation or rejection
        version - version number read from the file header
        downgrade - bool informing on whether the device will be downgraded
        note - upgrade warning text for user's consideration

        Timeout for this operation is modified to self.timeout + 120.

        The uploaded firmware is stored and can be confirmed for 30 s after the upload.
        """
        if type(fw) is not bytes:
            if not self.assertion:
                raise Exception("assetion is enabled and the script failed with api error: Firmware must be in \"bytes\".")
            self.logit(self.padding("firmware_upload:") + "data error", "Firmware must be in \"bytes\".", logging, verbose_failure)
            self.failure = "Firmware must be in \"bytes\"."
            return False
        try:
            command = self.session.put(
                (
                    "https://"
                    + self.ip
                    + "/api/firmware"
                ),
                timeout=self.timeout + 120,
                verify=False,
                headers={"Content-Type": "application/octet-stream"},
                data=fw,
                auth=self.auth_id
            )

            if command.json()["success"]:
                self.logit(self.padding("firmware_upload:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("firmware_upload:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            version_info = dict()
            version_info["fwid"] = command.json()["result"]["fileId"]
            version_info["version"] = command.json()["result"]["version"]
            version_info["downgrade"] = command.json()["result"]["downgrade"]
            version_info["note"] = command.json()["result"]["note"]

            if not direct:
                return version_info
            self.logit("firmware will be confirmed automatically (direct=True)")
            self.firmware_confirm(version_info["fwid"])
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("firmware_upload:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def firmware_confirm(self, fwid, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Confirms uploaded firmware file with fwid to be applied to the device.
        """
        try:
            command = self.session.post(
                (
                    "https://"
                    + self.ip
                    + "/api/firmware/apply?fileid="
                    + fwid
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )
            if command.json()["success"]:
                self.logit(self.padding("firmware_confirm:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("firmware_confirm:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("firmware_confirm:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def firmware_reject(self, fwid, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Rejects uploaded firmware file with fwid - another firmware file can be uploaded immediately.
        """
        try:
            command = self.session.post(
                (
                    "https://"
                    + self.ip
                    + "/api/firmware/reject?fileid="
                    + fwid
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )
            if command.json()["success"]:
                self.logit(self.padding("firmware_reject:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("firmware_reject:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("firmware_reject:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def factory_reset(self, sections=None, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Reset the device to the factory default configuration.
        Using parameter sections=network all network parameters will be also reset. If the parameter is not specified, network parameters are not reset.
        """
        params = ""
        if sections == "network":
            params = "?sections=network"
        try:
            command = self.session.post(
                (
                    "https://"
                    + self.ip
                    + "/api/config/factoryreset"
                    + params
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )
            if command.json()["success"]:
                self.logit(self.padding("factory_reset:") + "success", command.text, logging, verbose_success)
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("factory_reset:") + "api error", command.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("factory_reset:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False

    def phone_get(self, logging=True, verbose_success=False, verbose_failure=True) -> bool:
        """
        Retrieves status of SIP accounts and their calls (if there are any).
        List of accounts is populated. List of sessions is populated. Get them from the Device object.
        It is not possible to pair sessions with their respective accounts at the moment.

        phone_accounts is a list and contains a dict for each account with the following keys:
        - account (account ID indexed from 1)
        - accountType (string: general, local, msteams)
        - answerMode (int according to enum)
        - authId (string)
        - displayName (string)
        - domain (string)
        - domainPort (int, 0 means default port for individual SIP accounts)
        - enabled (bool)
        - proxyAddress (string)
        - proxyPort (int, 0 means default port for individual SIP accounts)
        - sipNumber (SIP URL, string)
        - registrationEnabled (bool)
        - registered (bool)
        - registerTime (int or None when the account is not registred)
        - registrarAddress (string)
        - registrarPort (int, 0 means default port for individual SIP accounts)

        phone_sessions is a list and contains a dict for each session (call) with the following keys:
        - calls (list of individual calls in a session, contains id (int), call type identifier, SIP URL and call state)
        - session (session ID indexed from 1)
        - direction (string: incoming or outgoing)
        - state (string: connecting, ringing, connected)
        Currently, there can be only one session in 2N OS devices. The list is empty if there is no session.
        """
        try:
            command = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/phone/status"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            command2 = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/call/status"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            command3 = self.session.get(
                (
                    "https://"
                    + self.ip
                    + "/api/phone/config"
                ),
                timeout=self.timeout,
                verify=False,
                auth=self.auth_id
            )

            self.online = True
            if command.json()["success"] and command2.json()["success"] and command3.json()["success"]:
                self.logit(self.padding("phone_get:") + "success", command.text + "|" + command2.text + "|" + command3.text, logging, verbose_success)
                self.phone_sessions = command2.json()["result"]["sessions"]
                self.phone_accounts = []
                for ph_status, ph_config in zip(command.json()["result"]["accounts"], command3.json()["result"]["accounts"]):
                    self.phone_accounts.append(ph_status)
                    for key in ph_config.keys():
                        self.phone_accounts[-1][key] = ph_config[key]
                for account in self.phone_accounts:
                    account["registerTime"] = account.get("registerTime")
            else:
                if not self.assertion:
                    raise Exception(f"assetion is enabled and the script failed with api error: {command.text}")
                self.logit(self.padding("phone_get:") + "api error", command.text + "|" + command2.text, logging, verbose_failure)
                self.failure = command.text
                return False
            self.failure = None
            return True
        except Exception as e:
            assert self.assertion, f"assetion is enabled and the script failed with general failure: {e}"
            self.offline_check(e)
            self.logit(self.padding("phone_get:") + "general failure", e, logging, verbose_failure)
            self.failure = e
            return False
