# Unofficial Python Module for 2N Devices

Intercoms and Access Units Running 2N OS (https://www.2n.cz)

The module is under construction. Please be kind since it is developed by mygranny (in Czech: mojebabicka).

## Jumpstart

Import the module.

The module requirements:

* math
* icecream
* requests
* urllib3

The module defines the Class Device, which you can use to instantiate devices (provide IP address, username, and password). Remember to set up an HTTP account with appropriate privileges in the device configuration. Requests always include Digest authentication. Please keep in mind that you need to set up an HTTP API account even when you switch Services in the device to None authentication (because authentication is always used in this module).

Use the device instance to call its methods. Typically, one method corresponds to one endpoint (or to one method of an endpoint). The device also provides data directly (e.g., switches' states). Many of these are not initialized at first, and an appropriate method needs to be called first. The appropriate method needs to be called again to update these states.

The module logs quite extensively to the command line using the Icecream module. The logging can be completely disabled, and you can select the verbosity of the logging for success and failure (verbose logging also contains additional information — usually an error message provided in the response).

Methods typically return a boolean indicating the operation's success. In some cases, response data (XML, image, etc.) are returned directly when the operation is successful. When an operation fails, you can retrieve the details in the device.failure object, which lets you handle the problem in a preferred way.

Get more information on the HTTP API of devices running 2N OS: https://wiki.2n.com/hip/hapi/latest/en

## Example Script

        import twoen

        # Initialize a Device instance (optional: get info, uptime, switch config and capabilities)
        device = twoen.Device("192.168.1.1", "admin", "BadPwd123")
        device.info()
        device.switch_caps()
        device.caps()

        # Read config and write it into a file
        with open("test_config.xml", "wb") as f:
            f.write(device.config())

        # Activate switch one
        device.switch_ctrl(1, "on")

By default the script will log the following data in command line:

        ic| func: 'info:...........................success'
        ic| func: 'switch_caps:....................success'
        ic| func: 'caps:...........................success'
        ic| func: 'config:.........................success'
        ic| func: 'switch_ctrl 1 on:...............success'
