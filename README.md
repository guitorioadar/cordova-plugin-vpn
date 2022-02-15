cordova-plugin-vpn
======================
`version 0.0.1`

This package is forked from [cordova-plugin-vpn](https://github.com/aquto/cordova-plugin-vpn)

We have updated this plugin with the latest version of the strongswan VPN plugin. This plugin is only use `IKEV2 for android and iOS`.

## Basic Setup

Navigate to your project's root directory and run the following command:

```javascript
cordova plugin add https://github.com/guitorioadar/cordova-plugin-vpn.git --variable ALLOWWIFI=true
```

>You can access the plugin using `window.plugins.VPNManager` this keyword



IOS
---

* Enable Network Extension capability in your iOS platform

Go to `Target`-> + `Capabilities`-> Search for `Network Extension` -> Select `Packet Tunnel`


Android
-------


* Enable androidx in your Android platform
* add `<preference name="AndroidXEnabled" value="true" />` in `config.xml` file inside your root cordova project

```xml
<platform name="android">
    <allow-intent href="market:*" />
    <preference name="AndroidXEnabled" value="true" />
</platform>
```

Usage
-----


This plugin provides functionality with 3 methods for now;
- enable
- disable
- registerCallback

### enable
This method will enable the vpn connection.
```javascript
window.plugins.VPNManager.enable(<successCallback>, <errorCallback>, <options>);
```
##### bewlow fields are mandatory for platforms that support
```javascript
if(device.platform == "Android"){   // device is from cordova-plugin-device plugin
        options = {
            "vpnUsername": "user_name", // guitorioadar
            "vpnPassword": "user_password", // password
            "vpnHost": "vpn_host_name", // 0.0.0.0 or vpn.example.com
            "caCertificate": "base64_formate_of_your_ca_certificate", // caCertificate
            "caCertificateCompanyName": "ca_certificate_company_name" // caCertificateCompanyName
        }
    }else { // iOS
        options = {
            "vpnPassword": "user_password", // password
            "vpnHost": "vpn_host_name", // 0.0.0.0 or vpn.example.com
            "appName": "App App" // To add the vpn profile
        }
    }
    window.plugins.VPNManager.enable(
        function(result) {
            // alert(result)
			console.log('AppLog JS connected');
        },
        function(error){
            // alert(error)
            console.log(error);
        },
        options
    );
```

### disable
This method will disable the vpn connection.

```javascript
window.plugins.VPNManager.disable(<successCallback>, <errorCallback>, <options>);
```

```javascript
window.plugins.VPNManager.disable(
        function(result) {
			console.log(result);
        },
        function(error){
            console.log(error);
        },
        {}
    );
```
### registerCallback
This method will listent the status of vpn connection.
```javascript
window.plugins.VPNManager.registerCallback(<successCallback>, <errorCallback>, <options>);
```

Example
```javascript
 // VPN Status
    window.plugins.VPNManager.registerCallback(
        function(status) {
            console.log("VPN Status "+status);
        },
        function(error){
            console.log("VPN Status error: "+error);
        },
        {}
    );
```


--------------------------------------------------------------------------------
The below methods are not maintained in cordova-plugin-vpn.
##### Exposes 5 methods: (android only)

+ isVpnCapable: returns true if this device is capable of establishing a vpn connection, else false
+ isUp: return true if vpn connection is active, else false
+ listen: register listeners for state and error state updates
    + possible states: DISABLED, CONNECTING, CONNECTED, DISCONNECTING
    + possible error states: NO\_ERROR, AUTH\_FAILED, PEER\_AUTH\_FAILED, LOOKUP\_FAILED, UNREACHABLE, GENERIC\_ERROR, DISALLOWED\_NETWORK\_TYPE
+ enable: establish a new VPN connection using the provided provisioning json. Will return an error if wifi/wimax/ethernet connection is active, and will shutdown the VPN if a connection with one of those types becomes active
+ disable: terminate the currently active VPN connection

note: return in this context means calling the provided success callback function. Returning an error means calling the provided error callback function

Error codes used when calling the error callback function:

+ NOT/_SUPPORTED,
+ MISSING/_FIELDS,
+ UNKNOWN/_ERROR,
+ PERMISSION/_NOT/_GRANTED,
+ DISALLOWED/_NETWORK/_TYPE

Edit this configuration file to enable or disable mobileOnly (disallow VPN connection while connected to wifi, wimax or ethernet) and to set the vpn name as shown by the VPN system dialog.
src/android/vpn_plugin_config.xml
