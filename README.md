# accountServerConnector

Get PTC accounts from external accounts server - intended for use with [pogoAccountServer](https://github.com/crhbetz/pogoAccountServer).
A device will fetch a PTC account from the server upon every PTC login. The recommended pogoAccountServer decides which account to serve, detailed in the README there.

# Replacing MAD AccountHandler

The plugin will replace MADs builtin account handler as far as possible. The goal is to eventually also support burn-types etc in here, but as of right now, the plugin will still cycle through all accounts regardless if MAD identified they had another type of ban (red screens, etc.).

**Weird behaviour of MADmin is to be expected. In case of problems, do what it wants you to do (maybe add a dummy account to a device) - only accounts from AccountServer will be used!**

# Setup

* upload .mp file from releases to MADmin if an up-to-date one is available, or clone the repo into `MAD/plugins/accountServerConnector` (leave out the `mp-` part of the directory - yes,
this is annoying :-) )
* `cp plugin.ini.example plugin.ini` and configure the `plugin.ini` according to your setup
* restart MAD
