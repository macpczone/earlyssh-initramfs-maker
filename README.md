﻿### Early SSH Initramfs Maker

This repo contains a script that can make an initramfs, which can be used to boot up a LUKS encrypted hard drive, with only a network connection. I spent a bit of time looking for a solution to boot a Centos 6 server that I am using, while having the main drive encrypted on a headless box. I found some solutions that added a module to dracut, but they involved replacing the console cryptsetup password prompt with an ssh only version. This is a bit inconvenient because I will sometimes want to attach a keyboard and monitor to this server, so I decided to create my own version without dracut, that allows the password to both be entered from the console and from the ssh connection as well.

This initramfs only works if you already have the drivers for your root filesystem compiled into the kernel, so it is only really for use on your final hardware. It should also work on any GNU based OS, since the standard initramfs is not used.
