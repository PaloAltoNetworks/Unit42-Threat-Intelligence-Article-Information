# Appendix for "Lateral Movement on macOS: Unique and Popular Techniques and In-the-Wild Examples"

[Link to article](https://unit42.paloaltonetworks.com/)

## 1) Query to hunt for processes used to steal SSH Keys

This XQL query looks for various processes that an attacker might use to facilitate exfiltration of ssh keys:

```
dataset = xdr_data
| filter agent_os_type = ENUM.AGENT_OS_MAC
| filter event_type = ENUM.PROCESS
| filter action_process_image_name in ("cp","mv","ln","tar","zip","scp","rsync","curl","wget","base64","xxd","vim","vi","nano"
)
| filter action_process_image_command_line contains "id_rsa" or action_process_image_command_line contains "/.ssh"
)
```

The above query looks for any process involved in manipulating the `.ssh` directory and its contents by either copying, moving, archiving, encoding or uploading content in this directory.

## 2) XQL Query to hunt for using the kickstart command to enable remote management

```
[begin code]dataset = xdr_data
| filter agent_os_type = ENUM.AGENT_OS_MAC
| filter event_type = ENUM.PROCESS
| filter action_process_image_name = "perl"
| filter action_process_image_command_line contains "System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart" and action_process_image_command_line contains "-activate" and ((action_process_image_command_line contains "-allowAccessFor" and action_process_image_command_line contains "-allUsers") or (action_process_image_command_line contains "-privs" and action_process_image_command_line contains "-all"))[end code]
```

## 3) Query to look for the kickstart command 

```
[begin code]dataset = xdr_data
| filter agent_os_type = ENUM.AGENT_OS_MAC
| filter event_type = ENUM.PROCESS
| filter action_process_image_name = “kickstart”
)
| filter action_process_image_command_line contains "-activate" and action_process_image_command_line contains "-configure" and action_process_image_command_line contains "-allowAccessFor -allUsers" and action_process_image_command_line contains "-privs -all"[end code]
)
```
