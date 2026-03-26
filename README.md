# ETW-PPL-Tester

A simple tool for exploring [Microsoft-Windows-Threat-Intelligence](https://github.com/jdu2600/Windows10EtwEvents/blob/main/manifest/Microsoft-Windows-Threat-Intelligence.tsv) (ETW-TI) events.

Note - some ETW-TI events must be additionally [enabled on a per-process basis](https://github.com/winsiderss/systeminformer/blob/8030be9396047dfa04ca77cec52c0c9c95c1e5dc/phnt/include/ntpsapi.h#L1618-L1640).

## Requirements

- Windows 10+
- Administrator privileges
- Visual Studio 2022

## Background

The ETW-TI provider can only be subscribed to by [Antimalware-PPL](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-) processes. This protection level is intended for security products, and is typically granted to services associated with [Early Launch AntiMalware](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/early-launch-antimalware) (ELAM) drivers.

Pat H demonstrated two approaches to consuming ETW-TI -
 * [Gaining Threat-Intelligence the dodgy way](https://blog.tofile.dev/2021/05/12/sealighterti.html) - admin-to-PPL exploitation
 * [Gaining Threat-Intelligence the REALLY dodgy way](https://blog.tofile.dev/2022/11/30/kdu_sealighter.html) - Bring Your Own Vulnerable Driver (BYOVD)

This project was originally a slightly more ergnomic version of Pat's BYOVD approach that I used to submit a bug report poc to Microsoft.

The second version updated to a [BYOD](https://github.com/jbaines-r7/dellicious) approach using a driver that is **not eligible** for Microsoft's [vulnerable driver blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules). The nuance is that [MSRC](https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria) only considers **user**-to-kernel LPE as "vulnerabilities". If a driver allows **admin**-to-kernel LPE this is acceptable for submission for [Windows Hardware Quality Labs](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs) (WHQL) signing.  Admin-to-kernel is not a security boundary - it is "by design".

## Further Reading
 * [Forget vulnerable drivers - Admin is all you need](https://www.elastic.co/security-labs/forget-vulnerable-drivers-admin-is-all-you-need) by Gabriel Landau

