### Feature
Software update mechanism

### Risk
Source of software updates tampered with or replaced

### Examples of Risk
- In June of 2017, the NotPetya espionage campaign was started via a malicious update to the MeDoc accounting software distributed by a compromised update server. See: [2017 Ukraine ransomware attacks](https://en.wikipedia.org/wiki/2017_Ukraine_ransomware_attacks). [The Consequences of Insecure Software Updates](https://insights.sei.cmu.edu/blog/the-consequences-of-insecure-software-updates/).
- From 2019 to 2023, eScan antivirus delivered updates insecurely. Attackers used sophisticated techniques to intercept this update traffic and deliver crypto mining malware as well. See: [Hackers infect users of antivirus service that delivered updates over HTTP](https://arstechnica.com/security/2024/04/hackers-infect-users-of-antivirus-service-that-delivered-updates-over-http/).

### Addressing Risk
To address this risk, software update clients must independently verify the authenticity of software update packages. This is commonly done by validating a digital signature of the update package. The client is then configured to validate the digital signature and only trust updates signed by a specific signer.

### Examples of Mitigations
- Windows Update presumes that the entire software distribution channel is insecure and digitally signs all updates. See: [Windows Update Security](https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-security).
- "The Update Framework" provides a reusable implementation of a secure update mechanism. See: [The Update Framework](https://theupdateframework.io/).

### Discussion
Software update mechanisms can be made more secure by considering the security of all paths along the distribution channel. For example, by following secure operational best practices in the distibution service and distributing content from immutable storage that can't be changed once written. However, the strongest protection is to have the client validate the authenticitity of the content itself. This eliminates almost all of the distribution infrastructure from the risks that need to be considered.

One common mistake updaters make is to transmit the authenticity information (such as a file hash) along with the file itself. This rarely mitigates the risk, as an attacker with access to the distribution channel can likely tamper with both the content and the file hash metadata.

If an updater relies on digital signing to prevent tamper protection, the key risk to the system becomes protection of the keys used to digitally sign the content. A good example of this is the 2020 SolarWinds breach, where both its update distribution mechanism and code signing mechanism were compromised. While the SolarWinds updater validated digital signatures, the attacker was also able to digitally sign the malicious content. See: [The SolarWinds cyberattack: The hack, the victims, and what we know](https://www.bleepingcomputer.com/news/security/the-solarwinds-cyberattack-the-hack-the-victims-and-what-we-know/).
