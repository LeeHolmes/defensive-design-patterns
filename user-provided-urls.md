### Feature
Connecting to user-provided URLs.

Examples of features that commonly do this include:
- URL previews
- web hooks
- "upload from URL" implementations of file, avatar, or image uploads
- URL testers (performance, uptime, load testing, certificate validators, screen shotting)
- server-side processing of user-provided XML documents

### Risk
Service infrastructure used to connect to remote URLs can be tricked to connect to internal networks. This leads to a risk of [Server-Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery).

### Examples of Risk
- In 2019, an [attack against Capital One](https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af) leveraged a feature in an application that caused it to connect to user-provided URLs. The attacker tricked it into connecting to a special AWS URL that disclosed local secrets, keys, and identities assigned to that application. The attacker then used those to extend their breach much further.
- There are many examples of server-side request forgery in HackerOne bug reports. Here is an [insightful exmample](https://cuberk.com/blog/SSRF-vulnerability-in-Facebook-production-server-Exploit-Details/) where Facebook paid over $30,000 in bug bounties due to a chain of these bugs that allowed phishing, connecting to internal servers, and more.

### Addressing Risk
The OWASP project has a [great reference](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) on addressing server-side request forgery risks. Allow-listing a pattern of outbound URLs is always the prefered option if possible. When this is not possible, implementing a deny list can work. This is extremely difficult to get correct, but libraries that defend against server-side request forgery are available for many programming languages. A great example of how complex a deny-list implementation can be is [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md).

While server-side request forgery is often considered a security problem with the application that does it, an important aspect of the issue is also the service network architecture as well as the SSRF targets themselves. If network connectivity is not expected between the machine(s) making outbound connections and the rest of the infrastructure, services can protect themselves through more effective network segmentation. Additionally, all endpoints should implement authentication mechanisms that are not vulnerable to SSRF.

### Examples of Mitigations
Most companies that have any form of security program immediately recognize server-side request forgery to be a risk once pointed out. Mitigation is often accopmlished through (at least) the techniques explained above.

When it comes to protecting the targets of SSRF vulnerabilites (unauthenticated endpoints), any form of authentication is often sufficient - such as OAUTH, certificate-based authentication, or managed identities. Authentication is an important protection regardless, as otherwise these endpoints are also vulnerable to attackers who have network access or have compromised the application in other ways.

An endpoint running on the local system can often be more challenging. One example is AWS' Instance Metadata Service. The AWS Instance Metadata Service lets applications running on a host retrieve service-specific secrets and credentials. The instance metadata service listens on a well-known IP. Because of this, it is a popular target for SSRF vulnerabilities: tricking an application to display the output of an arbitrary GET request could result in displaying that application's credentials and secrets if pointed at the instance metadata service endpoint. AWS has [introduced a v2 version of this service](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/) to address this by adding authentication to the endpoint. When an application first starts up, it uses a POST request to negotiate a temporary secure key with the instance metadata service. After that, all GET requests to this service must authenticate using this key in a special header.

Similarly, Azure Arc implements a solution where calls to its instance metadata endpoint must be authenticated using a token that the requesting application [must separately retrieve from the filesystem](https://learn.microsoft.com/en-us/azure/azure-arc/servers/managed-identity-authentication).

### Discussion
A related risk to user-provided URLs is also known as "forced authentication" in corporate / on-premises environments. If your service or application can be forced to connect to another endpoint and will attempt to authenticate while doing so, the identity of the service or application can often be stolen. This can be trivially true with bearer tokens where all the authentication information is transmitted as a HTTP header, or more subtly true in cases where the authentication information can be forwarded or cracked such as [NTLM relay attacks](https://attack.mitre.org/techniques/T1187/). One example of a domain controller's print job notification API being abused to compromise the forest or domain can be found [here](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1).
