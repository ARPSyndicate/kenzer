# KENZER | Automated web assets enumeration & scanning

## Demo

[![kenzer](screenshots/yt-thumbnail.png)](https://www.youtube.com/watch?v=pD0IRloikz8)

## Screenshots

![kenzer](screenshots/kenzer0.png)
![kenzer](screenshots/kenzer1.png)

## Instructions for running

1. Create an account on [Zulip](https://zulipchat.com)<br>
2. Navigate to `Settings > Your Bots > Add a new bot`<br>
3. Create a new generic bot named `kenzer`<br>
4. Add all the configurations in `configs/kenzer.conf`<br>
5. Install/Run using - <br>
   - `./install.sh -b` [if you need `kenzer-compatible` binaries to be installed]<br>
   - `./install.sh` [if you do not need `kenzer-compatible` binaries to be installed]<br>
   - `./run.sh` [if you do not need installation at all]<br>
   - `./service.sh` [initialize it as a service post-installation] **(preferred)**<br>
   - `bash swap.sh` [in case you are facing memory issues]
6. Interact with `kenzer` using Zulip client, by adding bot to a stream or via DM.<br>
7. Test `@**kenzer** man` as Zulip input to display available commands.<br>
8. All the commands can be used by mentioning the chatbot using the prefix `@**kenzer**`.<br>

## Built-in Modules

> - `ignorenum` - initializes & removes out of scope targets
> - `subenum` - enumerates subdomains
> - `repenum` - enumerates reputation of subdomains
> - `portenum` - enumerates open ports
> - `servenum` - enumerates services
> - `webenum` - enumerates webservers
> - `headenum` - enumerates additional info from webservers
> - `urlheadenum` - enumerates additional info from urls
> - `asnenum` - enumerates asn records
> - `dnsenum` - enumerates dns records
> - `conenum` - enumerates hidden files & directories
> - `urlenum` - enumerates urls
> - `socenum` - enumerates social media accounts
> - `subscan` - hunts for subdomain takeovers
> - `cscan[-[critical|high|medium|low|info|[custom]]]` - scan with customized templates
> - `cvescan[-[critical|high|medium|low|info|[custom]]]` - hunts for CVEs
> - `vulnscan[-[critical|high|medium|low|info|[custom]]]` - hunts for other common vulnerabilites
> - `urlcvescan[-[critical|high|medium|low|info|[custom]]]` - hunts for CVEs in URLs
> - `urlvulnscan[-[critical|high|medium|low|info|[custom]]]` - hunts for other common vulnerabilites in URLs
> - `portscan` - scans open ports
> - `endscan[-[critical|high|medium|low|info|[custom]]]` - hunts for vulnerablities in custom endpoints
> - `buckscan` - hunts for unreferenced aws s3 buckets
> - `favscan` - fingerprints webservers using favicon
> - `vizscan` - screenshots applications running on webservers
> - `idscan[-[critical|high|medium|low|info|[custom]]]` - identifies applications running on webservers
> - `enum` - runs all enumerator modules
> - `scan` - runs all scanner modules
> - `recon` - runs all modules
> - `hunt` - runs your custom workflow
> - `upload` - switches upload functionality
> - `upgrade` - upgrades kenzer to latest version
> - `monitor` - monitors ct logs for new subdomains
> - `monitor normalize` - normalizes the enumerations from ct logs
> - `monitor db` - monitors ct logs for kenzerdb's targets.txt
> - `sync` - synchronizes the local kenzerdb with github
> - `kenzer <module>` - runs a specific modules
> - `kenzer man` - shows this manual

## The Beginner's Workflow

![workflow](screenshots/workflow.png)

Although few more modules are available & much more is going to be released in the course of time which can advance this workflow, yet this one is enough to get started with & listed below are few of its successful hunts.<br><br>
<img src="screenshots/adobe.png" width="200" height="60">
<img src="screenshots/ibm.png" width="150" height="60">
<img src="screenshots/amazon.png" width="150" height="50">
<img src="screenshots/algolia.png" width="250" height="60">

**COMPATIBILITY TESTED ON DEBIAN(x64) ONLY**<br>
**FEEL FREE TO SUBMIT PULL REQUESTS**
