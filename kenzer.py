# imports
import zulip
import time
from datetime import datetime
import os
import sys
from chatterbot import ChatBot
from chatterbot.trainers import ChatterBotCorpusTrainer
from configparser import ConfigParser
import validators
import tldextract
import ipaddress

# core modules
from modules import enumerator
from modules import scanner
from modules import monitor

# colors
BLUE = '\033[94m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CLEAR = '\x1b[0m'

# configs
try:
    conf = "configs/kenzer.conf"
    config = ConfigParser()
    with open(conf) as f:
        config.read_file(f, conf)
    _BotMail = config.get("kenzer", "email")
    _Site = config.get("kenzer", "site")
    _APIKey = config.get("kenzer", "key")
    _uploads = config.get("kenzer", "uploads")
    _subscribe = config.get("kenzer", "subscribe")
    _kenzer = config.get("kenzer", "path")
    _logging = config.get("kenzer", "logging")
    _splitting = config.get("kenzer", "splitting")
    _kenzerdb = config.get("kenzerdb", "path")
    _github = config.get("kenzerdb", "token")
    _repo = config.get("kenzerdb", "repo")
    _user = config.get("kenzerdb", "user")
    _home = config.get("env", "home")
    _greynoise = config.get("env", "greynoise")
    os.chdir(_kenzer)
    os.environ["HOME"] = _home
    if(os.path.exists(_kenzerdb) == False):
        os.system("mkdir "+_kenzerdb)
except:
    sys.exit(RED+"[!] invalid configurations"+CLEAR)

# kenzer


class Kenzer(object):

    # initializations
    def __init__(self):
        print(BLUE+"KENZER[3.25] by ARPSyndicate"+CLEAR)
        print(YELLOW+"automated web assets enumeration & scanning"+CLEAR)
        self.client = zulip.Client(email=_BotMail, site=_Site, api_key=_APIKey)
        self.upload = False
        if _subscribe == "True":
            self.subscribe()
            print(YELLOW+"[*] subscribed all streams"+CLEAR)
        if _uploads == "True":
            self.upload = True
            print(YELLOW+"[*] enabled uploads"+CLEAR)
        print(YELLOW+"[*] training chatterbot"+CLEAR)
        self.chatbot = ChatBot("Kenzer")
        self.trainer = ChatterBotCorpusTrainer(self.chatbot)
        time.sleep(3)
        self.trainer.train("chatterbot.corpus.english")
        time.sleep(3)
        self.modules = ["monitor", "ignorenum", "subenum", "repenum", "webenum", "servenum", "urlheadenum", "headenum", "socenum", "conenum", "dnsenum", "portenum", "asnenum", "urlenum", "favscan",
                        "cscan", "idscan", "subscan", "cvescan", "vulnscan", "portscan", "urlcvescan", "urlvulnscan", "endscan", "buckscan", "vizscan", "enum", "scan", "recon", "hunt", "sync"]
        print(YELLOW+"[*] KENZER is online"+CLEAR)
        print(
            YELLOW+"[*] {0} modules up & running".format(len(self.modules))+CLEAR)

    # subscribes to all streams
    def subscribe(self):
        try:
            json = self.client.get_streams()["streams"]
            streams = [{"name": stream["name"]} for stream in json]
            self.client.add_subscriptions(streams)
        except:
            print(RED+"[!] an exception occurred.... retrying...."+CLEAR)
            self.subscribe()

    # manual
    def man(self):
        message = "**KENZER[3.25]**\n"
        message += "**KENZER modules**\n"
        message += "  `ignorenum` - initializes & removes out of scope targets\n"
        message += "  `subenum` - enumerates subdomains\n"
        message += "  `repenum` - enumerates reputation of subdomains\n"
        message += "  `portenum` - enumerates open ports\n"
        message += "  `servenum` - enumerates services\n"
        message += "  `webenum` - enumerates webservers\n"
        message += "  `headenum` - enumerates additional info from webservers\n"
        message += "  `urlheadenum` - enumerates additional info from urls\n"
        message += "  `conenum` - enumerates hidden files & directories\n"
        message += "  `dnsenum` - enumerates dns records\n"
        message += "  `asnenum` - enumerates asn records\n"
        message += "  `urlenum` - enumerates urls\n"
        message += "  `subscan` - hunts for subdomain takeovers\n"
        message += "  `socenum` - enumerates social media accounts\n"
        message += "  `cscan[-[critical|high|medium|low|info|[custom]]]` - scan with customized templates\n"
        message += "  `cvescan[-[critical|high|medium|low|info|[custom]]]` - hunts for CVEs\n"
        message += "  `vulnscan[-[critical|high|medium|low|info|[custom]]]` - hunts for other common vulnerabilites\n"
        message += "  `urlcvescan[-[critical|high|medium|low|info|[custom]]]` - hunts for CVEs in urls\n"
        message += "  `urlvulnscan[-[critical|high|medium|low|info|[custom]]]` - hunts for other common vulnerabilitesin urls\n"
        message += "  `portscan` - scans open ports\n"
        message += "  `endscan[-[critical|high|medium|low|info|[custom]]]` - hunts for vulnerablities in custom endpoints\n"
        message += "  `buckscan` - hunts for unreferenced aws s3 buckets\n"
        message += "  `favscan` - fingerprints webservers using favicon\n"
        message += "  `idscan[-[critical|high|medium|low|info|[custom]]]` - identifies applications running on webservers\n"
        message += "  `vizscan` - screenshots applications running on webservers\n"
        message += "  `enum` - runs all enumerator modules\n"
        message += "  `scan` - runs all scanner modules\n"
        message += "  `recon` - runs all modules\n"
        message += "  `hunt` - runs your custom workflow\n"
        message += "  `upload` - switches upload functionality\n"
        message += "  `sync` - synchronizes the local kenzerdb with github\n"
        message += "  `upgrade` - upgrades kenzer to latest version\n"
        message += "  `monitor` - monitors ct logs for new subdomains\n"
        message += "  `monitor normalize` - normalizes the enumerations from ct logs\n"
        message += "  `monitor db` - monitors ct logs for kenzerdb's targets.txt\n"
        message += "`kenzer <module>` - runs a specific modules\n"
        message += "`kenzer man` - shows this manual\n"
        message += "or you can just interact with chatterbot\n"
        self.sendMessage(message)
        return

    # sends messages
    def sendMessage(self, message):
        time.sleep(2)
        if self.type == "private":
            self.client.send_message({
                "type": self.type,
                "to": self.sender_email,
                "content": message
            })
        else:
            self.client.send_message({
                "type": self.type,
                "subject": self.subject,
                "to": self.display_recipient,
                "content": message
            })
        time.sleep(3)
        return

    # uploads output
    def uploader(self, domain, raw):
        global _kenzerdb
        global _Site
        org = domain
        data = _kenzerdb+org+"/"+raw
        if(os.path.exists(data) == False):
            return
        with open(data, 'rb') as fp:
            uploaded = self.client.call_endpoint(
                'user_uploads',
                method='POST',
                files=[fp],
            )
        self.sendMessage("{0}/{1} : {3}{2}".format(org,
                                                   raw, uploaded['uri'], _Site))
        return

    # removes log files
    def remlog(self, cont):
        dtype = False
        if validators.domain(cont.lower()) == True or cont.lower() == "monitor":
            dtype = True
        else:
            try:
                ipaddress.ip_network(cont)
            except ValueError:
                return
        self.enum = enumerator.Enumerator(
            cont.lower(), _kenzerdb, _kenzer, dtype)
        message = self.enum.remlog()
        return

    # splits .kenz files
    def splitkenz(self, cont):
        dtype = False
        if validators.domain(cont.lower()) == True or cont.lower() == "monitor":
            dtype = True
        else:
            try:
                ipaddress.ip_network(cont)
            except ValueError:
                return
        self.enum = enumerator.Enumerator(
            cont.lower(), _kenzerdb, _kenzer, dtype)
        message = self.enum.splitkenz()
        return

    # merges .kenz files
    def mergekenz(self, cont):
        dtype = False
        if validators.domain(cont.lower()) == True or cont.lower() == "monitor":
            dtype = True
        else:
            try:
                ipaddress.ip_network(cont)
            except ValueError:
                return
        self.enum = enumerator.Enumerator(
            cont.lower(), _kenzerdb, _kenzer, dtype)
        message = self.enum.mergekenz()
        return

    # monitors ct logs
    def monitor(self):
        self.sendMessage("[monitoring - #({0})]".format(len(self.content)-2))
        self.monitor = monitor.Monitor(_kenzerdb, " ".join(self.content[2:]))
        self.monitor.certex()
        return

    # monitors ct logs for kenzerdb's targets.txt
    def monitor_kenzerdb(self):
        domfile = _kenzerdb+"../targets.txt"
        with open(domfile) as f:
            line = len(f.readlines())
        self.sendMessage("[monitoring - #({0})]".format(line))
        self.monitor = monitor.Monitor(_kenzerdb)
        self.monitor.certex()
        return

    # normalizes enumerations from ct logs
    def normalize(self):
        self.monitor = monitor.Monitor(_kenzerdb, " ".join(self.content[2:]))
        self.monitor.normalize()
        self.sendMessage("[normalized - #({0})]".format(len(self.content)-2))
        return

    # initializes & removes out of scope targets
    def ignorenum(self):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            extracted = tldextract.extract(self.content[i].lower())
            domain = "{}.{}".format(extracted.domain, extracted.suffix)
            self.sendMessage(
                "[ignorenum - #({0}/{1})] {2}".format(i-1, len(self.content)-2, domain))
            self.enum = enumerator.Enumerator(
                domain, _kenzerdb, _kenzer, dtype)
            message = self.enum.ignorenum(self.content[i].lower())
            self.sendMessage(
                "[ignorenum - #({0}/{1}) - {2}] {3}".format(i-1, len(self.content)-2, message, domain))
            if self.upload:
                file = "ignorenum.kenz"
                self.uploader(self.content[i], file)
        return

    # enumerates subdomains
    def subenum(self):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage(
                "[subenum - #({0}/{1})] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.subenum()
            self.sendMessage("[subenum - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower()))
            if self.upload:
                file = "subenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # probes services from enumerated ports
    def servenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[servenum - #({0}/{1})] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.servenum()
            self.sendMessage("[servenum - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower()))
            if self.upload:
                file = "servenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # probes web servers from enumerated ports
    def webenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[webenum - #({0}/{1})] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.webenum()
            self.sendMessage("[webenum - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower()))
            if self.upload:
                file = "webenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates additional info from webservers
    def headenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[headenum - #({0}/{1})] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.headenum()
            self.sendMessage("[headenum - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower()))
            if self.upload:
                file = "headenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates additional info from urls
    def urlheadenum(self):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage("[urlheadenum - #({0}/{1})] {2}".format(
                i-1, len(self.content)-2, self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.urlheadenum()
            self.sendMessage("[urlheadenum - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower()))
            if self.upload:
                file = "urlheadenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates dns records
    def dnsenum(self):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True and self.content[i].lower() != "monitor"):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage(
                "[dnsenum - #({0}/{1})] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.dnsenum()
            self.sendMessage("[dnsenum - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower()))
            if self.upload:
                file = "dnsenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates hidden files & directories
    def conenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True:
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[conenum - #({0}/{1})] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.conenum()
            self.sendMessage(
                "[conenum - #({0}/{1}) ~] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            if self.upload:
                file = "conenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates asn for enumerated subdomains
    def asnenum(self):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True and self.content[i].lower() != "monitor"):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage(
                "[asnenum - #({0}/{1})] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.asnenum()
            self.sendMessage("[asnenum - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower()))
            if self.upload:
                file = "asnenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates open ports
    def portenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[portenum - #({0}/{1})] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.portenum()
            self.sendMessage("[portenum - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower()))
            if self.upload:
                file = "portenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates reputation of subdomains
    def repenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[repenum - #({0}/{1})] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.repenum(_greynoise)
            self.sendMessage("[repenum - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower()))
            if self.upload:
                file = "repenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates urls
    def urlenum(self):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            self.sendMessage(
                "[urlenum - #({0}/{1})] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.urlenum(_github)
            self.sendMessage("[urlenum - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower()))
            if self.upload:
                file = "urlenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # hunts for subdomain takeovers
    def subscan(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[subscan - #({0}/{1})] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer)
            self.mergekenz(self.content[i].lower())
            message = self.scan.subscan()
            self.sendMessage("[subscan - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower()))
            if self.upload:
                file = "subscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # enumerates social media accounts
    def socenum(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True:
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[socenum - #({0}/{1})] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            self.enum = enumerator.Enumerator(
                self.content[i].lower(), _kenzerdb, _kenzer, dtype)
            self.mergekenz(self.content[i].lower())
            message = self.enum.socenum()
            self.sendMessage("[socenum - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower()))
            if self.upload:
                file = "socenum.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # scans with customized templates
    def cscan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[cscan{3} - #({0}/{1})] {2}".format(i-1,
                                                                  len(self.content)-2, self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            self.mergekenz(self.content[i].lower())
            message = self.scan.cscan()
            self.sendMessage("[cscan{4} - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower(), display))
            if self.upload:
                file = "cscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # hunts for CVEs
    def cvescan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[cvescan{3} - #({0}/{1})] {2}".format(
                i-1, len(self.content)-2, self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            self.mergekenz(self.content[i].lower())
            message = self.scan.cvescan()
            self.sendMessage("[cvescan{4} - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower(), display))
            if self.upload:
                file = "cvescan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # hunts for other common vulnerabilities
    def vulnscan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[vulnscan{3} - #({0}/{1})] {2}".format(
                i-1, len(self.content)-2, self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            self.mergekenz(self.content[i].lower())
            message = self.scan.vulnscan()
            self.sendMessage("[vulnscan{4} - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower(), display))
            if self.upload:
                file = "vulnscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # hunts for CVEs in URLs
    def urlcvescan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[urlcvescan{3} - #({0}/{1})] {2}".format(
                i-1, len(self.content)-2, self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            self.mergekenz(self.content[i].lower())
            message = self.scan.urlcvescan()
            self.sendMessage("[urlcvescan{4} - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower(), display))
            if self.upload:
                file = "urlcvescan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # hunts for other common vulnerabilities in URLs
    def urlvulnscan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = True
            if(validators.domain(self.content[i].lower()) != True):
                self.sendMessage("[invalid] {0}".format(
                    self.content[i].lower()))
                continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[urlvulnscan{3} - #({0}/{1})] {2}".format(
                i-1, len(self.content)-2, self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            self.mergekenz(self.content[i].lower())
            message = self.scan.urlvulnscan()
            self.sendMessage("[urlvulnscan{4} - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower(), display))
            if self.upload:
                file = "urlvulnscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # scans open ports
    def portscan(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True:
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[portscan - #({0}/{1})] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer)
            message = self.scan.portscan()
            self.sendMessage(
                "[portscan - #({0}/{1}) ~] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            if self.upload:
                file = "portscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
        return

    # hunts for vulnerablities in custom endpoints
    def endscan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True:
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[endscan{3} - #({0}/{1})] {2}".format(
                i-1, len(self.content)-2, self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            self.mergekenz(self.content[i].lower())
            message = self.scan.endscan()
            self.sendMessage("[endscan{4} - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower(), display))
            if self.upload:
                file = "endscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # hunts for subdomain takeovers
    def buckscan(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[buckscan - #({0}/{1})] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer)
            self.mergekenz(self.content[i].lower())
            message = self.scan.buckscan()
            self.sendMessage("[buckscan - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower()))
            if self.upload:
                file = "buckscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # fingerprints servers using favicons
    def favscan(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[favscan - #({0}/{1})] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer)
            self.mergekenz(self.content[i].lower())
            message = self.scan.favscan()
            self.sendMessage("[favscan - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower()))
            if self.upload:
                file = "favscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # identifies applications running on webservers
    def idscan(self, severity=""):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True or self.content[i].lower() == "monitor":
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            display = ""
            if(len(severity) > 0):
                display = "({0})".format(severity)
            self.sendMessage("[idscan{3} - #({0}/{1})] {2}".format(
                i-1, len(self.content)-2, self.content[i].lower(), display))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer, severity)
            self.mergekenz(self.content[i].lower())
            message = self.scan.idscan()
            self.sendMessage("[idscan{4} - #({0}/{1}) - {2}] {3}".format(
                i-1, len(self.content)-2, message, self.content[i].lower(), display))
            if self.upload:
                file = "idscan.kenz"
                self.uploader(self.content[i], file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
            if _splitting == "True":
                self.splitkenz(self.content[i].lower())
        return

    # screenshots applications running on webservers
    def vizscan(self):
        for i in range(2, len(self.content)):
            dtype = False
            if validators.domain(self.content[i].lower()) == True:
                dtype = True
            else:
                try:
                    ipaddress.ip_network(self.content[i])
                except ValueError:
                    self.sendMessage("[invalid] {0}".format(
                        self.content[i].lower()))
                    continue
            self.sendMessage(
                "[vizscan - #({0}/{1})] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            self.scan = scanner.Scanner(
                self.content[i].lower(), _kenzerdb, dtype, _kenzer)
            message = self.scan.vizscan()
            self.sendMessage(
                "[vizscan - #({0}/{1}) ~] {2}".format(i-1, len(self.content)-2, self.content[i].lower()))
            if self.upload:
                for file in os.listdir(_kenzerdb+self.content[i].lower()+"/aquatone/screenshots/"):
                    self.uploader(self.content[i],
                                  "aquatone/screenshots/"+file)
            if _logging == "False":
                self.remlog(self.content[i].lower())
        return

    # runs all enumeration modules
    def enum(self):
        self.subenum()
        self.repenum()
        self.portenum()
        self.servenum()
        self.webenum()
        self.headenum()
        self.dnsenum()
        self.socenum()
        self.conenum()
        self.asnenum()
        # experimental ones
        # self.urlenum()
        # self.urlheadenum()
        return

    # runs all scanning modules
    def scan(self):
        self.favscan()
        self.idscan()
        self.subscan()
        self.portscan()
        self.buckscan()
        self.cvescan()
        self.vulnscan()
        self.vizscan()
        # experimental ones
        # self.urlcvescan()
        # self.urlvulnscan()
        # self.endscan()
        return

    # define your custom workflow
    def hunt(self):
        self.subenum()
        self.repenum()
        self.portenum()
        self.servenum()
        self.webenum()
        self.headenum()
        self.dnsenum()
        self.conenum()
        self.socenum()
        self.subscan()
        self.idscan()
        self.favscan()
        self.buckscan()
        self.portscan()
        self.cvescan()
        self.vulnscan()
        self.asnenum()
        self.vizscan()
        # experimental ones
        # self.urlenum()
        # self.urlheadenum()
        # self.urlcvescan()
        # self.urlvulnscan()
        # self.endscan()
        return

    # runs all modules
    def recon(self):
        self.enum()
        self.scan()
        return

    # synchronizes the local kenzerdb with github
    def sync(self):
        os.system("cd {0} && git remote set-url origin https://{1}@github.com/{2}/{3}.git && cd ../scripts && bash gen_readme.sh && cd .. && git pull && git add . && git commit -m \"{4}\" && git push".format(
            _kenzerdb, _github, _user, _repo, _BotMail+"("+str(datetime.utcnow())+")"))
        self.sendMessage("[synced]")
        return

    # upgrades kenzer to latest version
    def upgrade(self):
        os.system("bash update.sh")
        self.sendMessage("[upgraded]")
        return

    # controls
    def process(self, text):
        self.content = text["content"].split()
        self.sender_email = text["sender_email"]
        self.type = text["type"]
        self.display_recipient = text['display_recipient']
        self.subject = text['subject']
        content = self.content
        print(content)
        if self.sender_email == _BotMail:
            return
        try:
            if len(content) > 1 and content[0].lower() == "@**{0}**".format(_BotMail.split('@')[0].replace("-bot", "")):
                if content[1].lower() == "man":
                    if len(content) == 2:
                        self.man()
                    else:
                        message = "excuse me???"
                        self.sendMessage(message)
                elif content[1].lower() == "monitor":
                    if content[2].lower() == "normalize":
                        self.normalize()
                    elif content[2].lower() == "db":
                        self.monitor_kenzerdb()
                    else:
                        self.monitor()
                elif content[1].lower() == "ignorenum":
                    self.ignorenum()
                elif content[1].lower() == "subenum":
                    self.subenum()
                elif content[1].lower() == "repenum":
                    self.repenum()
                elif content[1].lower() == "webenum":
                    self.webenum()
                elif content[1].lower() == "servenum":
                    self.servenum()
                elif content[1].lower() == "socenum":
                    self.socenum()
                elif content[1].lower() == "headenum":
                    self.headenum()
                elif content[1].lower() == "urlheadenum":
                    self.urlheadenum()
                elif content[1].lower() == "asnenum":
                    self.asnenum()
                elif content[1].lower() == "dnsenum":
                    self.dnsenum()
                elif content[1].lower() == "conenum":
                    self.conenum()
                elif content[1].lower() == "favscan":
                    self.favscan()
                elif content[1].lower() == "portenum":
                    self.portenum()
                elif content[1].lower() == "urlenum":
                    self.urlenum()
                elif content[1].lower() == "subscan":
                    self.subscan()
                elif content[1].split("-")[0].lower() == "cscan":
                    if len(content[1].split("-")) > 1:
                        self.cscan(content[1].split("-")[1].lower())
                    else:
                        self.cscan()
                elif content[1].split("-")[0].lower() == "cvescan":
                    if len(content[1].split("-")) > 1:
                        self.cvescan(content[1].split("-")[1].lower())
                    else:
                        self.cvescan()
                elif content[1].split("-")[0].lower() == "vulnscan":
                    if len(content[1].split("-")) > 1:
                        self.vulnscan(content[1].split("-")[1].lower())
                    else:
                        self.vulnscan()
                elif content[1].split("-")[0].lower() == "urlcvescan":
                    if len(content[1].split("-")) > 1:
                        self.urlcvescan(content[1].split("-")[1].lower())
                    else:
                        self.urlcvescan()
                elif content[1].split("-")[0].lower() == "urlvulnscan":
                    if len(content[1].split("-")) > 1:
                        self.urlvulnscan(content[1].split("-")[1].lower())
                    else:
                        self.urlvulnscan()
                elif content[1].lower() == "portscan":
                    self.portscan()
                elif content[1].split("-")[0].lower() == "endscan":
                    if len(content[1].split("-")) > 1:
                        self.endscan(content[1].split("-")[1].lower())
                    else:
                        self.endscan()
                elif content[1].split("-")[0].lower() == "idscan":
                    if len(content[1].split("-")) > 1:
                        self.idscan(content[1].split("-")[1].lower())
                    else:
                        self.idscan()
                elif content[1].lower() == "vizscan":
                    self.vizscan()
                elif content[1].lower() == "buckscan":
                    self.buckscan()
                elif content[1].lower() == "enum":
                    self.enum()
                elif content[1].lower() == "scan":
                    self.scan()
                elif content[1].lower() == "hunt":
                    self.hunt()
                elif content[1].lower() == "recon":
                    self.recon()
                elif content[1].lower() == "sync":
                    self.sync()
                elif content[1].lower() == "upgrade":
                    self.upgrade()
                elif content[1].lower() == "upload":
                    self.upload = not self.upload
                    self.sendMessage("upload: "+str(self.upload))
                else:
                    message = self.chatbot.get_response(' '.join(self.content))
                    message = message.serialize()['text']
                    self.sendMessage(message)
        except Exception as exception:
            self.sendMessage("[exception] {0}:{1}".format(
                type(exception).__name__, str(exception)))
            print(exception.__class__.__name__ + ": " + str(exception))
        return

# main


def main():
    bot = Kenzer()
    bot.client.call_on_each_message(bot.process)


# runs main
if __name__ == "__main__":
    main()
