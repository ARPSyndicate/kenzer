#imports
import os

#enumerator
class Enumerator:
    
    #initializations
    def __init__(self, domain, db, kenzer, github=""):
        self.domain = domain
        self.organization = domain
        self.path = db+self.organization
        self.resources = kenzer+"resources"
        self.githubapi=github
        self.templates = self.resources+"/kenzer-templates/"
        if(os.path.exists(self.path) == False):
            os.system("mkdir "+self.path)

    #core enumerator modules

    #initializes & removes out of scope targets
    def ignorenum(self, ignore=""):
        domain = self.domain
        path = self.path
        output =path+"/ignorenum.kenz"
        files = ["/subenum.kenz", "/webenum.kenz", "/portenum.kenz", "/urlenum.kenz", "/servenum.kenz"]
        ignores = []
        if(len(ignore)>0):
            ignores.append(ignore)
            if(os.path.exists(output)):
                with open(output, "r") as f:
                    ignores.extend(f.read().split("/n"))
                    ignores = list(set(ignores))
                    ignores.sort()
                    f.close()
            with open(output, "w") as f:
                f.writelines("%s\n" % line for line in ignores)
                f.close()
        if(os.path.exists(output)):
            with open(output, "r") as f:
                ignores = f.read().split("/n")
            for key in ignores:
                for file in files:
                    if(os.path.exists(path+file)):
                        os.system("ex +g/{0}/d -cwq {1}".format(key, path+file))
                with open(output, encoding="ISO-8859-1") as f:
                    line = len(f.readlines())
        else:
            line = 0
        return line

    #enumerates subdomains
    def subenum(self):
        self.gitdomain()
        self.subfinder()
        self.shuffledns()
        self.amass()
        domain = self.domain
        path = self.path
        output =path+"/subenum.kenz"
        if(os.path.exists(output)):
            self.shuffsolv(output, domain)
            os.system("rm {0}".format(output))
        os.system("cat {0}/amass.log {0}/subfinder.log {0}/subenum.kenz* {0}/shuffledns.log {0}/shuffsolv.log {0}/gitdomain.log | sort -u > {1}".format(path, output))
        self.ignorenum()
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        else:
            line = 0
        return line
    
    #enumerates webservers
    def webenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/portenum.kenz"
        if(os.path.exists(subs) == False):
            return("!portenum")
        output = path+"/httpx.log"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        self.httpx(subs, output)
        output = path+"/webenum.kenz"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system("cat {0}/httpx.log {0}/webenum.kenz* | cut -d' ' -f 1 | sort -u > {1}".format(path, output))
        self.ignorenum()
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        else:
            line = 0
        return line
        
    #enumerates additional information for webservers
    def headenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs) == False):
            return("!webenum")
        output = path+"/headenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        extras = " -status-code -title -web-server -websocket -vhost -content-type "
        self.httpx(subs, output, extras)
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        else:
            line = 0
        return line
    
    #enumerates social media accounts
    def socenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs) == False):
            return("!webenum")
        output = path+"/EmailHarvester.log"
        os.system("EmailHarvester -d {0} -s {1}".format(domain, output))
        os.system("sed -i -e 's/^/[email] [{0}] /' {1}".format(domain, output))
        output = path+"/rescro.log"
        os.system("rescro -l {0} -s {1} -T 100 -o {2}".format(subs, self.templates+"rescro.yaml", output))
        out = path+"/socenum.kenz"
        if(os.path.exists(out)):
            os.system("mv {0} {0}.old".format(out))
        os.system("cat {0}/EmailHarvester.log {0}/rescro.log | sort -u  > {1}".format(path, out))
        if(os.path.exists(out)):
            with open(out, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        else:
            line=0
        return line
    
    #enumerates additional information for urls
    def urlheadenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/urlenum.kenz"
        if(os.path.exists(subs) == False):
            return("!urlenum")
        output = path+"/urlheadenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        extras = " -status-code -title -web-server -websocket -vhost -content-type "
        self.httpx(subs, output, extras)
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        else:
            line = 0
        return line

    #enumerates urls
    def urlenum(self):
        self.gau()
        self.giturl()
        self.gospider()
        domain = self.domain
        path = self.path
        output = path+"/urlenum.kenz"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system("cat {0}/urlenum.kenz* {0}/gau.log {0}/giturl.log {0}/gospider.log | grep \"{2}\" | sort -u> {1}".format(path, output, domain))
        self.ignorenum()
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        else:
            line = 0
        return line

    #enumerates open ports using NXScan
    def portenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("!subenum")
        self.shuffsolv(subs, domain)
        output = path+"/portenum.kenz"
        subs = path+"/shuffsolv.log"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system("sudo NXScan --only-enumerate -l {0} -o {1}".format(subs,path+"/nxscan"))
        os.system("cat {0}/nxscan/enum.txt {0}/portenum.kenz* | sort -u > {1}".format(path, output))
        self.ignorenum()
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        else:
            line = 0
        return line
    
    #enumerates services on open ports using NXScan
    def servenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/portenum.kenz"
        if(os.path.exists(subs) == False):
            return("!portenum")
        output = path+"/servenum.kenz"
        os.system("sudo NXScan --only-finger -l {0} -o {1}".format(subs,path+"/nxscan"))
        os.system("cat {0}/nxscan/finger.txt {0}/servenum.kenz* | sort -u > {1}".format(path, output))
        self.ignorenum()
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        else:
            line = 0
        return line

    #enumerates dns records using DNSX
    def dnsenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("!subenum")
        output = path+"/dnsenum.kenz"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system("dnsx -l {0} -o {1} -a -aaaa -cname -mx -ptr -soa -txt -resp -retry 2".format(subs, output))
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        else:
            line = 0
        return line
    
    #enumerates asn using domlock
    def asnenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/subenum.kenz"
        if(os.path.exists(subs) == False):
            return("!subenum")
        output = path+"/asnenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("domlock -l {0} -o {1} -T 30".format(subs, output))
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        else:
            line = 0
        return line
    
    #enumerates hidden files & directories using ffuf
    def conenum(self):
        domain = self.domain
        path = self.path
        subs = path+"/webenum.kenz"
        if(os.path.exists(subs) == False):
            return("!webenum")
        output = path+"/conenum.kenz"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("ffuf -u FuZZDoM/FuZZCoN -w {0}:FuZZDoM,{1}:FuZZCoN -or -of csv -o {2} -t 80".format(subs, self.resources+"/kenzer-templates/ffuf.lst", output))
        if(os.path.exists(output)):
            with open(output, encoding="ISO-8859-1") as f:
                line = len(f.readlines())
        else:
            line = 0
        return line

    #helper modules

    #downloads fresh list of public resolvers
    def getresolvers(self):
        output = self.resources+"/resolvers.txt"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 200 -o {0}".format(output))
    
    def generateSubdomainsWordist(self):
        os.system("cd {0} && wget -q https://raw.githubusercontent.com/internetwache/CT_subdomains/master/top-100000.txt -O top-100000.txt".format(self.resources))
        os.system("cd {0} && wget -q https://raw.githubusercontent.com/cqsd/daily-commonspeak2/master/wordlists/subdomains.txt -O subsB.txt".format(self.resources))
        output = self.resources+"/subsA.txt"
        os.system("cat {0}/top-100000.txt | cut -d ',' -f 2 | sort -u > {1}".format(self.resources, output))
        output = self.resources+"/subdomains.txt"
        os.system("cat {0}/subsA.txt {0}/subsB.txt | sort -u > {1}".format(self.resources, output))
        

    #resolves & removes wildcard subdomains using shuffledns
    def shuffsolv(self, domains, domain):
        self.getresolvers()
        path=self.path + "/shuffsolv.1.log"
        if(os.path.exists(path)):
            os.system("rm {0}".format(path))
        os.system("shuffledns -strict-wildcard -retries 6 -wt 20 -r {3}/resolvers.txt -o {0} -v -list {1} -d {2}".format(path, domains, domain,self.resources))
        oldp = path
        path = self.path+"/shuffsolv.log"
        os.system("shuffledns -strict-wildcard -retries 6 -wt 20 -r {3}/resolvers.txt -o {0} -v -list {1} -d {2}".format(path, oldp, domain,self.resources))
        os.system("rm "+oldp)
        return

    #enumerates subdomains using github-subdomains
    def gitdomain(self):
        domain = self.domain
        path = self.path
        api=self.githubapi
        output = path+"/gitdomain.log"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system("github-subdomains -d {1} -t {2} > {0}".format(output, domain, api))
        return

    #enumerates subdomains using subfinder
    #"retains wildcard domains"
    def subfinder(self):
        domain = self.domain
        path = self.path
        output = path+"/subfinder.log"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system("subfinder -all -recursive -t 50 -max-time 20 -o {0} -v -timeout 20 -d {1}".format(output, domain))
        return
    
    #enumerates subdomains using amass
    def amass(self):
        domain = self.domain
        path = self.path
        output = path+"/amass.log"
        if(os.path.exists(output)):
            os.system("mv {0} {0}.old".format(output))
        os.system("amass enum -o {0} -d {1} -norecursive -noalts -active -nolocaldb".format(output, domain))
        return

    #enumerates subdomains using shuffledns
    #"removes wildcard domains"
    def shuffledns(self):
        self.getresolvers()
        self.generateSubdomainsWordist()
        domain = self.domain
        path = self.path
        output = path+"/shuffledns.log"
        if(os.path.exists(output)):
            os.system("rm {0}".format(output))
        os.system("shuffledns -retries 6 -strict-wildcard -wt 30 -r {2}/resolvers.txt -w {2}/subdomains.txt -o {0} -v -d {1}".format(output, domain, self.resources))
        self.shuffsolv(output, domain)
        os.system("rm {0} && mv {1} {0}".format(output, path+"/shuffsolv.log"))
        return 

    #probes for web servers using httpx
    def httpx(self, domains, output, extras=""):
        os.system("httpx {2} -no-color -l {0} -threads 80 -retries 3 -timeout 7 -verbose -o {1}".format(domains, output, extras))
        return
    
    #enumerates urls using gau
    def gau(self):
        domain = self.domain
        path = self.path
        path+="/gau.log"
        if(os.path.exists(path)):
            os.system("mv {0} {0}.old".format(path))
        os.system("gau -subs -o {0} {1}".format(path, domain))
        return

    #enumerates urls using gospider
    def gospider(self):
        domain = self.domain
        path = self.path
        path+="/gospider.log"
        if(os.path.exists(path)):
            os.system("mv {0} {0}.old".format(path))
        os.system("gospider -S {0}/webenum.kenz -w -r --sitemap -c 10 -t 5 -o {0}/gocrawler -q -u web | sort -u > {1}".format(self.path, path))
        return
    
    #enumerates urls using github-endpoints
    def giturl(self):
        domain = self.domain
        path = self.path
        path+="/giturl.log"
        api = self.githubapi
        if(os.path.exists(path)):
            os.system("mv {0} {0}.old".format(path))
        os.system("github-endpoints -a -t {2} -d {1} > {0}".format(path, domain, api))
        return

    #removes log files & empty files
    def remlog(self):
        os.system("rm {0}/*.log*".format(self.path))
        os.system("rm -r {0}/nuclei {0}/jaeles {0}/nxscan {0}/gocrawler".format(self.path))
        os.system("find {0} -type f -empty -delete".format(self.path))
