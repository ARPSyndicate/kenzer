#imports
import os
import tldextract

#monitor
class Monitor:
    
    #initializations
    def __init__(self, db, domains=""):
        self.domains = domains
        self.organization = "monitor"
        self.db = db
        self.path = db+self.organization
        if(os.path.exists(self.path) == False):
            os.system("mkdir "+self.path)

    #core monitor modules
    
    #enumerates subdomains using certex
    def certex(self):
        domains = self.domains
        path = self.path
        output = path+"/subenum.kenz"
        if len(domains)==0:
            os.system("certex -f {0} -o {1} &".format(self.db+"../domains.txt", output))
        else:
            os.system("certex -d {0} -o {1} &".format(domains, output))
        return

    #normalizes enumerations
    def normalize(self):
        self.subenum()
        self.portenum()
        self.webenum()
        self.dnsenum()
        self.asnenum()
        self.headenum()
        self.favscan()
        self.idscan()
        self.cvescan()
        self.vulnscan()
        self.buckscan()
        return

    #normalizes subenum
    def subenum(self):
        kenzerdb = self.db
        subenum = self.path+"/subenum.kenz"
        if(os.path.exists(subenum) == False):
            return
        with open(subenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for subdomain in domains:
            try:
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/subenum.kenz", 'a', encoding="ISO-8859-1") as f:
                        f.write(subdomain)
                os.system("mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/subenum.kenz"))
                os.system("rm {0}.old".format(destination+"/subenum.kenz"))
                if(os.path.exists(destination+"/ignorenum.kenz")):
                    with open(destination+"/ignorenum.kenz", "r") as f:
                        ignore = f.read().split("/n")
                    for key in ignore:
                        os.system("ex +g/{0}/d -cwq {1}".format(key, destination+"/subenum.kenz"))
            except:
                continue
        return

    #normalizes portenum
    def portenum(self):
        kenzerdb = self.db
        portenum = self.path+"/portenum.kenz"
        if(os.path.exists(portenum) == False):
            return
        with open(portenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for subdomain in domains:
            try:
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/portenum.kenz", 'a', encoding="ISO-8859-1") as f:
                        f.write(subdomain)
                os.system("mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/portenum.kenz"))
                os.system("rm {0}.old".format(destination+"/portenum.kenz"))
            except:
                continue
        return

    #normalizes webenum
    def webenum(self):
        kenzerdb = self.db
        webenum = self.path+"/webenum.kenz"
        if(os.path.exists(webenum) == False):
            return
        with open(webenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for subdomain in domains:
            try:
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/webenum.kenz", 'a', encoding="ISO-8859-1") as f:
                        f.write(subdomain)
                os.system("mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/webenum.kenz"))
                os.system("rm {0}.old".format(destination+"/webenum.kenz"))
            except:
                continue
        return
    
    #normalizes headenum
    def headenum(self):
        kenzerdb = self.db
        headenum = self.path+"/headenum.kenz"
        if(os.path.exists(headenum) == False):
            return
        with open(headenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[0]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/headenum.kenz", 'a', encoding="ISO-8859-1") as f:
                        f.write(data)
                os.system("mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/headenum.kenz"))
                os.system("rm {0}.old".format(destination+"/headenum.kenz"))
            except:
                continue
        return
    
    #normalizes asnenum
    def asnenum(self):
        kenzerdb = self.db
        asnenum = self.path+"/asnenum.kenz"
        if(os.path.exists(asnenum) == False):
            return
        with open(asnenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[0]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/asnenum.kenz", 'a', encoding="ISO-8859-1") as f:
                        f.write(data)
                os.system("mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/asnenum.kenz"))
                os.system("rm {0}.old".format(destination+"/asnenum.kenz"))
            except:
                continue
        return

    #normalizes dnsenum
    def dnsenum(self):
        kenzerdb = self.db
        dnsenum = self.path+"/dnsenum.kenz"
        if(os.path.exists(dnsenum) == False):
            return
        with open(dnsenum, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/dnsenum.kenz", 'a', encoding="ISO-8859-1") as f:
                        f.write(data)
                os.system("mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/dnsenum.kenz"))
                os.system("rm {0}.old".format(destination+"/dnsenum.kenz"))
            except:
                continue
        return
    

    #normalizes favscan
    def favscan(self):
        kenzerdb = self.db
        favscan = self.path+"/favscan.kenz"
        if(os.path.exists(favscan) == False):
            return
        with open(favscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split("	")[2]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/favscan.kenz", 'a', encoding="ISO-8859-1") as f:
                        f.write(data)
                os.system("mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/favscan.kenz"))
                os.system("rm {0}.old".format(destination+"/favscan.kenz"))
            except:
                continue
        return
    
    #normalizes idscan
    def idscan(self):
        kenzerdb = self.db
        idscan = self.path+"/idscan.kenz"
        if(os.path.exists(idscan) == False):
            return
        with open(idscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/idscan.kenz", 'a', encoding="ISO-8859-1") as f:
                        f.write(data)
                os.system("mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/idscan.kenz"))
                os.system("rm {0}.old".format(destination+"/idscan.kenz"))
            except:
                continue
        return

    #normalizes vulnscan
    def vulnscan(self):
        kenzerdb = self.db
        vulnscan = self.path+"/vulnscan.kenz"
        if(os.path.exists(vulnscan) == False):
            return
        with open(vulnscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/vulnscan.kenz", 'a', encoding="ISO-8859-1") as f:
                        f.write(data)
                os.system("mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/vulnscan.kenz"))
                os.system("rm {0}.old".format(destination+"/vulnscan.kenz"))
            except:
                continue
        return

    #normalizes cvescan
    def cvescan(self):
        kenzerdb = self.db
        cvescan = self.path+"/cvescan.kenz"
        if(os.path.exists(cvescan) == False):
            return
        with open(cvescan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/cvescan.kenz", 'a', encoding="ISO-8859-1") as f:
                        f.write(data)
                os.system("mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/cvescan.kenz"))
                os.system("rm {0}.old".format(destination+"/cvescan.kenz"))
            except:
                continue
        return

    #normalizes buckscan
    def buckscan(self):
        kenzerdb = self.db
        buckscan = self.path+"/buckscan.kenz"
        if(os.path.exists(buckscan) == False):
            return
        with open(buckscan, 'r', encoding="ISO-8859-1") as f:
            domains = f.readlines()
        domains=list(set(domains))
        domains.sort()
        for data in domains:
            try:
                subdomain = data.split(" ")[1]
                extracted = tldextract.extract(subdomain)
                domain = "{}.{}".format(extracted.domain, extracted.suffix)
                destination = kenzerdb+domain
                if not os.path.exists(destination):
                    os.makedirs(destination)
                with open(destination+"/buckscan.kenz", 'a', encoding="ISO-8859-1") as f:
                    f.write(data)
                os.system("mv {0} {0}.old && sort -u {0}.old > {0}".format(destination+"/buckscan.kenz"))
                os.system("rm {0}.old".format(destination+"/buckscan.kenz"))
            except:
                continue
        return