# This class is used to contained methods of calculating features' input

# -*- coding: utf-8 -*-
from bs4 import BeautifulSoup
import ssl
import urllib
import urllib.request
from urllib.parse import urlparse
from urllib.request import urlopen
import whois
import datetime
from tldextract import extract
import dns.resolver
import bs4
import regex
import socket
import threading
import requests
from model.functions import Functions
import numpy as np
import time

def url_is_internal(url,compare):
    # url is the param needed to be compared to compare
    if ".".join(extract(url)) == ".".join(extract(compare)) or (url[0:4] != "http" and url[0] != "#"):
        return True
    else:
        return False

def get_domain_from_url(url):
    subdomain, domain, suffix = extract(url)
    full_domain = (subdomain+"." if subdomain else "") + domain + "."+ suffix
    return full_domain


class Checker():
    
    def check_connection(url):
        try:
            r = requests.get(url,timeout=7)
            print("CHECK CONNECTION",r)
            return 1
        except Exception as e:
            print("connection error",e)
            return 0

    def having_IP_Address(url):
        status = 0
        having_ip = "unknown"

        try:
            symbol = regex.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',url)
            if(len(symbol)!=0):
                status = 1
                having_ip = "yes" 
            else:
                status = -1
                having_ip = "no" 
               
        except Exception as e:
            print("err_having_IP_Address",e)
            status = 0
        
        return {
            "status": status,
            "info": {
                "having_ip": having_ip
            }
        }
            
    def URL_Length(url):
        status = 0
        url_length = "unknown"

        try:
            length=len(url)
            url_length = length

            if(length<54):
                status = -1
            elif(54<=length<=75):
                status = 0
            else:
                status = 1
        except Exception as e:
            print("err_URL_length",e)
            status = 0
        
        return {
            "status": status,
            "info": {
                "url_length": url_length
            }
        }

    def Shortining_Service(url):
        status = 0
        redirect_count = "unknown"
        try:
            r = requests.get(url,timeout=7)
            redirect_count = len(r.history)
            if redirect_count > 1:
                status = 1
            else:
                status = -1
        except Exception as e:
            print("err_shortining_Service",e)
            status = 0
        
        return {
            "status": status,
            "info": {
                "redirect_count": redirect_count,
            }
        }
    
    def having_At_Symbol(url):
        status = 0
        having_aid_symbol = "unknown"

        try:
            symbol=regex.findall(r'@',url)
            if(len(symbol)==0):
                status = -1
                having_aid_symbol = "no"
            else:
                status = 1
                having_aid_symbol = "yes"

        except Exception as e:
            print("err_having_At_Symbol",e)
            status = 0
        
        return {
            "status": status,
            "info": {
                "having_aid_symbol": having_aid_symbol
            }
        }
    
    def double_slash_redirecting(url):
        return {
            "status": -1
        }
    
    def Prefix_Suffix(url):
        status = 0
        suspicious_domain = "no"
        try:
            subDomain, domain, suffix = extract(url)
            if(domain.count('-')):
                status = 1
                suspicious_domain = "yes"
            else:
                status = -1
                suspicious_domain = "no"
        except Exception as e:
            print("err_Prefix_Suffix",e)
            status = 0
            suspicious_domain = "unknown"
        
        return {
            "status": status,
            "info": {
                "suspicious_domain": suspicious_domain
            }
        }
    
    def having_Sub_Domain(url):
        status = 0,
        subdomain_count = "unknown",

        try:
            subDomain, domain, suffix = extract(url)
            subdomain_count = subDomain.count('.')
            if(subDomain.count('.')==0):
                status = -1
                subdomain_count = subdomain_count
            elif(subDomain.count('.')==1):
                status = 0
                subdomain_count = subdomain_count
            else:
                status = 1
                subdomain_count = subdomain_count

        except Exception as e:
            print("err_having_Sub_Domain",e)
            status = 0

        return {
            "status": status,
            "info": {
                "subdomain_count": subdomain_count
            }
        }    

    def SSLfinal_State(url):
        status = 0,
        has_ssl = "unknown",

        try:
            if(regex.search('^https',url)):

                usehttps = 1
            else:
                usehttps = 0
            subDomain, domain, suffix = extract(url)
            host_name = domain + "." + suffix
            context = ssl.create_default_context()
            sct = context.wrap_socket(socket.socket(), server_hostname = host_name)
            sct.connect((host_name, 443))
            certificate = sct.getpeercert()
            # print("CERTIFICATE:",certificate)
            startingDate = str(certificate['notBefore'])
            endingDate = str(certificate['notAfter'])
            startingYear = int(startingDate.split()[3])
            endingYear = int(endingDate.split()[3])
            Age_of_certificate = endingYear-startingYear
            if((usehttps==1) and (Age_of_certificate>=1) ):
                status = -1 
                has_ssl = "yes"
            else:
                status = 1 
                has_ssl = "no"

        except Exception as e:
            print("err_SSLfinal_State",e)
            status = 0  
        
        return {
            "status": status,
            "info": {
                "has_ssl": has_ssl
            }
        }
    
    def Domain_registeration_length(url):
        status = 0,
        domain_registration_length = "unknown"
        try:
            w = whois.whois(url)
            updated = w.creation_date
            exp = w.expiration_date
            if type(updated) == list:
                updated = updated[-1]
            if type(exp) == list:
                exp = exp[-1]

            length = (exp-updated).days
            domain_registration_length = length
            if(length<=365):
                status = 1
            else:
                status = -1
        except Exception as e:
            print("err_Domain_registration_length",e)
            status = 0
        
        return {
            "status": status,
            "info": {
                "domain_registration_length": domain_registration_length
            }
        }
    
    def Favicon(url):
        status = 0
        has_favicon = "unknown"

        try:
            r = requests.get(url,timeout=7)
            html = r.text

            regex_favicon = '<link rel=".*?icon".*?href="(.*?)"'
            regex_result = regex.findall(regex_favicon,html)
            if len(regex_result) == 0:
                status = 1
                has_favicon = "no"
            else:
                favicon_url = regex_result[0]

                url_domain = ".".join(extract(url)[1:3])
                favicon_domain = ".".join(extract(favicon_url[1:3]))
                if url_domain == favicon_domain:
                    status = -1
                    has_favicon = "yes"
                else:
                    status = 1
                    has_favicon = "no"

        except Exception as e:
            print("err_favicon",e)
            status = 1
        
        return {
            "status": status,
            "info": {
                "has_favicon": has_favicon
            }
        }
    
    def port(url):
        status = 0
        try:
            subDomain, domain, suffix = extract(url)
            host_name = domain + "." + suffix
            DEFAULT_TIMEOUT = 0.5
            open_port = []
            list_ports = [21,22,23,80,443,445,1433,1521,3306,3389]
            timeout=DEFAULT_TIMEOUT
            TCPsock = socket.socket()
            TCPsock.settimeout(timeout)
            TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                for i in list_ports:
                    result = TCPsock.connect((host_name, i))
                    if result == 0:
                        open_port.append(i)
            except:
                pass
            if (80,443 in open_port) and  len(list_ports) > 2:
                status = 1
            elif (80,443 in open_port) and len(list_ports) == 2:
                status = -1
            else:
                status = 1
        except Exception as e:
            print("err_port",e)
            status = 0
        
        return {
            "status": status
        }
                            
    def HTTPS_token(url):
        status = 0
        try:
            subDomain, domain, suffix = extract(url)
            host =subDomain +'.' + domain + '.' + suffix 
            if(host.count('https')): 
                status = 1
            else:
                status = -1
        except Exception as e:
            print("err_HTTPS_token",e)
            status = 0
        
        return {
            "status": status
        }

    def Request_URL(url):
        status = 0
        external_request_count = "unknown"
        internal_request_count = "unknown"
        
        try:
            r = requests.get(url,timeout=7)
            html = r.text
            url_elems = extract(url)
            domain = url_elems[1] + "." + url_elems[2]
            
            regex_external = "(href=|src=)(\"|')((https|http)://)"

            links = regex.findall(regex_external,html)

            regex_all = "(href=|src=)(\"|')(.*?)(\"|')"
            total_links = len(regex.findall(regex_all,html))

            count_diff = 0 # number of external domains
            for link in links:
                domain_of_link = urlparse(link[2])[1]
                domain_elements = domain_of_link.split(".")
                domain_of_link = ".".join(domain_elements[len(domain_elements)-2:len(domain_elements)])
                count_diff += domain_of_link != domain
            if (total_links == 0):
                status = 1
            
            external_request_count = count_diff
            internal_request_count = total_links - external_request_count

            diff_rate = (count_diff / total_links) if (total_links) else 0
            
            if diff_rate < 0.22:
                status = -1
            elif diff_rate <= 0.61:
                status = 0
            else:
                status = 1
        except Exception as e:
            print("err_Request_url",e)
            status = 0

        return {
            "status": status,
            "info": {
                "internal_request_count": internal_request_count,
                "external_request_count": external_request_count
            }
        }
    
    def URL_of_Anchor(url):
        status = 0
        anchor_link_count = "unknown"

        try:
            t1 = time.time()
            regex_str = "<a href=\".*?\""
            html = requests.get(url,timeout=7).text
            links_list = regex.findall(regex_str,html)
            count_internal = 0

            for link in links_list:
                if url_is_internal(link,url):
                    count_internal += 1
            
            if len(links_list) == 0:
                status = 1
            else: 
                count_anchor = len(links_list) - count_internal
                rate = count_anchor / len(links_list)

                anchor_link_count = count_anchor
                if (rate < 0.31):
                    status = -1
                elif (0.31 <= rate <= 0.67):
                    status = 0
                else:
                    status = 1
        except Exception as e:
            print("err_URL_of_Anchor",e)
            status = 0
        
        return {
            "status": status,
            "anchor_link_count": anchor_link_count
        }
    
    def Links_in_tags(url):
        return {
            "status": -1
        }
    
    def SFH(url):
        # MrNA
        return {
            "status": -1
        }
    
    def Submitting_to_email(url):
        # MrNA
        return {
            "status": -1
        }

    def Abnormal_URL(url):
        # remember to split domain
        status = 0
        whois_valid = "unknown"

        try:
            w = whois.whois(url)
        
            print("W",w)
            if w.domain_name == None:
                whois_valid = "no"
                status = 1
            else:
                whois_valid = "yes"
                status = -1 

        except Exception as e:
            print("err_abnormal_url",e)
            whois_valid = "no"
            status = 1

        return {
            "status": status,
            "info": {
                "whois_valid": whois_valid
            }
        }
    
    def Redirect(url):
        status = 0

        try:
            r = requests.get(url,timeout=7)
            redirections = len(r.history)

            if redirections <= 1:
                status = -1
            elif redirections < 4:
                status = 0
            else:
                status = 1
        # still need to validate client redirecting sites
        except Exception as e:
            print("err_redirect",e)
            status = 0
        
        return {
            "status": status
        }
    
    def on_mouseover(url):
        status = 0
        try:
            html = requests.get(url,timeout=7).text
            soup = BeautifulSoup(html, 'html.parser')
            p = soup.find_all('script')
            result = 1
            strr = ""
            for jss in p:
                strr = strr + jss.text
            if "window.status" in strr:
                result = -1
            status = result
        except Exception as e:
            print("err_onmouseover",e)
            status = 1
        
        return {
            "status": status
        }
    
    def RightClick(url):
        status = 0
        try:
            html = requests.get(url,timeout=7).text
            soup = BeautifulSoup(html, 'html.parser')
            p = soup.find_all('script')
            result = 1
            strr = ""
            for jss in p:
                strr = strr + jss.text
            if "contextmenu" in strr:
                result = -1
            status = result
        except Exception as e:
            print("err_RighClick",e)
            status = 0
        
        return {
            "status": status
        }
    
    def popUpWidnow(url):
        status = 0
        has_popup_window = "unknown"

        try:
            html = requests.get(url,timeout=7).text
            soup = BeautifulSoup(html, 'html.parser')
            p = soup.find_all('script')
            result = 1
            strr = ""
            for jss in p:
                strr = strr + jss.text
            if "window.open" in strr:
                has_popup_window = "yes"
                result = -1
            else:
                has_popup_window = "no"

            status = result
        except Exception as e:
            print("err_popUpWindow",e)
            status = 0
        
        return {
            "status": status,
            "info" : {
                "has_popup_window": has_popup_window
            }
        }
    
    def Iframe(url):
        status = 0
        has_iframe = "unknown"
        try:
            html = requests.get(url,timeout=7).text
            if "</iframe>" in html:
                has_iframe = "yes"
                status = -1
            else:
                has_iframe = "no"
                status = 1
        except Exception as e:
            print("err_Iframe")
            status = 0
        
        return {
            "status": status,
            "info": {
                "has_iframe": has_iframe
            }
        }
    
    def age_of_domain (url):
        status = 0
        age_of_domain = "unknown"

        try:
            w = whois.whois(url)
            start_date = w.creation_date
            current_date = datetime.datetime.now()

            if type(start_date) == list:
                start_date = start_date[-1]
        
            age = (current_date-start_date).days
            
            age_of_domain = age

            if(age>=180):
                status = -1
            else:
                status = 1
        except Exception as e:
            print("err_age_of_domain",e)
            status = 1
        
        return {
            "status": status,
            "info": {
                "age_of_domain": age_of_domain
            }
        }

    def DNSRecord(url):
        status = 0
        has_dns_record = "unknown"
        try: 
            try:
                result = dns.resolver.query(url, 'A')
                for i in result:
                    if i:
                        status = -1  
                        has_dns_record = "yes"
                        break
            except:
                status = 1
                has_dns_record = "no"
        except Exception as e:
            print("err_DNSRecord")    
            status = 0
        
        return {
            "status": status,
            "info": {
                "has_dns_record": has_dns_record
            }
        }

    def web_traffic(url):
        status = 0
        alexa_rank = "unknown"
        try:
            soup = bs4.BeautifulSoup(urlopen('http://data.alexa.com/data?cli=10&dat=snbamz&url='+url).read(),features="html.parser")
            if not hasattr(soup.popularity,'text'):
                status = 1
            else:
                rank = int(soup.popularity['text'])
                alexa_rank = rank

                if rank < 100000:
                    status = -1
                else:
                    status = 1
        except Exception as e:
            print("err_web_traffic",e)
            status = 0
        
        return {
            "status": status,
            "info": {
                "alexa_rank": alexa_rank
            }
        }

    def Page_Rank(url):
        status = 0
        open_page_rank = "unknown"
        try:
            URL = "https://openpagerank.com/api/v1.0/getPageRank"
            PARAMS = {'domains[]':'google.com'} 
            r=requests.get(URL,params=PARAMS, headers={'API-OPR':'8044swwk8og00wwgc8ogo80cocs00o0o4008kkg0'}, timeout=7)
            json_data = r.json()
            domainarray = json_data['response']
            target = domainarray[0]
            rank = target['rank']
            open_page_rank = rank
            
            if rank=="None" or float(rank or 0.1)<0.2:
                status = -1
            else:
                status = 1
        except Exception as e:
            print("err_Page_Rank",e)
            status = 0
        
        return {
            "status": status,
            "info": {
                "open_page_rank": open_page_rank
            }
        }

    def Google_Index(url):
        status = 0
        google_index = "unknown"
        try:
            r = requests.head("https://webcache.googleusercontent.com/search?q=cache:" + url, timeout=7)
            if r.status_code == 404:
                status = -1
                google_index = "no"
            else:
                status = 1
                google_index = "yes"

        except Exception as e:
            print("err_google_index",e)
            status = 0

        return {
            "status": status,
            "google_index": google_index
        }

    def Links_pointing_to_page(url): # backlinks
        # proxyht
        return {
            "status": -1
        }

    def Statistical_report(url):
        status = 0
        found_in_our_database = "unknown"

        f = open("model/data/urls.csv","r",encoding="UTF-8")
        data = f.read().split("\n")
        
        if url in data:
            status = 1
            found_in_our_database = "yes"
        else: 
            status = -1
            found_in_our_database = "no"
        
        return {
            "status": status,
            "info": {
                "found_in_our_database": found_in_our_database
            }
        }
    
    
