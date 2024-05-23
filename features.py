from pip._vendor.urllib3.util import url
import datetime
import whois
from urllib.parse import urlparse, urlencode
import ipaddress
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from http.client import HTTPConnection, HTTPSConnection
from urllib3.exceptions import InsecureRequestWarning
import pandas as pd
import warnings

warnings.filterwarnings("ignore", category=UserWarning)  # Ignore UserWarnings (e.g., scikit-learn version)


def check_https_url(url):
    HTTPS_URL = f'https://{url}'
    try:
        HTTPS_URL = urlparse(HTTPS_URL)
        connection = HTTPSConnection(HTTPS_URL.netloc, timeout=2)
        connection.request('HEAD', HTTPS_URL.path)
        if connection.getresponse():
            return f'https://{url}', True
        else:
            return f'https://{url}',False
    except:
        return f'https://{url}',False

def check_http_url(url):
    HTTP_URL = f'http://{url}'
    try:
        HTTP_URL = urlparse(HTTP_URL)
        connection = HTTPConnection(HTTP_URL.netloc, timeout=2)
        connection.request('HEAD', HTTP_URL.path)
        if connection.getresponse():
            return f'http://{url}',True
        else:
            return f'http://{url}',False
    except:
        return f'http://{url}',False

def fix_url(
    url,
): 
   if url.startswith('http') or url.startswith('https'):
     return url
   else: 
     if check_https_url(url)[1]:
        return check_https_url(url)[0]
     elif check_http_url(url)[1]:
        return check_http_url(url)[0]
   return f"http://{url}"


def get_protocol(url):
    protocol, _, _, _, _, _ = urlparse(url.replace("[", "").replace("]", "").strip())
    return protocol


def get_host(url):
    _, host, _, _, _, _ = urlparse(url.replace("[", "").replace("]", "").strip())
    return host


def get_path(url):
    _, _, path, _, _, _ = urlparse(url.replace("[", "").replace("]", "").strip())
    return path


def get_parameters(url):
    _, _, _, parameters, _, _ = urlparse(url.replace("[", "").replace("]", "").strip())
    return parameters


def get_query(url):
    _, _, _, _, query, _ = urlparse(url.replace("[", "").replace("]", "").strip())
    return query


def get_fragment(url):
    _, _, _, _, _, fragment = urlparse(url.replace("[", "").replace("]", "").strip())
    return fragment


def Shortining_Service(url):
    match = re.search(
        "bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
        "yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
        "short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
        "doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|"
        "db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|"
        "q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
        "x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"
        "tr\.im|link\.zip\.net",
        url,
    )
    if match:
        return 1
    else:
        return 0
def feature(url):
  l=[]
  url=fix_url(url)
  urlp=get_protocol(url)
  urlh=get_host(url)
  urlpath=get_path(url)
  urlq=get_query(url)
  urlf=get_fragment(url)
  #feature for url in general
  l.append(url)
  l.append(Shortining_Service(url))
  l.append(having_ip_address(url))#2
  l.append(pathcount(url))#3
  l.append(redirection(url))#4
  l.append(flagEmailAddress(url))
  l.extend(countfe(url))
  l.append(digit_count(url))#5
  l.append(letter_count(url))#6
  l.append(length(url))#7
  l.append(punyflag(url))#8
  l.append(portflag(url)) #9
  #host feature
  l.append(sub_domains(urlh))#10
  l.append(main_domains(urlh)) #11
  l.append(shady_url(urlh))#12
  l.append(length(urlh))#13
  l.append(spaces(urlh))#13
  l.append(protocol_inhostname(urlh))#14
  l.extend(countfe(urlh))#45 
  l.append(digit_count(urlh))#46
  l.append(letter_count(urlh))#47
  #path
  l.append(length(urlpath))#46
  l.extend(countfe(urlpath))#77
  l.append(digit_count(urlpath))#78
  l.append(letter_count(urlpath))#79
  l.append(protocol_inhostname(urlpath))#80
  l.append(length(urlh)/length(url))#81 
  l.append(length(urlpath)/length(url))#82
  l.append(length(urlpath)/length(urlh))#83
  try: 
    l.append(websiteForwarding(requests.get(url,timeout = 5.0)))#84
  except :
    l.append(-1)
  #HTML
  l.extend(HTML_FEATURE(url))
  l.append(img_count(url))
  l.append(link_count(url))
  l.append(age(url))
  l.append(StatusBarCust(url))
  l.append(DisableRightClick(url))
  l.append(UsingPopupWindow(url))

  return l
  

def having_ip_address(url):
    match = re.search(
        "(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|"  # IPv4
        "(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
        "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|"  # IPv4 with port
        "((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)"  # IPv4 in hexadecimal
        "(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|"
        "([0-9]+(?:\.[0-9]+){3}:[0-9]+)|"
        "((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)",
        url,
    )  # Ipv6
    if match:
        return 1
    else:
        return 0


def pathcount(url):
    return abs(url.count("/") - 2 * url.count("//"))


def redirection(url):
    if "//" in urlparse(url).path:
        return 1
    else:
        return 0


def spaces(url):
    return url.count(" ")

def protocol_inhostname(url):
  if 'https'.casefold() == url.casefold() :
    return 1 
  return 0


def countfe(url):
    s = "!\"#$%&'()*+, -.:;<=>?@[]^_`{|}~"
    d = {}
    l=[]
    for i in s:
        d[i] = url.count(i)
    for i in s:
      l.append(d[i])
    return l 

def letter_count(url):
  sumalpha = 0
  for i in url:
        if i.isalpha():
            sumalpha += 1
  return  sumalpha

def digit_count(url):
  sumdigit=0
  for i in url:
        if i.isnumeric():
            sumdigit += 1
  return  sumdigit

def length(url):
    return len(url)


def sub_domains(url):
    o = url.split(".")
    counterd = 0
    for i in url:
        if i == ".":
            counterd += 1
    sublen = 0
    for i in range(0, counterd - 1):
        if not (counterd - 1 == 0):
            sublen += len(o[i])
    return sublen


def main_domains(url):
    o = url.split(".")
    return len(o[-1])


def img_count(url):
  try:
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    response = requests.get(url,timeout=10.0,verify=False)
    soup = BeautifulSoup(response.content, "html.parser")
    return len(soup.find_all("src"))
  except:
    return 0




def link_count(url):
  try:
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    response = requests.get(url,timeout=5.0,verify=False)
    soup = BeautifulSoup(response.content, "html.parser")
    u = soup.find_all("a")
    return len(u)
  except:
    return 0



def punyflag(url):
    if url.startswith("https://xn--") or url.startswith("http://xn--"):
        return 1
    else:
        return 0


def portflag(url):
    if re.search(
        "^[a-z][a-z0-9+\-.]*://([a-z0-9\-._~%!$&'()*+,;=]+@)?([a-z0-9\-._~%]+|\[[a-z0-9\-._~%!$&'()*+,;=:]+\]):([0-9]+)",
        url,
    ):
        return 1
    return 0


def shady_url(url):
    l = [
        "country",
        "kim",
        "science",
        "gq",
        "work",
        "ninja",
        "xyz",
        "date",
        "faith",
        "zip",
        "racing",
        "cricket",
        "win",
        "space",
        "accountant",
        "realtor",
        "top",
        "stream",
        "christmas",
        "gdn",
        "mom",
        "pro",
        "men",
    ]
    o = url.split(".")
    if o[-1] in l:
        return 1
    else:
        return 0


def age(url):
  try:
    w = whois.whois(url)
    if w["creation_date"] == None:
        return 0
    if not (type(w["creation_date"])==list):


      a = datetime.datetime.now() - w["creation_date"]
      if a.days >= 730:
        return 1
      else : 
        return 0

    a = datetime.datetime.now() - w["creation_date"][0]
    if a.days >= 730:
        return 1
    else : 
        return 0
    return a.days
  except Exception as e:
    return 0


def flagEmailAddress(url):
    if re.findall(r'[\w\.-]+@[\w\.-]+', url):
        return 1
    else:
        return 0
def websiteForwarding(response):
  if response == "":
    return 0
  else:
    return len(response.history)

def TLD_count(url):
    tld_file = open('/content/tld.txt', 'r')
    tldcount = 0 
    tld_list=tld_file.readlines()
    line=0  
    while (line < len(tld_list)):
       if tld_list[line].rstrip() in url :
          tldcount+=1
          line+=10
       line+=1
    if(".php" in url):
      tldcount-=1;
    if(".html" in url):
      tldcount-=1;

    tld_file.seek(0)
    return tldcount


def StatusBarCust(url):
        try:
            requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
            response = requests.get(url,timeout=5.0,verify=False)
            if re.findall("<script>.+onmouseover.+</script>", response.text):
                return 1
            else:
                return 0
        except:
             return -1

def DisableRightClick(url):

        try:
            requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
            response = requests.get(url,timeout=5.0,verify=False)
            if re.findall(r"event.button ?== ?2", response.text):
                return 1
            else:
                return 0
        except:
             return -1

def UsingPopupWindow(url):
        try:
            requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
            response = requests.get(url,timeout=5.0,verify=False)
            if re.findall(r"alert\(", response.text):
                return 1
            else:
                return 0
        except:
             return -1

def HTML_FEATURE(url):
  try:
    l=[]
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    response = requests.get(url,timeout = 3.0,verify=False)
    soup = BeautifulSoup(response.content, "html.parser")
    def has_title(soup):
        if soup.title is None:
            return 0
        if len(soup.title.text) > 0:
            return 1
        else:
            return 0
    
    
    # has_input
    def has_input(soup):
        if len(soup.find_all("input")):
            return 1
        else:
            return 0
    
    
    # has_button
    def has_button(soup):
        if len(soup.find_all("button")) > 0:
            return 1
        else:
            return 0
    
    
    # has_image
    def has_image(soup):
        if len(soup.find_all("image")) == 0:
            return 0
        else:
            return 1
    
    
    # has_submit
    def has_submit(soup):
        for button in soup.find_all("input"):
            if button.get("type") == "submit":
                return 1
            else:
                pass
        return 0
    
    
    # has_link
    def has_link(soup):
        if len(soup.find_all("link")) > 0:
            return 1
        else:
            return 0
    
    
    # has_password
    def has_password(soup):
        for input in soup.find_all("input"):
            if (input.get("type") or input.get("name") or input.get("id")) == "password":
                return 1
            else:
                pass
        return 0
    
    
    # has_email_input
    def has_email_input(soup):
        for input in soup.find_all("input"):
            if (input.get("type") or input.get("id") or input.get("name")) == "email":
                return 1
            else:
                pass
        return 0
    
    
    # has_hidden_element
    def has_hidden_element(soup):
        for input in soup.find_all("input"):
            if input.get("type") == "hidden":
                return 1
            else:
                pass
        return 0
    
    
    # has_audio
    def has_audio(soup):
        if len(soup.find_all("audio")) > 0:
            return 1
        else:
            return 0
    
    
    # has_video
    def has_video(soup):
        if len(soup.find_all("video")) > 0:
            return 1
        else:
            return 0
    
    
    # number_of_inputs
    def number_of_inputs(soup):
        return len(soup.find_all("input"))
    
    
    # number_of_buttons
    def number_of_buttons(soup):
        return len(soup.find_all("button"))
    
    
    # number_of_images
    def number_of_images(soup):
        image_tags = len(soup.find_all("image"))
        count = 0
        for meta in soup.find_all("meta"):
            if meta.get("type") or meta.get("name") == "image":
                count += 1
        return image_tags + count
    
    
    # number_of_option
    def number_of_option(soup):
        return len(soup.find_all("option"))
    
    
    # number_of_href
    def number_of_href(soup):
        count = 0
        for link in soup.find_all("link"):
            if link.get("href"):
                count += 1
        return count
    
    
    # number_of_script
    def number_of_script(soup):
        return len(soup.find_all("script"))
    
    
    # length_of_title
    def length_of_title(soup):
        if soup.title == None:
            return 0
        return len(soup.title.text)
    def length_of_text(soup):
        return len(soup.get_text())
    
    
    # number of clickable button
    def number_of_clickable_button(soup):
        count = 0
        for button in soup.find_all("button"):
            if button.get("type") == "button":
                count += 1
        return count
    
    
    # number of a
    def number_of_a(soup):
        return len(soup.find_all("a"))
    
    
    # number of img
    def number_of_img(soup):
        return len(soup.find_all("img"))
    
    
    # number of div class
    def number_of_div(soup):
        return len(soup.find_all("div"))
    
    
    # has form
    def has_form(soup):
        if len(soup.find_all("form")) > 0:
            return 1
        else:
            return 0
    
    
    # has textarea
    def has_text_area(soup):
        if len(soup.find_all("textarea")) > 0:
            return 1
        else:
            return 0
    
    
    # has iframe
    def has_iframe(soup):
        if len(soup.find_all("iframe")) > 0:
            return 1
        else:
            return 0
    
    
    # has text input
    def has_text_input(soup):
        for input in soup.find_all("input"):
            if input.get("type") == "text":
                return 1
        return 0
    
    
    # number of meta
    def number_of_meta(soup):
        return len(soup.find_all("meta"))
    
    
    # has nav
    def has_nav(soup):
        if len(soup.find_all("nav")) > 0:
            return 1
        else:
            return 0
    
    
    # has object
    def has_object(soup):
        if len(soup.find_all("object")) > 0:
            return 1
        else:
            return 0
    
    
    # has picture
    def has_picture(soup):
        if len(soup.find_all("picture")) > 0:
            return 1
        else:
            return 0
    
    
    # number of sources
    def number_of_sources(soup):
        return len(soup.find_all("source"))
        
    # number of span
    def number_of_span(soup):
        return len(soup.find_all("span"))
    
    
    l.append(has_title(soup))
    l.append(has_input(soup))
    l.append(has_button(soup))
    l.append(has_image(soup))
    l.append(has_submit(soup))
    l.append(has_link(soup))
    l.append(has_password(soup))
    l.append(has_email_input(soup))
    l.append(has_hidden_element(soup))
    l.append(has_audio(soup))
    l.append(has_video(soup))
    l.append(number_of_inputs(soup))
    l.append(number_of_buttons(soup))
    l.append(number_of_images(soup))
    l.append(number_of_option(soup))
    l.append(number_of_href(soup))
    l.append(number_of_script(soup))
    l.append(length_of_title(soup))
    l.append(number_of_clickable_button(soup))
    l.append(number_of_a(soup))
    l.append(number_of_img(soup))
    l.append(number_of_div(soup))
    l.append(has_form(soup))
    l.append(has_text_area(soup))
    l.append(number_of_meta(soup))
    l.append(has_nav(soup))
    l.append(has_object(soup))
    l.append(has_picture(soup))
    l.append(number_of_sources(soup))
    l.append(number_of_span(soup))
    return(l)
  except Exception as e: 
    print(e)
    for i in range (0,30): 
      l.append(-1)
    return l 


