from attackcti import attack_client
import urllib.request
from pandas import *
import numpy as np
from pathlib import Path
import json
from fuzzywuzzy import fuzz
from pathlib import Path
import stix2

class Mitre(attack_client):
 T=[]
 R=[]
 G=[]
 client=[]

 def __init__(self):
  self.client=attack_client()
#  self.R=lift.get_relationships()
#  self.T=lift.get_techniques()
  self.G=self.client.remove_revoked(self.client.get_groups())
# def get_tech_by_group(self,Groups):
# => get techniques form the groups in question

#============================================all thai function will need to stay in class
def load_thaicert(path):
 url= "https://apt.thaicert.or.th/cgi-bin/getmisp.cgi?o=g"
 my_file=Path(path)
 if my_file.exists():
  print('loading existing file')
 else :
  print('Beginning file download with urllib2...')
  download_link(url,path)
 return  thai(path)
#=============================================== linked to thai
def get_ATPs(country,target,database): # make so syno doesn/t have opperation in the name (grab beetween 'Operation “PowerFall”)
 b= get_victime(country,database) # go through the list and return objects matching
 actors=get_target(target,b)
 # get the values
 actorsn=[actor['value'].split(", ") for actor in actors]
# ATPs=[item for sublist in actorsn for item in sublist]
 return actorsn

def flattenList(nestedList):
    # check if list is empty
    if not(bool(nestedList)):
        return nestedList
     # to check instance of list is empty or not
    if isinstance(nestedList[0], list):
        # call function with sublist as argument
        return flattenList(*nestedList[:1]) + flattenList(nestedList[1:])
    # call function with sublist as argument
    return nestedList[:1] + flattenList(nestedList[1:])

def morph (data,List,fun ):# WHY DOES THIS ALTER THE DATA ???
 switcher = {
  'r':remove(data,List),
  'a':add(data,List)
    }
 return switcher.get(fun)

def add (data,List):
 for a in List:
  data.append(a)
 return data

def get_victime(country, database):#predefine key and meta
 return json_extract('cfr-suspected-victims',country,database)

def get_target(target, database): #predefine key and meta
 return json_extract('cfr-target-category',target,database)

#==============================================================try the above better
def remove(val,ob):
    remove=[ a for a in ob if Match_V(a,val)]
    return [a for a in ob if a not in remove]

def json_extract(key, val ,obj):
    return [ a for a in obj if Match(a,key,val)]

def Match(obj, key, val): # can't give it a list of items
 List = [val] if isinstance(val, (str,dict)) else val
 if isinstance(obj,list):
  for items in obj:
   if  Match(items,key,List):
    return True
 elif isinstance(obj,(dict,stix2.v20.sdo.IntrusionSet,stix2.v20.sdo.AttackPattern,stix2.v20.sro.Relationship)):
  for k, v in obj.items():
   if k == key:
    if isinstance(v,list): # go in list
     hits=[a for a in List for b in v  if 80<fuzz.ratio(b,a)]
     if len(hits)>0:
      return True
    elif isinstance(v,(str,int)):
     hits=[a for a in List if 80<fuzz.ratio(v,a)]
     if len(hits)>0:
      return True
   elif isinstance(v, (dict,list )):
     if Match(v, key, List) :
      return True
 return False

def iterate(predicate, iterable):
   for i in iterable:
       if predicate(i):
            return(i)
       else:
            break

def Match_V(obj, val): # for pure lists untill string
    List = [val] if isinstance(val, str) else val
    for  v in obj:
        if isinstance(v,str):
            hits=[v for  a in List if 80<fuzz.ratio(v,a)]
            if len(hits)>0:
                return True
        elif isinstance(v, (dict, list)):
            return Match_V(v, List)
    return False

#===================================================================================
def json_key_value(obj, key):
    """Recursively fetch values from nested JSON."""
    arr = []
    def extract(obj, arr, key):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, (dict,stix2.v20.sdo.IntrusionSet,stix2.v20.sdo.AttackPattern,stix2.v20.sro.Relationship)):
            """Order of the if is important! If reversed no list will be appended."""
            for k, v in obj.items():
                print(k)
                if k == key:
                    arr.append(v) # if key == list add
                elif isinstance(v, (dict, list)):
                    extract(v, arr, key)
        elif isinstance(obj, list):
            for item in obj: # for all items redue function
                extract(item, arr, key)
        return arr
    values = extract(obj, arr, key)
    return values

#=============================================== linked to mitre
def make_dic(ATPobjs,tech):
 ATP_list = []
 for g in ATPobjs:
  group_dict = dict()
  group_dict[g['name']] = []
  ATP_list.append(group_dict)
 for index,group in enumerate(ATP_list):
  for group_name,techniques_list in group.items():
   for gut in tech[index]:
    technique_dict = dict()
    technique_dict['techniqueId'] = gut['external_references'][0]['external_id']
    technique_dict['techniqueName'] = gut['name']
    techniques_list.append(technique_dict)
 return ATP_list
#technique_dict['comment'] = gut['relationship_description']
#technique_dict['tactic'] = gut['tactic']
#technique_dict['group_io'] = gut['external_references'][0]['external_id']

#=============================================== linked to mitre
def to_template(list):
 layers=[]
 for group in list:
     for k,v in group.items():
         if v:
             actor_layer = {
                 "description": ("Enterprise techniques used by {0}, ATT&CK group {1} v1.0".format(k,k)),
                 "name": ("{0} ({1})".format(k,k)),
                 "domain": "enterprise-attack",
                 "version": "2.2",
                 "techniques": [
                     {
                         "score": 1,
                         "techniqueID" : technique['techniqueId'],
                         "comment": ""
                     } for technique in v
                 ],
                 "gradient": {
                     "colors": [
                         "#ffffff",
                         "#ff6666"
                     ],
                     "minValue": 0,
                     "maxValue": 1
                 },
                 "legendItems": [
                     {
                         "label": ("used by {}".format(k)),
                         "color": "#ff6666"
                     }
                 ]
             }
             layers.append(actor_layer)
 return layers
#===============================================
def write_to_json(filepath,data):
 with open(filepath, 'w') as outfile:
  json.dump(data, outfile)

                        # "techniqueName" : technique['techniqueName'],
# made increment the base aswell

#=============================================== linked to mitre
def make_overlay(layers):
 highscore=0
 overlay = {
  "description": ("Enterprise techniques overlay "),
  "name": ("Overlay"),
  "domain": "enterprise-attack",
  "version": "2.2",
  "techniques": [],
  "gradient": {
   "colors": [
    "#ffffff",
    "#ff6666"
    ],
    "minValue": 0,
    "maxValue": 1
    },
    "legendItems": [
     {
     "label": (""),
     "color": "#ff6666"
     }
    ]
    }
 for layer in layers:
  for tech in layer['techniques']:
   if any(tech['techniqueID'] in overlaytech['techniqueID'] for overlaytech in overlay['techniques']):
    for index,a in enumerate(overlay['techniques']):
     if a['techniqueID'] == tech['techniqueID']:
      overlay['techniques'][index]['score'] +=1
      if overlay['techniques'][index]['score']>highscore:

       highscore = overlay['techniques'][index]['score']
   else :
    overlay['techniques'].append(tech)
  overlay['gradient']['maxValue']=highscore
 return overlay

#============================================all thai function will need to stay in class

def download_link( url, path):
 urllib.request.urlretrieve(url, path)

class getdata:
 rawdata=[]
 data=[]
 def __init__(self,path):
  self.port(path)
  self.parse()
 def port(self,path):
  ref = open(path.rstrip(),"r")
  self.rawdata= ref.read()
  ref.close()
 def parse(self):
  self.data=self.rawdata

class thai (getdata):
 def port(self,path):
  super().port(path)
  self.rawdata = json.loads(self.rawdata)
 def parse(self):
  self.data=self.rawdata['values']

