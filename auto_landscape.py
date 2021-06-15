import NL_toolbox as nl
import pandas
import json
import textwrap

__description__ = 'Mitre Overlay Generator From Thaicert query'
__author__ = 'Vanhaecke Niels'
__version__ = '0.0.1'
__date__ = '2021/06/02'


def PrintManual():
    manual = '''
    Manual:

    This function book contains functions

    Examples:
thaipath ='/home/work/test.json'
country = ['belgium','germany','france','UK']
country = ['belgium']
target = ['pharmaceutical']

    Print Overlay from Search
    gen_overlay('/home/work/test.json',['belgium','germany','france','UK'],'pharmaceutical','overlay.json')

dicn=pd.json_normalize(dic)
dicn.colums
    '''
    for line in manual.split('\n'):
        print(textwrap.fill(line))
# to do => use better mitre attack framwork then querying every actor
#        =>replace the eval function in json_search with recursive function
def generate(thaipath,country,target,pathoverlay):
 groups= nl.lift.get_enterprise_groups()
 groups = nl.lift.remove_revoked(groups)
 thaicert=nl.load_thaicert(thaipath)
 ATPs=nl.get_ATPs(country,target,thaicert.data)
 # filter ATPS and add

 ATPobjs=nl.json_search('aliases',ATPs ,groups)
 print('quering mitre api...')
 tech= [nl.lift.get_techniques_used_by_group(a) for a in ATPobjs]
 dic=nl.make_dic(ATPobjs,tech)
 nlayers =nl.to_template(dic)
 overlay=nl.make_overlay(nlayers)
 nl.write_to_json(pathoverlay,overlay)

def generate(thaipath,country,target,pathoverlay):
    mitre=nl.Mitre() # still loads pretty long
    thaicert=nl.load_thaicert(thaipath)
    ATPs=nl.get_ATPs(country,target,thaicert.data)
# add and remove items
    mATPs=nl.add(nl.remove(['Darkhotel'],ATPs),['Lasarus Group','FIN7','FIN11']) # make it so this can be give + non cap sensitve and contains
#    mATPs=nl.morph(nl.morph(ATPs,['Darkhotel'],'r'),['Lasarus','Fin7','Fin11'],'a')  # remove changes the ATPs ??? why
    fATPs=nl.flattenList(mATPs)
    ATPobjs=nl.json_extract('aliases',fATPs ,mitre.G)
    tech= [mitre.client.get_techniques_used_by_group(a) for a in ATPobjs]              # Improve the speed of this function (by querying all once ) where is the relationship between actors and tech ????
    dic=nl.make_dic(ATPobjs,tech)
    overlay=nl.make_overlay(nl.to_template(dic))
    nl.write_to_json(pathoverlay,overlay)
